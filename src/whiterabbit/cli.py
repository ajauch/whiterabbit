"""Typer CLI for WhiteRabbit."""

from __future__ import annotations

import asyncio
import csv
import logging
import re
import threading
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text

from whiterabbit import __version__
from whiterabbit.config import RepoScanConfig, ScanConfig
from whiterabbit.repo_runner import RepoScanRunner
from whiterabbit.repo_scanner import get_all_repo_scanners
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.repo_scanner.clone import clone_repo
from whiterabbit.report.formatters.html import write_html
from whiterabbit.report.formatters.json import format_json, write_json
from whiterabbit.report.formatters.terminal import format_terminal
from whiterabbit.report.models import ScanReport, Severity
from whiterabbit.runner import ScanRunner
from whiterabbit.scanner import get_all_scanners

LOG_PATH = Path(__file__).resolve().parent / "whiterabbit.log"
CSV_PATH = Path("ScanResults.csv")
REPO_CSV_PATH = Path("RepoScanResults.csv")
CSV_HEADERS = ["URL", "Date", "Time", "Grade", "High", "Medium", "Low"]


def _setup_logging(verbose: bool = False) -> None:
    logger = logging.getLogger("whiterabbit")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    if not logger.handlers:
        fh = logging.FileHandler(LOG_PATH, encoding="utf-8")
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-5s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(fh)


def _append_csv(report: ScanReport, path: Path = CSV_PATH) -> None:
    write_header = not path.exists()
    try:
        with path.open("a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            if write_header:
                writer.writerow(CSV_HEADERS)
            writer.writerow(
                [
                    report.target,
                    report.scan_date.strftime("%Y-%m-%d"),
                    report.scan_date.strftime("%H:%M:%S"),
                    report.grade,
                    report.summary.get(Severity.HIGH, 0),
                    report.summary.get(Severity.MEDIUM, 0),
                    report.summary.get(Severity.LOW, 0),
                ]
            )
    except PermissionError:
        logging.getLogger("whiterabbit").warning(
            "Could not write to %s (file may be open in another program)", path
        )
        Console().print(
            f"[yellow]Warning: Could not write to {path} — "
            f"is it open in another program?[/yellow]"
        )


app = typer.Typer(
    name="whiterabbit",
    help="WhiteRabbit — a local, open-source web security scanner.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"WhiteRabbit v{__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
) -> None:
    pass


STATUS_ICONS = {
    "pending": "[dim]  ...[/dim]",
    "running": "[yellow]  >>>[/yellow]",
    "done": "[green]  OK[/green]",
    "error": "[red]  ERR[/red]",
}


def _build_progress_table(
    target: str,
    scanner_status: dict[str, str],
) -> Table:
    table = Table(
        show_header=False,
        show_edge=False,
        box=None,
        padding=(0, 1),
        expand=False,
    )
    table.add_column(width=6)
    table.add_column()

    header = Text.assemble(("Scanning ", "bold"), (target, "bold cyan"))
    table.add_row("", header)

    for name, status in scanner_status.items():
        icon = STATUS_ICONS.get(
            status.split(":")[0] if ":" in status else status, STATUS_ICONS["running"]
        )
        detail = ""
        if status.startswith("error:"):
            detail = f" [dim]({status[6:].strip()})[/dim]"
        table.add_row(icon, Text.from_markup(f"{name}{detail}"))

    return table


@app.command()
def scan(
    target: Annotated[str, typer.Argument(help="URL or hostname to scan.")],
    quick: Annotated[bool, typer.Option("--quick", help="Headers + SSL only.")] = False,
    full: Annotated[
        bool, typer.Option("--full", help="All available scanners.")
    ] = False,
    scanners: Annotated[
        str | None, typer.Option("--scanners", help="Comma-separated scanner list.")
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Write report to file (.json or .html)."),
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Output format: terminal, json, html.")
    ] = "terminal",
    timeout: Annotated[
        int, typer.Option("--timeout", help="Per-scanner timeout in seconds.")
    ] = 300,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Disable colored output.")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed scanner output.")
    ] = False,
) -> None:
    """Scan a target for security issues."""
    _setup_logging(verbose)

    if no_color:
        console.no_color = True

    config = ScanConfig(
        timeout=timeout,
        verbose=verbose,
        format=fmt,
        output=output,
        scanners=scanners.split(",") if scanners else [],
        quick=quick,
        full=full,
    )

    all_scanners = get_all_scanners()
    selected: list[str] = []

    if scanners:
        selected = config.scanners
        for name in selected:
            if name not in all_scanners:
                console.print(f"[red]Unknown scanner: {name!r}[/red]")
                available = ", ".join(sorted(all_scanners)) or "(none)"
                console.print(f"Available scanners: {available}")
                raise typer.Exit(1)
    elif quick:
        selected = [n for n in ("ssl", "headers") if n in all_scanners]
    elif full:
        selected = list(all_scanners)
    else:
        selected = list(all_scanners)

    scanner_instances = [all_scanners[n]() for n in selected]

    scan_log = logging.getLogger("whiterabbit")
    unavailable = [s for s in scanner_instances if not s.is_available()]
    for s in unavailable:
        missing = s.check_dependencies()
        scan_log.warning("scanner %s unavailable: %s", s.name, "; ".join(missing))
        console.print(f"[yellow]Scanner {s.display_name} unavailable:[/yellow]")
        for line in missing:
            console.print(f"  {line}")
    scanner_instances = [s for s in scanner_instances if s.is_available()]

    if not scanner_instances:
        scan_log.error("no scanners available for %s", target)
        console.print(
            "[yellow]No scanners available. Running produces an empty report.[/yellow]"
        )

    scanner_status: dict[str, str] = {
        s.display_name: "pending" for s in scanner_instances
    }
    lock = threading.Lock()

    def on_progress(scanner_name: str, status: str) -> None:
        with lock:
            scanner_status[scanner_name] = status

    runner = ScanRunner(on_progress=on_progress)

    report_result: ScanReport | None = None

    def run_scan() -> None:
        nonlocal report_result
        report_result = asyncio.run(runner.run(target, scanner_instances, config))

    with Live(
        _build_progress_table(target, scanner_status),
        console=console,
        transient=True,
        refresh_per_second=8,
    ) as live:
        thread = threading.Thread(target=run_scan)
        thread.start()

        while thread.is_alive():
            with lock:
                live.update(_build_progress_table(target, scanner_status))
            thread.join(timeout=0.12)

    assert report_result is not None
    _output_report(report_result, fmt, output)


@app.command("list-scanners")
def list_scanners() -> None:
    """List all available scanners."""
    all_scanners = get_all_scanners()
    if not all_scanners:
        console.print("[yellow]No scanners registered yet.[/yellow]")
        return

    table = Table(title="Available Scanners", show_header=True)
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Status")

    for name, cls in sorted(all_scanners.items()):
        instance = cls()
        status = (
            "[green]ready[/green]"
            if instance.is_available()
            else "[red]missing deps[/red]"
        )
        table.add_row(name, instance.description, status)

    console.print(table)


@app.command("check-deps")
def check_deps() -> None:
    """Check which scanner dependencies are installed."""
    all_scanners = get_all_scanners()
    if not all_scanners:
        console.print("[yellow]No scanners registered yet.[/yellow]")
        return

    all_good = True
    for _name, cls in sorted(all_scanners.items()):
        instance = cls()
        missing = instance.check_dependencies()
        if missing:
            all_good = False
            console.print(f"[red]{instance.display_name}:[/red]")
            for line in missing:
                console.print(f"  {line}")
        else:
            console.print(
                f"[green]{instance.display_name}:[/green] all dependencies installed"
            )

    if all_good:
        console.print("\n[green]All scanner dependencies are installed.[/green]")


# ---------------------------------------------------------------------------
# Repo scanning commands
# ---------------------------------------------------------------------------


_LOCAL_PATH_RE = re.compile(r"^(?:[A-Za-z]:[/\\]|[/\\]|\.\.?[/\\])")


def _looks_like_local_path(target: str) -> bool:
    return bool(_LOCAL_PATH_RE.match(target))


@app.command("scanrepo")
def scanrepo(
    target: Annotated[
        str, typer.Argument(help="Git repo URL or local directory path.")
    ],
    branch: Annotated[
        str | None, typer.Option("--branch", "-b", help="Branch to checkout.")
    ] = None,
    depth: Annotated[
        int | None, typer.Option("--depth", help="Clone depth (default 1, 0 for full).")
    ] = 1,
    scanners: Annotated[
        str | None, typer.Option("--scanners", help="Comma-separated scanner list.")
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Write report to file (.json or .html)."),
    ] = None,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Output format: terminal, json, html.")
    ] = "terminal",
    timeout: Annotated[
        int, typer.Option("--timeout", help="Per-scanner timeout in seconds.")
    ] = 300,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Disable colored output.")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed scanner output.")
    ] = False,
    keep_clone: Annotated[
        bool, typer.Option("--keep-clone", help="Keep cloned repo after scan.")
    ] = False,
) -> None:
    """Scan a GitHub repository for security vulnerabilities."""
    _setup_logging(verbose)

    if no_color:
        console.no_color = True

    target = target.strip().strip('"').strip("'")
    is_local = Path(target).is_dir()

    if not is_local:
        import shutil

        if not shutil.which("git"):
            console.print("[red]git is not installed or not on PATH.[/red]")
            raise typer.Exit(1)

    config = RepoScanConfig(
        timeout=timeout,
        verbose=verbose,
        format=fmt,
        output=output,
        scanners=scanners.split(",") if scanners else [],
        branch=branch,
        depth=depth if depth and depth > 0 else None,
        keep_clone=keep_clone,
    )

    all_repo_scanners = get_all_repo_scanners()
    selected: list[str] = []

    if scanners:
        selected = config.scanners
        for name in selected:
            if name not in all_repo_scanners:
                console.print(f"[red]Unknown repo scanner: {name!r}[/red]")
                available = ", ".join(sorted(all_repo_scanners)) or "(none)"
                console.print(f"Available repo scanners: {available}")
                raise typer.Exit(1)
    else:
        selected = list(all_repo_scanners)

    scanner_instances = [all_repo_scanners[n]() for n in selected]

    scan_log = logging.getLogger("whiterabbit")
    unavailable = [s for s in scanner_instances if not s.is_available()]
    for s in unavailable:
        missing = s.check_dependencies()
        scan_log.warning("scanner %s unavailable: %s", s.name, "; ".join(missing))
        console.print(f"[yellow]Scanner {s.display_name} unavailable:[/yellow]")
        for line in missing:
            console.print(f"  {line}")
    scanner_instances = [s for s in scanner_instances if s.is_available()]

    if not scanner_instances:
        scan_log.error("no repo scanners available")
        console.print(
            "[yellow]No repo scanners available. Running produces an empty report.[/yellow]"
        )

    display_target = target

    if not is_local and _looks_like_local_path(target):
        console.print(f"[red]Directory not found: {target}[/red]")
        raise typer.Exit(1)

    if is_local:
        repo_path = str(Path(target).resolve())
        _run_repo_scan(
            display_target, repo_path, scanner_instances, config, fmt, output
        )
    else:
        console.print(f"[dim]Cloning {target}...[/dim]")

        async def _clone_and_scan() -> ScanReport:
            async with clone_repo(
                target,
                branch=config.branch,
                depth=config.depth,
                keep=config.keep_clone,
            ) as repo_dir:
                if config.keep_clone:
                    console.print(f"[dim]Cloned to {repo_dir}[/dim]")
                runner = RepoScanRunner()
                return await runner.run(
                    display_target, str(repo_dir), scanner_instances, config
                )

        report = asyncio.run(_clone_and_scan())
        _output_report(report, fmt, output, csv_path=REPO_CSV_PATH)


def _run_repo_scan(
    display_target: str,
    repo_path: str,
    scanner_instances: list[BaseRepoScanner],
    config: RepoScanConfig,
    fmt: str,
    output: str | None,
) -> None:
    scanner_status: dict[str, str] = {
        s.display_name: "pending" for s in scanner_instances
    }
    lock = threading.Lock()

    def on_progress(scanner_name: str, status: str) -> None:
        with lock:
            scanner_status[scanner_name] = status

    runner = RepoScanRunner(on_progress=on_progress)

    report_result: ScanReport | None = None

    def run_scan() -> None:
        nonlocal report_result
        report_result = asyncio.run(
            runner.run(display_target, repo_path, scanner_instances, config)
        )

    with Live(
        _build_progress_table(display_target, scanner_status),
        console=console,
        transient=True,
        refresh_per_second=8,
    ) as live:
        thread = threading.Thread(target=run_scan)
        thread.start()

        while thread.is_alive():
            with lock:
                live.update(_build_progress_table(display_target, scanner_status))
            thread.join(timeout=0.12)

    assert report_result is not None
    _output_report(report_result, fmt, output, csv_path=REPO_CSV_PATH)


def _output_report(
    report: ScanReport, fmt: str, output: str | None, csv_path: Path = CSV_PATH
) -> None:
    _append_csv(report, csv_path)

    if fmt == "json":
        if output:
            write_json(report, output)
            console.print(f"JSON report written to {output}")
        else:
            console.print(format_json(report))
    elif fmt == "html":
        if output:
            write_html(report, output)
            console.print(f"HTML report written to {output}")
        else:
            console.print(
                "[yellow]HTML format requires --output. "
                "Use --format terminal for console output.[/yellow]"
            )
    else:
        format_terminal(report, console)
        if output:
            if output.endswith(".html"):
                write_html(report, output)
                console.print(f"\nHTML report written to {output}")
            else:
                write_json(report, output)
                console.print(f"\nJSON report written to {output}")


@app.command("list-repo-scanners")
def list_repo_scanners() -> None:
    """List all available repo scanners."""
    all_repo_scanners = get_all_repo_scanners()
    if not all_repo_scanners:
        console.print("[yellow]No repo scanners registered yet.[/yellow]")
        return

    table = Table(title="Available Repo Scanners", show_header=True)
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Status")

    for name, cls in sorted(all_repo_scanners.items()):
        instance = cls()
        status = (
            "[green]ready[/green]"
            if instance.is_available()
            else "[red]missing deps[/red]"
        )
        table.add_row(name, instance.description, status)

    console.print(table)


@app.command("check-repo-deps")
def check_repo_deps() -> None:
    """Check which repo scanner dependencies are installed."""
    all_repo_scanners = get_all_repo_scanners()
    if not all_repo_scanners:
        console.print("[yellow]No repo scanners registered yet.[/yellow]")
        return

    import shutil

    all_good = True

    git_ok = shutil.which("git") is not None
    if git_ok:
        console.print("[green]git:[/green] installed")
    else:
        all_good = False
        console.print("[red]git:[/red] not found on PATH")

    for _name, cls in sorted(all_repo_scanners.items()):
        instance = cls()
        missing = instance.check_dependencies()
        if missing:
            all_good = False
            console.print(f"[red]{instance.display_name}:[/red]")
            for line in missing:
                console.print(f"  {line}")
        else:
            console.print(
                f"[green]{instance.display_name}:[/green] all dependencies installed"
            )

    if all_good:
        console.print("\n[green]All repo scanner dependencies are installed.[/green]")
