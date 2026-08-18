"""Rich terminal formatter for scan reports."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from whiterabbit.report.models import ScanReport, Severity

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

GRADE_COLORS: dict[str, str] = {
    "A+": "bold green",
    "A": "green",
    "B": "cyan",
    "C": "yellow",
    "D": "red",
    "F": "bold red",
}


def format_terminal(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()

    grade_color = GRADE_COLORS.get(report.grade, "white")
    grade_text = Text(report.grade, style=grade_color)

    total_findings = sum(report.summary.values())
    header = Text.assemble(
        ("Target: ", "bold"),
        (report.target, ""),
        ("\n"),
        ("Grade:  ", "bold"),
        grade_text,
        ("\n"),
        ("Scan:   ", "bold"),
        (f"{report.duration_seconds:.1f}s", ""),
        (" | ", "dim"),
        (f"{total_findings} finding(s)", ""),
        (" | ", "dim"),
        (f"v{report.whiterabbit_version}", "dim"),
    )
    console.print(Panel(header, title="WhiteRabbit Scan Report", border_style="blue"))

    summary_table = Table(title="Summary by Severity", show_header=True)
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")
    for sev in Severity:
        count = report.summary.get(sev, 0)
        style = SEVERITY_COLORS[sev] if count > 0 else "dim"
        summary_table.add_row(sev.value.upper(), str(count), style=style)
    console.print(summary_table)

    for result in report.results:
        if result.error:
            console.print(
                f"\n[red]Scanner {result.scanner_name} failed:[/red] {result.error}"
            )
            continue

        if not result.findings:
            continue

        findings_table = Table(
            title=f"Findings — {result.scanner_name}",
            show_header=True,
            expand=True,
        )
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Title")
        findings_table.add_column("Category", width=12)

        sorted_findings = sorted(
            result.findings,
            key=lambda f: list(Severity).index(f.severity),
        )

        for finding in sorted_findings:
            sev_style = SEVERITY_COLORS[finding.severity]
            findings_table.add_row(
                Text(finding.severity.value.upper(), style=sev_style),
                finding.title,
                finding.category,
            )

        console.print(findings_table)

    if total_findings == 0:
        console.print("\n[green]No issues found.[/green]")
