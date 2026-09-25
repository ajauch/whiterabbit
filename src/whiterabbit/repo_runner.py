"""Async orchestrator that runs repo scanners concurrently and builds a report."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from whiterabbit import __version__
from whiterabbit.languages import detect_languages
from whiterabbit.report.grader import compute_grade
from whiterabbit.report.models import Finding, ScanReport, ScanResult, Severity

if TYPE_CHECKING:
    from whiterabbit.config import RepoScanConfig
    from whiterabbit.repo_scanner.base import BaseRepoScanner

log = logging.getLogger("whiterabbit")

ProgressCallback = Callable[[str, str], None]


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse identical findings across different file paths."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        raw = f.raw or {}
        key = f"{f.scanner}|{f.category}|{raw.get('matched', '')}|{f.description}"
        groups.setdefault(key, []).append(f)

    deduped: list[Finding] = []
    for group in groups.values():
        keep = group[0]
        if len(group) > 1:
            other_files = []
            for f in group[1:]:
                r = f.raw or {}
                other_files.append(str(r.get("file", f.title)))
            suffix = f" (also in {len(group) - 1} other file(s): {', '.join(other_files[:5])})"
            keep = keep.model_copy(
                update={"description": (keep.description + suffix)[:500]}
            )
        deduped.append(keep)
    return deduped


class RepoScanRunner:
    def __init__(self, on_progress: ProgressCallback | None = None) -> None:
        self._on_progress = on_progress

    def _report_progress(self, scanner_name: str, status: str) -> None:
        if self._on_progress:
            self._on_progress(scanner_name, status)

    async def _run_scanner(
        self,
        scanner: BaseRepoScanner,
        repo_path: str,
        config: RepoScanConfig,
    ) -> ScanResult:
        self._report_progress(scanner.display_name, "running")
        log.info(
            "[%s] starting repo scan (timeout=%ss)",
            scanner.name,
            scanner.effective_timeout(config),
        )
        started = datetime.now(UTC)
        try:
            result = await asyncio.wait_for(
                scanner.scan(repo_path, config),
                timeout=scanner.effective_timeout(config),
            )
        except TimeoutError:
            log.error(
                "[%s] timed out after %ss",
                scanner.name,
                scanner.effective_timeout(config),
            )
            result = ScanResult(
                target=repo_path,
                scanner_name=scanner.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Scanner timed out after {scanner.effective_timeout(config)}s",
            )
        except Exception as exc:
            log.error("[%s] exception: %s", scanner.name, exc, exc_info=True)
            result = ScanResult(
                target=repo_path,
                scanner_name=scanner.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc) or f"{type(exc).__name__} (no details)",
            )

        if result.error is not None and not result.error:
            result.error = "unknown error (empty message)"

        elapsed = (result.finished_at - result.started_at).total_seconds()
        if result.error is not None:
            log.error(
                "[%s] finished with error (%.1fs): %s",
                scanner.name,
                elapsed,
                result.error,
            )
        else:
            log.info(
                "[%s] finished OK (%.1fs) — %d finding(s)",
                scanner.name,
                elapsed,
                len(result.findings),
            )

        status = f"error: {result.error}" if result.error is not None else "done"
        self._report_progress(scanner.display_name, status)
        return result

    async def run(
        self,
        target: str,
        repo_path: str,
        scanners: list[BaseRepoScanner],
        config: RepoScanConfig,
    ) -> ScanReport:
        scanner_names = [s.name for s in scanners]
        log.info(
            "repo scan started — target=%s scanners=%s timeout=%ss",
            target,
            scanner_names,
            config.timeout,
        )
        scan_start = datetime.now(UTC)
        results: list[ScanResult] = []

        async with asyncio.TaskGroup() as tg:
            tasks = [
                tg.create_task(self._run_scanner(s, repo_path, config))
                for s in scanners
            ]

        results = [t.result() for t in tasks]

        scan_end = datetime.now(UTC)
        all_findings: list[Finding] = []
        for r in results:
            all_findings.extend(r.findings)

        all_findings = _deduplicate_findings(all_findings)

        grade = compute_grade(all_findings)
        summary: dict[Severity, int] = {s: 0 for s in Severity}
        for f in all_findings:
            summary[f.severity] += 1

        errors = [r for r in results if r.error]
        duration = (scan_end - scan_start).total_seconds()
        log.info(
            "repo scan complete — target=%s grade=%s duration=%.1fs findings=%s errors=%d",
            target,
            grade,
            duration,
            {s.value: c for s, c in summary.items() if c},
            len(errors),
        )
        for r in errors:
            log.warning("  scanner %s failed: %s", r.scanner_name, r.error)

        languages = detect_languages(repo_path)

        return ScanReport(
            target=target,
            scan_date=scan_start,
            duration_seconds=duration,
            grade=grade,
            summary=summary,
            results=results,
            whiterabbit_version=__version__,
            languages=languages or None,
        )
