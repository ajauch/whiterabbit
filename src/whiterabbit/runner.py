"""Async orchestrator that runs scanners concurrently and builds a report."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

from whiterabbit import __version__
from whiterabbit.report.grader import compute_grade
from whiterabbit.report.models import Finding, ScanReport, ScanResult, Severity

if TYPE_CHECKING:
    from whiterabbit.config import ScanConfig
    from whiterabbit.scanner.base import BaseScanner

log = logging.getLogger("whiterabbit")

ProgressCallback = Callable[[str, str], None]


class ScanRunner:
    def __init__(self, on_progress: ProgressCallback | None = None) -> None:
        self._on_progress = on_progress

    def _report_progress(self, scanner_name: str, status: str) -> None:
        if self._on_progress:
            self._on_progress(scanner_name, status)

    async def _run_scanner(
        self, scanner: BaseScanner, target: str, config: ScanConfig
    ) -> ScanResult:
        self._report_progress(scanner.display_name, "running")
        log.info("[%s] starting against %s (timeout=%ss)", scanner.name, target, scanner.effective_timeout(config))
        started = datetime.now(timezone.utc)
        try:
            result = await asyncio.wait_for(
                scanner.scan(target, config),
                timeout=scanner.effective_timeout(config),
            )
        except asyncio.TimeoutError:
            log.error("[%s] timed out after %ss", scanner.name, scanner.effective_timeout(config))
            result = ScanResult(
                target=target,
                scanner_name=scanner.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                error=f"Scanner timed out after {scanner.effective_timeout(config)}s",
            )
        except Exception as exc:
            log.error("[%s] exception: %s", scanner.name, exc, exc_info=True)
            result = ScanResult(
                target=target,
                scanner_name=scanner.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                error=str(exc) or f"{type(exc).__name__} (no details)",
            )

        if result.error is not None and not result.error:
            result.error = "unknown error (empty message)"

        elapsed = (result.finished_at - result.started_at).total_seconds()
        if result.error is not None:
            log.error("[%s] finished with error (%.1fs): %s", scanner.name, elapsed, result.error)
        else:
            log.info("[%s] finished OK (%.1fs) — %d finding(s)", scanner.name, elapsed, len(result.findings))

        status = f"error: {result.error}" if result.error is not None else "done"
        self._report_progress(scanner.display_name, status)
        return result

    async def run(
        self,
        target: str,
        scanners: list[BaseScanner],
        config: ScanConfig,
    ) -> ScanReport:
        scanner_names = [s.name for s in scanners]
        log.info("scan started — target=%s scanners=%s timeout=%ss", target, scanner_names, config.timeout)
        scan_start = datetime.now(timezone.utc)
        results: list[ScanResult] = []

        async with asyncio.TaskGroup() as tg:
            tasks = [
                tg.create_task(self._run_scanner(s, target, config))
                for s in scanners
            ]

        results = [t.result() for t in tasks]

        scan_end = datetime.now(timezone.utc)
        all_findings: list[Finding] = []
        for r in results:
            all_findings.extend(r.findings)

        grade = compute_grade(all_findings)
        summary: dict[Severity, int] = {s: 0 for s in Severity}
        for f in all_findings:
            summary[f.severity] += 1

        errors = [r for r in results if r.error]
        duration = (scan_end - scan_start).total_seconds()
        log.info(
            "scan complete — target=%s grade=%s duration=%.1fs findings=%s errors=%d",
            target, grade, duration,
            {s.value: c for s, c in summary.items() if c},
            len(errors),
        )
        for r in errors:
            log.warning("  scanner %s failed: %s", r.scanner_name, r.error)

        return ScanReport(
            target=target,
            scan_date=scan_start,
            duration_seconds=duration,
            grade=grade,
            summary=summary,
            results=results,
            whiterabbit_version=__version__,
        )
