"""Tests for JSON and terminal report formatters."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console

from whiterabbit.report.formatters.json import format_json, write_json
from whiterabbit.report.formatters.terminal import format_terminal
from whiterabbit.report.models import (
    Finding,
    ScanReport,
    ScanResult,
    Severity,
    UnavailableScanner,
)


def _report_with_findings() -> ScanReport:
    findings = [
        Finding(
            severity=Severity.HIGH,
            title="Missing HSTS",
            description="HSTS not set",
            remediation="Add HSTS header",
            category="headers",
            scanner="headers",
        ),
        Finding(
            severity=Severity.INFO,
            title="HTTP/2",
            description="HTTP/2 supported",
            remediation="No action",
            category="headers",
            scanner="headers",
        ),
    ]
    result = ScanResult(
        target="example.com",
        scanner_name="headers",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC),
        findings=findings,
    )
    return ScanReport(
        target="example.com",
        scan_date=datetime(2026, 1, 1, tzinfo=UTC),
        duration_seconds=5.0,
        grade="D",
        summary={
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
            Severity.INFO: 1,
        },
        results=[result],
        whiterabbit_version="0.1.0",
    )


def _empty_report() -> ScanReport:
    return ScanReport(
        target="clean.example.com",
        scan_date=datetime(2026, 1, 1, tzinfo=UTC),
        duration_seconds=1.0,
        grade="A+",
        summary={s: 0 for s in Severity},
        results=[],
        whiterabbit_version="0.1.0",
    )


class TestJSONFormatter:
    def test_format_json_valid(self) -> None:
        report = _report_with_findings()
        output = format_json(report)
        parsed = json.loads(output)
        assert parsed["target"] == "example.com"
        assert parsed["grade"] == "D"
        assert len(parsed["results"]) == 1

    def test_format_json_empty_report(self) -> None:
        output = format_json(_empty_report())
        parsed = json.loads(output)
        assert parsed["grade"] == "A+"
        assert parsed["results"] == []

    def test_write_json_file(self) -> None:
        report = _report_with_findings()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        write_json(report, path)
        content = Path(path).read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert parsed["target"] == "example.com"
        assert content.endswith("\n")
        Path(path).unlink()

    def test_json_round_trip(self) -> None:
        report = _report_with_findings()
        output = format_json(report)
        parsed = json.loads(output)
        restored = ScanReport.model_validate(parsed)
        assert restored.target == report.target
        assert restored.grade == report.grade
        assert len(restored.results) == len(report.results)

    def test_json_includes_unavailable_scanners(self) -> None:
        report = _empty_report()
        report.scanners_unavailable = [
            UnavailableScanner(scanner="nuclei", reason="'nuclei' not found on PATH"),
            UnavailableScanner(
                scanner="testssl", reason="'testssl.sh' not found on PATH"
            ),
        ]
        output = format_json(report)
        parsed = json.loads(output)
        assert len(parsed["scanners_unavailable"]) == 2
        assert parsed["scanners_unavailable"][0]["scanner"] == "nuclei"


class TestTerminalFormatter:
    def test_format_with_findings(self) -> None:
        report = _report_with_findings()
        console = Console(file=None, force_terminal=True, width=120)
        with console.capture() as capture:
            format_terminal(report, console)
        output = capture.get()
        assert "example.com" in output
        assert "D" in output
        assert "Missing HSTS" in output

    def test_format_empty_report(self) -> None:
        report = _empty_report()
        console = Console(file=None, force_terminal=True, width=120)
        with console.capture() as capture:
            format_terminal(report, console)
        output = capture.get()
        assert "clean.example.com" in output
        assert "A+" in output
        assert "No issues found" in output

    def test_format_report_with_error(self) -> None:
        error_result = ScanResult(
            target="example.com",
            scanner_name="broken",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            finished_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
            error="Connection refused",
        )
        report = ScanReport(
            target="example.com",
            scan_date=datetime(2026, 1, 1, tzinfo=UTC),
            duration_seconds=1.0,
            grade="A+",
            summary={s: 0 for s in Severity},
            results=[error_result],
            whiterabbit_version="0.1.0",
        )
        console = Console(file=None, force_terminal=True, width=120)
        with console.capture() as capture:
            format_terminal(report, console)
        output = capture.get()
        assert "broken" in output
        assert "Connection refused" in output

    def test_format_unavailable_scanners(self) -> None:
        report = _empty_report()
        report.scanners_unavailable = [
            UnavailableScanner(scanner="nuclei", reason="'nuclei' not found on PATH"),
        ]
        console = Console(file=None, force_terminal=True, width=120)
        with console.capture() as capture:
            format_terminal(report, console)
        output = capture.get()
        assert "nuclei" in output
        assert "unavailable" in output.lower()
        assert "not found on PATH" in output

    def test_format_default_console(self) -> None:
        report = _empty_report()
        format_terminal(report)
