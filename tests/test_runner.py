"""Tests for the async scan runner."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.runner import ScanRunner
from whiterabbit.scanner.base import BaseScanner


class FakeScanner(BaseScanner):
    name = "fake"
    display_name = "Fake Scanner"
    description = "A fake scanner for testing"
    required_binaries: list[str] = []

    def __init__(self, findings: list[Finding] | None = None, delay: float = 0) -> None:
        self._findings = findings or []
        self._delay = delay

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        return ScanResult(
            target=target,
            scanner_name=self.name,
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            findings=self._findings,
        )


class ErrorScanner(BaseScanner):
    name = "error"
    display_name = "Error Scanner"
    description = "Always errors"
    required_binaries: list[str] = []

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        raise RuntimeError("Scanner exploded")


class TestScanRunner:
    @pytest.fixture
    def config(self) -> ScanConfig:
        return ScanConfig(timeout=10)

    @pytest.mark.asyncio
    async def test_empty_scan(self, config: ScanConfig) -> None:
        runner = ScanRunner()
        report = await runner.run("example.com", [], config)
        assert report.target == "example.com"
        assert report.grade == "A+"
        assert len(report.results) == 0

    @pytest.mark.asyncio
    async def test_single_scanner(self, config: ScanConfig) -> None:
        finding = Finding(
            severity=Severity.HIGH,
            title="Test finding",
            description="Desc",
            remediation="Fix",
            category="test",
            scanner="fake",
        )
        scanner = FakeScanner(findings=[finding])
        runner = ScanRunner()
        report = await runner.run("example.com", [scanner], config)
        assert len(report.results) == 1
        assert len(report.results[0].findings) == 1
        assert report.grade == "D"

    @pytest.mark.asyncio
    async def test_multiple_scanners(self, config: ScanConfig) -> None:
        s1 = FakeScanner()
        s2 = FakeScanner()
        runner = ScanRunner()
        report = await runner.run("example.com", [s1, s2], config)
        assert len(report.results) == 2

    @pytest.mark.asyncio
    async def test_scanner_error_handled(self, config: ScanConfig) -> None:
        scanner = ErrorScanner()
        runner = ScanRunner()
        report = await runner.run("example.com", [scanner], config)
        assert len(report.results) == 1
        assert report.results[0].error is not None
        assert "Scanner exploded" in report.results[0].error
        assert report.grade == "A+"

    @pytest.mark.asyncio
    async def test_scanner_timeout(self) -> None:
        config = ScanConfig(timeout=1)
        scanner = FakeScanner(delay=10)
        runner = ScanRunner()
        report = await runner.run("example.com", [scanner], config)
        assert len(report.results) == 1
        assert report.results[0].error is not None
        assert "timed out" in report.results[0].error

    @pytest.mark.asyncio
    async def test_progress_callback(self, config: ScanConfig) -> None:
        events: list[tuple[str, str]] = []

        def on_progress(name: str, status: str) -> None:
            events.append((name, status))

        scanner = FakeScanner()
        runner = ScanRunner(on_progress=on_progress)
        await runner.run("example.com", [scanner], config)
        assert len(events) == 2
        assert events[0] == ("Fake Scanner", "running")
        assert events[1][0] == "Fake Scanner"
        assert events[1][1] == "done"

    @pytest.mark.asyncio
    async def test_report_fields(self, config: ScanConfig) -> None:
        runner = ScanRunner()
        report = await runner.run("example.com", [], config)
        assert report.whiterabbit_version == "0.1.0"
        assert report.duration_seconds >= 0
        assert report.scan_date is not None
        assert report.summary[Severity.CRITICAL] == 0
