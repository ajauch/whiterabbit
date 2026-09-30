"""Tests for the async repo scan runner."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from whiterabbit import __version__
from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_runner import RepoScanRunner
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity


class FakeRepoScanner(BaseRepoScanner):
    name = "fake"
    display_name = "Fake Repo Scanner"
    description = "A fake repo scanner for testing"

    def __init__(self, findings: list[Finding] | None = None, delay: float = 0) -> None:
        self._findings = findings or []
        self._delay = delay

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        return ScanResult(
            target=repo_path,
            scanner_name=self.name,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            findings=self._findings,
        )


class FakeRepoScanner2(BaseRepoScanner):
    name = "fake2"
    display_name = "Fake Repo Scanner 2"
    description = "A second fake repo scanner for testing"

    def __init__(self, findings: list[Finding] | None = None) -> None:
        self._findings = findings or []

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        return ScanResult(
            target=repo_path,
            scanner_name=self.name,
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            findings=self._findings,
        )


class ErrorRepoScanner(BaseRepoScanner):
    name = "error"
    display_name = "Error Repo Scanner"
    description = "Always errors"

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        raise RuntimeError("Repo scanner exploded")


class TestRepoScanRunner:
    @pytest.fixture
    def config(self) -> RepoScanConfig:
        return RepoScanConfig(timeout=10)

    @pytest.mark.asyncio
    async def test_empty_scan(self, config: RepoScanConfig) -> None:
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/repo", [], config
        )
        assert report.target == "https://github.com/user/repo"
        assert report.grade == "A+"
        assert len(report.results) == 0

    @pytest.mark.asyncio
    async def test_single_scanner(self, config: RepoScanConfig) -> None:
        finding = Finding(
            severity=Severity.HIGH,
            title="CVE-2024-1234",
            description="Vulnerability",
            remediation="Update package",
            category="dependency-cve",
            scanner="fake",
        )
        scanner = FakeRepoScanner(findings=[finding])
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/repo", [scanner], config
        )
        assert len(report.results) == 1
        assert len(report.results[0].findings) == 1
        assert report.grade == "D"

    @pytest.mark.asyncio
    async def test_multiple_scanners(self, config: RepoScanConfig) -> None:
        s1 = FakeRepoScanner()
        s2 = FakeRepoScanner()
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/repo", [s1, s2], config
        )
        assert len(report.results) == 2

    @pytest.mark.asyncio
    async def test_scanner_error_handled(self, config: RepoScanConfig) -> None:
        scanner = ErrorRepoScanner()
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/repo", [scanner], config
        )
        assert len(report.results) == 1
        assert report.results[0].error is not None
        assert "Repo scanner exploded" in report.results[0].error
        assert report.grade == "A+"

    @pytest.mark.asyncio
    async def test_scanner_timeout(self) -> None:
        config = RepoScanConfig(timeout=1)
        scanner = FakeRepoScanner(delay=10)
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/repo", [scanner], config
        )
        assert len(report.results) == 1
        assert report.results[0].error is not None
        assert "timed out" in report.results[0].error

    @pytest.mark.asyncio
    async def test_progress_callback(self, config: RepoScanConfig) -> None:
        events: list[tuple[str, str]] = []

        def on_progress(name: str, status: str) -> None:
            events.append((name, status))

        scanner = FakeRepoScanner()
        runner = RepoScanRunner(on_progress=on_progress)
        await runner.run("https://github.com/user/repo", "/tmp/repo", [scanner], config)
        assert len(events) == 2
        assert events[0] == ("Fake Repo Scanner", "running")
        assert events[1][0] == "Fake Repo Scanner"
        assert events[1][1] == "done"

    @pytest.mark.asyncio
    async def test_report_fields(self, config: RepoScanConfig) -> None:
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/repo", [], config
        )
        assert report.whiterabbit_version == __version__
        assert report.duration_seconds >= 0
        assert report.scan_date is not None
        assert report.summary[Severity.CRITICAL] == 0

    @pytest.mark.asyncio
    async def test_target_vs_repo_path(self, config: RepoScanConfig) -> None:
        scanner = FakeRepoScanner()
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/clone/repo", [scanner], config
        )
        assert report.target == "https://github.com/user/repo"
        assert report.results[0].target == "/tmp/clone/repo"

    @pytest.mark.asyncio
    async def test_dedup_syncs_summary_and_results(
        self, config: RepoScanConfig
    ) -> None:
        """Summary counts must equal sum of results[].findings (issue #48)."""
        dup = Finding(
            severity=Severity.HIGH,
            title="CVE-2024-9999",
            description="Vulnerability in dep",
            remediation="Upgrade dep",
            category="dependency-cve",
            scanner="fake",
            raw={"matched": "dep@1.0", "file": "package.json"},
        )
        dup2 = dup.model_copy(
            update={"raw": {"matched": "dep@1.0", "file": "yarn.lock"}}
        )
        unique = Finding(
            severity=Severity.MEDIUM,
            title="Secret found",
            description="Leaked token",
            remediation="Rotate token",
            category="secret",
            scanner="fake2",
        )
        s1 = FakeRepoScanner(findings=[dup, dup2])
        s2 = FakeRepoScanner2(findings=[unique])
        runner = RepoScanRunner()
        report = await runner.run(
            "https://github.com/user/repo", "/tmp/repo", [s1, s2], config
        )

        detail_total = sum(len(r.findings) for r in report.results)
        summary_total = sum(report.summary.values())
        assert summary_total == detail_total
        assert report.summary[Severity.HIGH] == 1
        assert report.summary[Severity.MEDIUM] == 1
        assert len(report.results[0].findings) == 1
        assert len(report.results[1].findings) == 1
