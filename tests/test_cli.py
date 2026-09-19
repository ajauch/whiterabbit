"""Tests for the CLI layer — argument parsing, scanner selection, output routing."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from whiterabbit.cli import app
from whiterabbit.report.models import ScanReport, Severity

runner = CliRunner()


def _fake_report(target: str = "example.com", grade: str = "A+") -> ScanReport:
    return ScanReport(
        target=target,
        scan_date=datetime(2026, 1, 1, tzinfo=UTC),
        duration_seconds=1.0,
        grade=grade,
        summary={s: 0 for s in Severity},
        results=[],
        whiterabbit_version="0.1.0",
    )


class TestVersionFlag:
    def test_version_output(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "WhiteRabbit v" in result.output

    def test_short_version(self) -> None:
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert "WhiteRabbit v" in result.output


class TestNoArgs:
    def test_no_args_shows_help(self) -> None:
        result = runner.invoke(app, [])
        assert "Usage" in result.output or "whiterabbit" in result.output.lower()


class TestListScanners:
    def test_list_scanners(self) -> None:
        result = runner.invoke(app, ["list-scanners"])
        assert result.exit_code == 0
        assert "ssl" in result.output.lower() or "Available Scanners" in result.output

    def test_list_repo_scanners(self) -> None:
        result = runner.invoke(app, ["list-repo-scanners"])
        assert result.exit_code == 0
        assert "cve" in result.output.lower() or "Repo Scanners" in result.output


class TestScanCommand:
    @patch("whiterabbit.cli.ScanRunner")
    @patch("whiterabbit.cli.get_all_scanners")
    def test_unknown_scanner_exits(
        self, mock_get: MagicMock, mock_runner: MagicMock
    ) -> None:
        mock_get.return_value = {"ssl": MagicMock(), "headers": MagicMock()}
        result = runner.invoke(app, ["scan", "example.com", "--scanners", "nope"])
        assert result.exit_code == 1
        assert "Unknown scanner" in result.output

    @patch("whiterabbit.cli._append_csv")
    @patch("whiterabbit.cli.ScanRunner")
    @patch("whiterabbit.cli.get_all_scanners")
    def test_quick_selects_ssl_and_headers(
        self,
        mock_get: MagicMock,
        mock_runner_cls: MagicMock,
        mock_csv: MagicMock,
    ) -> None:
        ssl_cls = MagicMock()
        ssl_instance = MagicMock()
        ssl_instance.is_available.return_value = True
        ssl_instance.display_name = "SSL"
        ssl_cls.return_value = ssl_instance

        hdr_cls = MagicMock()
        hdr_instance = MagicMock()
        hdr_instance.is_available.return_value = True
        hdr_instance.display_name = "Headers"
        hdr_cls.return_value = hdr_instance

        nuclei_cls = MagicMock()

        mock_get.return_value = {
            "ssl": ssl_cls,
            "headers": hdr_cls,
            "nuclei": nuclei_cls,
        }

        report = _fake_report()

        async def fake_run(target, scanners, config):
            return report

        runner_instance = MagicMock()
        runner_instance.run = fake_run
        mock_runner_cls.return_value = runner_instance

        result = runner.invoke(app, ["scan", "example.com", "--quick"])
        assert result.exit_code == 0
        nuclei_cls.assert_not_called()

    @patch("whiterabbit.cli._append_csv")
    @patch("whiterabbit.cli.ScanRunner")
    @patch("whiterabbit.cli.get_all_scanners")
    def test_scan_json_output(
        self,
        mock_get: MagicMock,
        mock_runner_cls: MagicMock,
        mock_csv: MagicMock,
    ) -> None:
        scanner_cls = MagicMock()
        scanner_instance = MagicMock()
        scanner_instance.is_available.return_value = True
        scanner_instance.display_name = "SSL"
        scanner_cls.return_value = scanner_instance
        mock_get.return_value = {"ssl": scanner_cls}

        report = _fake_report()

        async def fake_run(target, scanners, config):
            return report

        runner_instance = MagicMock()
        runner_instance.run = fake_run
        mock_runner_cls.return_value = runner_instance

        result = runner.invoke(
            app, ["scan", "example.com", "--scanners", "ssl", "--format", "json"]
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["target"] == "example.com"
        assert parsed["grade"] == "A+"

    @patch("whiterabbit.cli._append_csv")
    @patch("whiterabbit.cli.ScanRunner")
    @patch("whiterabbit.cli.get_all_scanners")
    def test_scan_no_available_scanners(
        self,
        mock_get: MagicMock,
        mock_runner_cls: MagicMock,
        mock_csv: MagicMock,
    ) -> None:
        scanner_cls = MagicMock()
        scanner_instance = MagicMock()
        scanner_instance.is_available.return_value = False
        scanner_instance.display_name = "Nuclei"
        scanner_instance.check_dependencies.return_value = ["nuclei not found"]
        scanner_cls.return_value = scanner_instance
        mock_get.return_value = {"nuclei": scanner_cls}

        report = _fake_report()

        async def fake_run(target, scanners, config):
            return report

        runner_instance = MagicMock()
        runner_instance.run = fake_run
        mock_runner_cls.return_value = runner_instance

        result = runner.invoke(app, ["scan", "example.com"])
        assert "unavailable" in result.output.lower() or "No scanners" in result.output


class TestScanRepoCommand:
    @patch("whiterabbit.cli.get_all_repo_scanners")
    def test_unknown_repo_scanner_exits(self, mock_get: MagicMock) -> None:
        mock_get.return_value = {"cve": MagicMock(), "owasp": MagicMock()}
        result = runner.invoke(app, ["scanrepo", "./somedir", "--scanners", "nope"])
        assert result.exit_code == 1
        assert "Unknown repo scanner" in result.output

    @patch("whiterabbit.cli._append_csv")
    @patch("whiterabbit.cli.RepoScanRunner")
    @patch("whiterabbit.cli.get_all_repo_scanners")
    def test_local_dir_scan(
        self,
        mock_get: MagicMock,
        mock_runner_cls: MagicMock,
        mock_csv: MagicMock,
        tmp_path: pytest.TempPathFactory,
    ) -> None:
        scanner_cls = MagicMock()
        scanner_instance = MagicMock()
        scanner_instance.is_available.return_value = True
        scanner_instance.display_name = "CVE Scanner"
        scanner_cls.return_value = scanner_instance
        mock_get.return_value = {"cve": scanner_cls}

        report = _fake_report(target=str(tmp_path))

        async def fake_run(target, repo_path, scanners, config):
            return report

        runner_instance = MagicMock()
        runner_instance.run = fake_run
        mock_runner_cls.return_value = runner_instance

        result = runner.invoke(app, ["scanrepo", str(tmp_path)])
        assert result.exit_code == 0


class TestCheckDeps:
    def test_check_deps_runs(self) -> None:
        result = runner.invoke(app, ["check-deps"])
        assert result.exit_code == 0

    def test_check_repo_deps_runs(self) -> None:
        result = runner.invoke(app, ["check-repo-deps"])
        assert result.exit_code == 0
