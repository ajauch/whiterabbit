"""Tests for the slopsquat scanner."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.slopsquat_scanner import (
    PackageStatus,
    SlopsquatScanner,
    _check_npm,
    _check_pypi,
    _statuses_to_findings,
)
from whiterabbit.report.models import Severity

# ---------------------------------------------------------------------------
# Unit tests: registry check functions
# ---------------------------------------------------------------------------


class TestCheckPypi:
    def test_exists(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {}}
        mock_resp.raise_for_status = MagicMock()

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_resp)

        result = asyncio.run(_check_pypi(client, "requests"))
        assert result.exists is True
        assert result.name == "requests"

    def test_not_found(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_resp)

        result = asyncio.run(_check_pypi(client, "nonexistent-pkg"))
        assert result.exists is False
        assert result.name == "nonexistent-pkg"

    def test_network_error_fails_open(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("connection refused"))

        result = asyncio.run(_check_pypi(client, "some-pkg"))
        assert result.exists is None
        assert result.name == "some-pkg"

    def test_parses_creation_date(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "releases": {
                "0.1.0": [{"upload_time_iso_8601": "2026-09-15T10:00:00Z"}],
            }
        }

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_resp)

        result = asyncio.run(_check_pypi(client, "new-pkg"))
        assert result.exists is True
        assert result.created is not None
        assert result.created.year == 2026


class TestCheckNpm:
    def test_exists(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"time": {}}
        mock_resp.raise_for_status = MagicMock()

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_resp)

        result = asyncio.run(_check_npm(client, "express"))
        assert result.exists is True

    def test_not_found(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_resp)

        result = asyncio.run(_check_npm(client, "fake-npm-pkg"))
        assert result.exists is False

    def test_scoped_package_url(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"time": {}}
        mock_resp.raise_for_status = MagicMock()

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_resp)

        asyncio.run(_check_npm(client, "@scope/pkg"))
        call_url = client.get.call_args[0][0]
        assert "%2F" in call_url
        assert "@scope%2Fpkg" in call_url

    def test_network_error_fails_open(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("timeout"))

        result = asyncio.run(_check_npm(client, "some-pkg"))
        assert result.exists is None

    def test_parses_creation_date(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"time": {"created": "2026-09-18T12:00:00Z"}}

        client = AsyncMock()
        client.get = AsyncMock(return_value=mock_resp)

        result = asyncio.run(_check_npm(client, "new-npm-pkg"))
        assert result.exists is True
        assert result.created is not None


# ---------------------------------------------------------------------------
# Unit tests: finding conversion
# ---------------------------------------------------------------------------


class TestStatusesToFindings:
    def test_hallucinated_package(self) -> None:
        statuses = [PackageStatus(name="fake-pkg", exists=False)]
        findings = _statuses_to_findings(statuses, "PyPI")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.category == "hallucinated-dependency"
        assert f.scanner == "slopsquat"
        assert f.cwe == "CWE-829"
        assert "fake-pkg" in f.title
        assert "does not exist" in f.description

    def test_existing_package_no_finding(self) -> None:
        statuses = [PackageStatus(name="requests", exists=True)]
        findings = _statuses_to_findings(statuses, "PyPI")
        assert len(findings) == 0

    def test_network_error_no_finding(self) -> None:
        statuses = [PackageStatus(name="some-pkg", exists=None)]
        findings = _statuses_to_findings(statuses, "PyPI")
        assert len(findings) == 0

    def test_recently_created_package(self) -> None:
        yesterday = datetime.now(UTC) - timedelta(days=1)
        statuses = [PackageStatus(name="new-pkg", exists=True, created=yesterday)]
        findings = _statuses_to_findings(statuses, "npm")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.LOW
        assert "Recently created" in f.title
        assert "new-pkg" in f.title

    def test_old_package_no_finding(self) -> None:
        old_date = datetime.now(UTC) - timedelta(days=365)
        statuses = [PackageStatus(name="stable-pkg", exists=True, created=old_date)]
        findings = _statuses_to_findings(statuses, "PyPI")
        assert len(findings) == 0

    def test_mixed_results(self) -> None:
        yesterday = datetime.now(UTC) - timedelta(days=1)
        statuses = [
            PackageStatus(
                name="real-pkg", exists=True, created=datetime(2020, 1, 1, tzinfo=UTC)
            ),
            PackageStatus(name="fake-pkg", exists=False),
            PackageStatus(name="error-pkg", exists=None),
            PackageStatus(name="new-pkg", exists=True, created=yesterday),
        ]
        findings = _statuses_to_findings(statuses, "PyPI")
        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities
        assert Severity.LOW in severities


# ---------------------------------------------------------------------------
# Integration tests: SlopsquatScanner.scan()
# ---------------------------------------------------------------------------


class TestSlopsquatScanner:
    def test_no_manifests(self, tmp_path: Path) -> None:
        scanner = SlopsquatScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert result.findings == []

    def test_all_packages_exist(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests>=2.0\n")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "releases": {
                "2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00Z"}],
            }
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 0

    def test_hallucinated_pypi_package(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("nonexistent-ai-pkg>=1.0\n")

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "nonexistent-ai-pkg" in f.title
        assert f.category == "hallucinated-dependency"

    def test_hallucinated_npm_package(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"fake-npm-pkg": "^1.0.0"}})
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        assert "fake-npm-pkg" in result.findings[0].title

    def test_mixed_results(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests>=2.0\nfake-pkg\n")

        def mock_get(url: str, **kwargs):
            resp = MagicMock()
            if "fake-pkg" in url:
                resp.status_code = 404
            else:
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.json.return_value = {
                    "releases": {
                        "2.31.0": [{"upload_time_iso_8601": "2023-05-22T00:00:00Z"}],
                    }
                }
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        assert "fake-pkg" in result.findings[0].title

    def test_network_error_per_package_fails_open(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("some-pkg>=1.0\n")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("DNS failure"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 0

    def test_total_network_failure(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests>=2.0\n")

        import httpx

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            side_effect=httpx.ConnectError("total failure"),
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is not None
        assert "connect" in result.error.lower()

    def test_deduplication_across_manifests(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "requirements.txt").write_text("requests>=2.0\n")

        call_count = 0

        def mock_get(url: str, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            resp.json.return_value = {
                "releases": {
                    "2.31.0": [{"upload_time_iso_8601": "2023-01-01T00:00:00Z"}],
                }
            }
            return resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert call_count == 1

    def test_recently_created_package(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("brand-new-pkg>=1.0\n")

        yesterday = datetime.now(UTC) - timedelta(days=1)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "releases": {
                "0.1.0": [
                    {"upload_time_iso_8601": yesterday.isoformat()},
                ],
            }
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.LOW
        assert "Recently created" in result.findings[0].title

    def test_empty_manifests(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "package.json").write_text(json.dumps({"name": "test"}))

        scanner = SlopsquatScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert result.findings == []

    def test_unpinned_deps_are_checked(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("unpinned-pkg\n")

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert len(result.findings) == 1
        assert "unpinned-pkg" in result.findings[0].title

    def test_scanner_name_and_metadata(self) -> None:
        scanner = SlopsquatScanner()
        assert scanner.name == "slopsquat"
        assert scanner.display_name == "Slopsquat Scanner"
        assert scanner.is_available()
