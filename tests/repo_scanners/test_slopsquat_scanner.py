"""Tests for the slopsquat scanner."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.slopsquat_scanner import (
    THREAT_CRITICAL,
    THREAT_HIGH,
    THREAT_MEDIUM,
    THREAT_MIN,
    PackageMetadata,
    SlopsquatScanner,
    _check_npm,
    _check_pypi,
    _metadata_to_findings,
    _score_package,
    _score_to_severity,
)
from whiterabbit.report.models import Severity

# ---------------------------------------------------------------------------
# Helpers — build mock registry responses
# ---------------------------------------------------------------------------


_UNSET = object()


def _pypi_json(
    *,
    author: str | None = "Test Author",
    description: str = "A legitimate test package with a full description.",
    license_val: str = "MIT",
    project_urls: dict | None | object = _UNSET,
    releases: dict | None = None,
    classifiers: list | None | object = _UNSET,
) -> dict:
    if project_urls is _UNSET:
        project_urls = {"Source": "https://github.com/test/test"}
    if releases is None:
        releases = {
            "1.0.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}],
            "1.1.0": [{"upload_time_iso_8601": "2020-06-01T00:00:00Z"}],
            "2.0.0": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z"}],
        }
    if classifiers is _UNSET:
        classifiers = ["Programming Language :: Python :: 3"]
    return {
        "info": {
            "author": author,
            "author_email": None,
            "maintainer": None,
            "maintainer_email": None,
            "description": description,
            "summary": (description[:50] + "...") if description else "",
            "license": license_val,
            "license_expression": None,
            "home_page": None,
            "project_urls": project_urls,
            "classifiers": classifiers,
        },
        "releases": releases,
    }


def _pypi_downloads_json(*, last_month: int = 500_000) -> dict:
    return {"data": {"last_month": last_month}}


def _npm_json(
    *,
    description: str = "A legitimate npm package",
    maintainers: list | None = None,
    repository: dict | None = None,
    license_val: str = "MIT",
    versions: dict | None = None,
    readme: str = "# Package\n\nFull documentation goes here. " * 10,
    created: str = "2019-06-01T00:00:00Z",
) -> dict:
    if maintainers is None:
        maintainers = [{"name": "testuser"}]
    if repository is None:
        repository = {"type": "git", "url": "https://github.com/test/test"}
    if versions is None:
        versions = {"1.0.0": {}, "1.1.0": {}, "2.0.0": {}}
    return {
        "description": description,
        "maintainers": maintainers,
        "repository": repository,
        "license": license_val,
        "versions": versions,
        "readme": readme,
        "homepage": "",
        "time": {"created": created},
    }


def _npm_downloads_json(*, downloads: int = 100_000) -> dict:
    return {"downloads": downloads}


def _mock_client_for_pypi(
    registry_json: dict,
    downloads_json: dict | None = None,
    status: int = 200,
) -> AsyncMock:
    if downloads_json is None:
        downloads_json = _pypi_downloads_json()

    def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
        resp = MagicMock()
        if "pypistats" in url:
            resp.status_code = 200
            resp.json.return_value = downloads_json
        else:
            resp.status_code = status
            resp.raise_for_status = MagicMock()
            resp.json.return_value = registry_json
        return resp

    client = AsyncMock()
    client.get = AsyncMock(side_effect=mock_get)
    return client


def _mock_client_for_npm(
    registry_json: dict,
    downloads_json: dict | None = None,
    status: int = 200,
) -> AsyncMock:
    if downloads_json is None:
        downloads_json = _npm_downloads_json()

    def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
        resp = MagicMock()
        if "api.npmjs.org" in url:
            resp.status_code = 200
            resp.json.return_value = downloads_json
        else:
            resp.status_code = status
            resp.raise_for_status = MagicMock()
            resp.json.return_value = registry_json
        return resp

    client = AsyncMock()
    client.get = AsyncMock(side_effect=mock_get)
    return client


# ---------------------------------------------------------------------------
# Unit tests: registry check functions
# ---------------------------------------------------------------------------


class TestCheckPypi:
    def test_exists_with_metadata(self) -> None:
        client = _mock_client_for_pypi(_pypi_json())
        result = asyncio.run(_check_pypi(client, "requests"))
        assert result.exists is True
        assert result.name == "requests"
        assert result.has_author is True
        assert result.has_source_repo is True
        assert result.has_license is True
        assert result.release_count == 3
        assert result.has_classifiers is True

    def test_not_found(self) -> None:
        client = _mock_client_for_pypi({}, status=404)
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
        data = _pypi_json(
            releases={"0.1.0": [{"upload_time_iso_8601": "2026-09-15T10:00:00Z"}]}
        )
        client = _mock_client_for_pypi(data)
        result = asyncio.run(_check_pypi(client, "new-pkg"))
        assert result.exists is True
        assert result.created is not None
        assert result.created.year == 2026

    def test_fetches_download_count(self) -> None:
        client = _mock_client_for_pypi(
            _pypi_json(), _pypi_downloads_json(last_month=42)
        )
        result = asyncio.run(_check_pypi(client, "some-pkg"))
        assert result.monthly_downloads == 42

    def test_downloads_failure_returns_none(self) -> None:
        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            if "pypistats" in url:
                raise Exception("timeout")
            resp.status_code = 200
            resp.raise_for_status = MagicMock()
            resp.json.return_value = _pypi_json()
            return resp

        client = AsyncMock()
        client.get = AsyncMock(side_effect=mock_get)
        result = asyncio.run(_check_pypi(client, "some-pkg"))
        assert result.exists is True
        assert result.monthly_downloads is None

    def test_suspicious_package_metadata(self) -> None:
        data = _pypi_json(
            author=None,
            description="",
            license_val="",
            project_urls=None,
            releases={"0.1.0": [{"upload_time_iso_8601": "2026-09-01T00:00:00Z"}]},
            classifiers=[],
        )
        client = _mock_client_for_pypi(data, _pypi_downloads_json(last_month=5))
        result = asyncio.run(_check_pypi(client, "shady-pkg"))
        assert result.exists is True
        assert result.has_author is False
        assert result.has_source_repo is False
        assert result.has_license is False
        assert result.release_count == 1
        assert result.has_classifiers is False
        assert result.monthly_downloads == 5


class TestCheckNpm:
    def test_exists_with_metadata(self) -> None:
        client = _mock_client_for_npm(_npm_json())
        result = asyncio.run(_check_npm(client, "express"))
        assert result.exists is True
        assert result.has_author is True
        assert result.has_source_repo is True
        assert result.has_license is True
        assert result.release_count == 3

    def test_not_found(self) -> None:
        client = _mock_client_for_npm({}, status=404)
        result = asyncio.run(_check_npm(client, "fake-npm-pkg"))
        assert result.exists is False

    def test_scoped_package_url(self) -> None:
        client = _mock_client_for_npm(_npm_json())
        asyncio.run(_check_npm(client, "@scope/pkg"))
        call_url = client.get.call_args_list[0][0][0]
        assert "%2F" in call_url
        assert "@scope%2Fpkg" in call_url

    def test_network_error_fails_open(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("timeout"))
        result = asyncio.run(_check_npm(client, "some-pkg"))
        assert result.exists is None

    def test_parses_creation_date(self) -> None:
        client = _mock_client_for_npm(_npm_json(created="2026-09-18T12:00:00Z"))
        result = asyncio.run(_check_npm(client, "new-npm-pkg"))
        assert result.exists is True
        assert result.created is not None

    def test_fetches_download_count(self) -> None:
        client = _mock_client_for_npm(_npm_json(), _npm_downloads_json(downloads=77))
        result = asyncio.run(_check_npm(client, "some-pkg"))
        assert result.monthly_downloads == 77


# ---------------------------------------------------------------------------
# Unit tests: threat scoring
# ---------------------------------------------------------------------------


class TestScorePackage:
    def test_legitimate_package_scores_zero(self) -> None:
        meta = PackageMetadata(
            name="requests",
            exists=True,
            created=datetime(2011, 2, 14, tzinfo=UTC),
            description="Python HTTP for Humans.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=172,
            has_classifiers=True,
            monthly_downloads=1_200_000_000,
        )
        score, signals = _score_package(meta)
        assert score == 0
        assert signals == []

    def test_fully_suspicious_package_scores_high(self) -> None:
        meta = PackageMetadata(
            name="shady-pkg",
            exists=True,
            created=datetime.now(UTC) - timedelta(days=5),
            description="",
            has_author=False,
            has_source_repo=False,
            has_license=False,
            release_count=1,
            has_classifiers=False,
            monthly_downloads=3,
        )
        score, signals = _score_package(meta)
        assert score >= THREAT_CRITICAL
        signal_names = {s.name for s in signals}
        assert "no_description" in signal_names
        assert "no_author" in signal_names
        assert "no_source_repo" in signal_names
        assert "no_license" in signal_names
        assert "single_release" in signal_names
        assert "very_recent" in signal_names
        assert "very_low_downloads" in signal_names
        assert "no_classifiers" in signal_names

    def test_no_description_signal(self) -> None:
        meta = PackageMetadata(
            name="pkg",
            exists=True,
            description="short",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=10,
            has_classifiers=True,
            monthly_downloads=50_000,
        )
        _score, signals = _score_package(meta)
        assert any(s.name == "no_description" for s in signals)

    def test_few_releases_signal(self) -> None:
        meta = PackageMetadata(
            name="pkg",
            exists=True,
            description="A full description for testing.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=2,
            has_classifiers=True,
            monthly_downloads=50_000,
        )
        _score, signals = _score_package(meta)
        assert any(s.name == "few_releases" for s in signals)

    def test_recent_creation_signal(self) -> None:
        meta = PackageMetadata(
            name="pkg",
            exists=True,
            created=datetime.now(UTC) - timedelta(days=90),
            description="A full description for testing.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=10,
            has_classifiers=True,
            monthly_downloads=50_000,
        )
        _score, signals = _score_package(meta)
        assert any(s.name == "recent" for s in signals)

    def test_very_recent_creation_signal(self) -> None:
        meta = PackageMetadata(
            name="pkg",
            exists=True,
            created=datetime.now(UTC) - timedelta(days=10),
            description="A full description for testing.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=10,
            has_classifiers=True,
            monthly_downloads=50_000,
        )
        _score, signals = _score_package(meta)
        assert any(s.name == "very_recent" for s in signals)

    def test_low_downloads_signal(self) -> None:
        meta = PackageMetadata(
            name="pkg",
            exists=True,
            description="A full description for testing.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=10,
            has_classifiers=True,
            monthly_downloads=50,
        )
        _score, signals = _score_package(meta)
        assert any(s.name == "low_downloads" for s in signals)

    def test_downloads_none_skips_signal(self) -> None:
        meta = PackageMetadata(
            name="pkg",
            exists=True,
            description="A full description for testing.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=10,
            has_classifiers=True,
            monthly_downloads=None,
        )
        _score, signals = _score_package(meta)
        assert not any(
            s.name in ("low_downloads", "very_low_downloads") for s in signals
        )

    def test_old_creation_date_no_signal(self) -> None:
        meta = PackageMetadata(
            name="pkg",
            exists=True,
            created=datetime(2015, 1, 1, tzinfo=UTC),
            description="A full description for testing.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=10,
            has_classifiers=True,
            monthly_downloads=50_000,
        )
        _score, signals = _score_package(meta)
        assert not any(s.name in ("recent", "very_recent") for s in signals)


class TestScoreToSeverity:
    def test_critical(self) -> None:
        assert _score_to_severity(THREAT_CRITICAL) == Severity.CRITICAL
        assert _score_to_severity(100) == Severity.CRITICAL

    def test_high(self) -> None:
        assert _score_to_severity(THREAT_HIGH) == Severity.HIGH
        assert _score_to_severity(THREAT_CRITICAL - 1) == Severity.HIGH

    def test_medium(self) -> None:
        assert _score_to_severity(THREAT_MEDIUM) == Severity.MEDIUM
        assert _score_to_severity(THREAT_HIGH - 1) == Severity.MEDIUM

    def test_low(self) -> None:
        assert _score_to_severity(THREAT_MEDIUM - 1) == Severity.LOW
        assert _score_to_severity(0) == Severity.LOW


# ---------------------------------------------------------------------------
# Unit tests: finding conversion
# ---------------------------------------------------------------------------


class TestMetadataToFindings:
    def test_nonexistent_package(self) -> None:
        metadata = [PackageMetadata(name="fake-pkg", exists=False)]
        findings = _metadata_to_findings(metadata, "PyPI")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.MEDIUM
        assert f.category == "hallucinated-dependency"
        assert f.scanner == "slopsquat"
        assert f.cwe == "CWE-829"
        assert "fake-pkg" in f.title
        assert "does not exist" in f.description
        assert f.raw["registry_status"] == 404
        assert f.raw["threat_score"] == 0

    def test_suspicious_existing_package(self) -> None:
        meta = PackageMetadata(
            name="shady-pkg",
            exists=True,
            description="",
            has_author=False,
            has_source_repo=False,
            has_license=False,
            release_count=1,
            has_classifiers=False,
            monthly_downloads=5,
        )
        findings = _metadata_to_findings([meta], "PyPI")
        assert len(findings) == 1
        f = findings[0]
        assert f.severity in (Severity.HIGH, Severity.CRITICAL)
        assert f.category == "slopsquatted-dependency"
        assert f.raw["threat_score"] > 0
        assert len(f.raw["threat_signals"]) > 0
        assert "threat score" in f.title

    def test_legitimate_package_no_finding(self) -> None:
        meta = PackageMetadata(
            name="requests",
            exists=True,
            created=datetime(2011, 1, 1, tzinfo=UTC),
            description="Python HTTP for Humans.",
            has_author=True,
            has_source_repo=True,
            has_license=True,
            release_count=172,
            has_classifiers=True,
            monthly_downloads=1_000_000,
        )
        findings = _metadata_to_findings([meta], "PyPI")
        assert len(findings) == 0

    def test_network_error_no_finding(self) -> None:
        metadata = [PackageMetadata(name="some-pkg", exists=None)]
        findings = _metadata_to_findings(metadata, "PyPI")
        assert len(findings) == 0

    def test_below_min_threshold_no_finding(self) -> None:
        meta = PackageMetadata(
            name="low-score-pkg",
            exists=True,
            description="A real description here that is long enough.",
            has_author=True,
            has_source_repo=True,
            has_license=False,
            release_count=5,
            has_classifiers=True,
            monthly_downloads=50_000,
        )
        score, _ = _score_package(meta)
        assert score < THREAT_MIN
        findings = _metadata_to_findings([meta], "PyPI")
        assert len(findings) == 0

    def test_mixed_results(self) -> None:
        metadata = [
            PackageMetadata(
                name="real-pkg",
                exists=True,
                created=datetime(2020, 1, 1, tzinfo=UTC),
                description="A real package with good metadata.",
                has_author=True,
                has_source_repo=True,
                has_license=True,
                release_count=20,
                has_classifiers=True,
                monthly_downloads=100_000,
            ),
            PackageMetadata(name="fake-pkg", exists=False),
            PackageMetadata(name="error-pkg", exists=None),
            PackageMetadata(
                name="shady-pkg",
                exists=True,
                description="",
                has_author=False,
                has_source_repo=False,
                has_license=False,
                release_count=1,
                has_classifiers=False,
                monthly_downloads=2,
            ),
        ]
        findings = _metadata_to_findings(metadata, "PyPI")
        assert len(findings) == 2

        categories = {f.category for f in findings}
        assert "hallucinated-dependency" in categories
        assert "slopsquatted-dependency" in categories


# ---------------------------------------------------------------------------
# Integration tests: SlopsquatScanner.scan()
# ---------------------------------------------------------------------------


def _make_mock_async_client(mock_get_fn):  # type: ignore[no-untyped-def]
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=mock_get_fn)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


class TestSlopsquatScanner:
    def test_no_manifests(self, tmp_path: Path) -> None:
        scanner = SlopsquatScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert result.findings == []

    def test_legitimate_packages_no_findings(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests>=2.0\n")

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            if "pypistats" in url:
                resp.status_code = 200
                resp.json.return_value = _pypi_downloads_json(last_month=1_000_000)
            else:
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.json.return_value = _pypi_json()
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 0

    def test_nonexistent_pypi_package(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("nonexistent-ai-pkg>=1.0\n")

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.MEDIUM
        assert "nonexistent-ai-pkg" in f.title
        assert f.category == "hallucinated-dependency"

    def test_suspicious_pypi_package(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("shady-pkg>=1.0\n")

        suspicious_data = _pypi_json(
            author=None,
            description="",
            license_val="",
            project_urls=None,
            releases={"0.1.0": [{"upload_time_iso_8601": "2026-09-01T00:00:00Z"}]},
            classifiers=[],
        )

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            if "pypistats" in url:
                resp.status_code = 200
                resp.json.return_value = _pypi_downloads_json(last_month=3)
            else:
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.json.return_value = suspicious_data
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity in (Severity.HIGH, Severity.CRITICAL)
        assert "shady-pkg" in f.title
        assert f.category == "slopsquatted-dependency"
        assert f.raw["threat_score"] >= THREAT_HIGH

    def test_nonexistent_npm_package(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"fake-npm-pkg": "^1.0.0"}})
        )

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        assert "fake-npm-pkg" in result.findings[0].title

    def test_mixed_results(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests>=2.0\nfake-pkg\n")

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            if "pypistats" in url:
                resp.status_code = 200
                resp.json.return_value = _pypi_downloads_json(last_month=1_000_000)
                return resp
            if "fake-pkg" in url:
                resp.status_code = 404
            else:
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.json.return_value = _pypi_json()
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
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

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal call_count
            if "pypistats" not in url:
                call_count += 1
            resp = MagicMock()
            if "pypistats" in url:
                resp.status_code = 200
                resp.json.return_value = _pypi_downloads_json()
            else:
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.json.return_value = _pypi_json()
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert call_count == 1

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

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
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

    def test_threat_score_in_raw_output(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("shady-pkg\n")

        suspicious_data = _pypi_json(
            author=None,
            description="",
            license_val="",
            project_urls=None,
            releases={"0.1.0": [{"upload_time_iso_8601": "2026-09-01T00:00:00Z"}]},
            classifiers=[],
        )

        def mock_get(url: str, **kwargs):  # type: ignore[no-untyped-def]
            resp = MagicMock()
            if "pypistats" in url:
                resp.status_code = 200
                resp.json.return_value = _pypi_downloads_json(last_month=0)
            else:
                resp.status_code = 200
                resp.raise_for_status = MagicMock()
                resp.json.return_value = suspicious_data
            return resp

        with patch(
            "whiterabbit.repo_scanner.slopsquat_scanner.httpx.AsyncClient",
            return_value=_make_mock_async_client(mock_get),
        ):
            scanner = SlopsquatScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert len(result.findings) == 1
        raw = result.findings[0].raw
        assert "threat_score" in raw
        assert raw["threat_score"] >= THREAT_CRITICAL
        assert "threat_signals" in raw
        assert len(raw["threat_signals"]) >= 5
        for sig in raw["threat_signals"]:
            assert "name" in sig
            assert "points" in sig
            assert "detail" in sig
