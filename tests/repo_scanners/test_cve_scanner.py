"""Tests for the CVE dependency scanner."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.cve_scanner import (
    CVEScanner,
    _adjust_severity_for_dep_context,
    _cvss_to_severity,
    _dep_context_label,
    _downgrade_severity,
    _osv_to_findings,
)
from whiterabbit.repo_scanner.manifest import (
    detect_ecosystems,
    detect_ecosystems_rich,
    parse_package_json,
    parse_package_lock_json,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from whiterabbit.report.models import Severity


class TestParseRequirementsTxt:
    def test_pinned_versions(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask==3.0.0\n")
        result = parse_requirements_txt(req)
        assert ("requests", "2.31.0") in result
        assert ("flask", "3.0.0") in result

    def test_ignores_comments_and_flags(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\n-r other.txt\nrequests==2.31.0\n")
        result = parse_requirements_txt(req)
        assert len(result) == 1
        assert result[0] == ("requests", "2.31.0")

    def test_ignores_unpinned(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.0\nflask\n")
        result = parse_requirements_txt(req)
        assert len(result) == 0

    def test_empty_file(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("")
        result = parse_requirements_txt(req)
        assert result == []


class TestParsePyprojectToml:
    def test_pinned_dependencies(self, tmp_path: Path) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[project]\ndependencies = [\n  "requests==2.31.0",\n  "flask==3.0.0",\n]\n'
        )
        result = parse_pyproject_toml(toml)
        assert ("requests", "2.31.0") in result
        assert ("flask", "3.0.0") in result

    def test_ignores_unpinned(self, tmp_path: Path) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text('[project]\ndependencies = [\n  "requests>=2.0",\n]\n')
        result = parse_pyproject_toml(toml)
        assert len(result) == 0


class TestParsePackageJson:
    def test_both_dep_types(self, tmp_path: Path) -> None:
        pj = tmp_path / "package.json"
        pj.write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.2"},
                    "devDependencies": {"jest": "~29.7.0"},
                }
            )
        )
        result = parse_package_json(pj)
        assert ("express", "4.18.2") in result
        assert ("jest", "29.7.0") in result

    def test_empty_deps(self, tmp_path: Path) -> None:
        pj = tmp_path / "package.json"
        pj.write_text(json.dumps({"name": "test"}))
        result = parse_package_json(pj)
        assert result == []

    def test_invalid_json(self, tmp_path: Path) -> None:
        pj = tmp_path / "package.json"
        pj.write_text("not json")
        result = parse_package_json(pj)
        assert result == []


class TestParsePackageLockJson:
    def test_v3_format(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "myapp"},
                        "node_modules/express": {"version": "4.18.2"},
                    },
                }
            )
        )
        result = parse_package_lock_json(lock)
        assert ("express", "4.18.2") in result
        assert len(result) == 1

    def test_v1_format(self, tmp_path: Path) -> None:
        lock = tmp_path / "package-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {"lodash": {"version": "4.17.21"}},
                }
            )
        )
        result = parse_package_lock_json(lock)
        assert ("lodash", "4.17.21") in result


class TestDetectEcosystems:
    def test_python_project(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        result = detect_ecosystems(str(tmp_path))
        assert "PyPI" in result
        assert ("requests", "2.31.0") in result["PyPI"]

    def test_node_project(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"express": "^4.18.2"}})
        )
        result = detect_ecosystems(str(tmp_path))
        assert "npm" in result

    def test_no_manifests(self, tmp_path: Path) -> None:
        result = detect_ecosystems(str(tmp_path))
        assert result == {}

    def test_mixed_project(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"react": "^18.0.0"}})
        )
        result = detect_ecosystems(str(tmp_path))
        assert "PyPI" in result
        assert "npm" in result

    def test_finds_manifests_in_subdirectories(self, tmp_path: Path) -> None:
        backend = tmp_path / "backend"
        backend.mkdir()
        (backend / "requirements.txt").write_text("django==4.2.0\n")
        frontend = tmp_path / "frontend"
        frontend.mkdir()
        (frontend / "package.json").write_text(
            json.dumps({"dependencies": {"react": "^18.0.0"}})
        )
        result = detect_ecosystems(str(tmp_path))
        assert "PyPI" in result
        assert ("django", "4.2.0") in result["PyPI"]
        assert "npm" in result
        assert ("react", "18.0.0") in result["npm"]

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps({"dependencies": {"hidden": "^1.0.0"}})
        )
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"express": "^4.18.2"}})
        )
        result = detect_ecosystems(str(tmp_path))
        pkgs = [name for name, _ in result.get("npm", [])]
        assert "express" in pkgs
        assert "hidden" not in pkgs


class TestCvssSeverity:
    def test_critical(self) -> None:
        assert _cvss_to_severity(9.8) == Severity.CRITICAL

    def test_high(self) -> None:
        assert _cvss_to_severity(7.5) == Severity.HIGH

    def test_medium(self) -> None:
        assert _cvss_to_severity(5.0) == Severity.MEDIUM

    def test_low(self) -> None:
        assert _cvss_to_severity(2.0) == Severity.LOW

    def test_info(self) -> None:
        assert _cvss_to_severity(0.0) == Severity.INFO

    def test_none_defaults_medium(self) -> None:
        assert _cvss_to_severity(None) == Severity.MEDIUM


class TestOsvToFindings:
    def test_basic_vuln(self) -> None:
        vulns = [
            {
                "id": "GHSA-1234-5678-abcd",
                "summary": "SQL injection in package",
                "aliases": ["CVE-2024-1234"],
                "severity": [
                    {
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
                    }
                ],
                "references": [{"url": "https://example.com/advisory"}],
                "database_specific": {"cwe_ids": ["CWE-89"]},
                "_queried_package": {
                    "package": {"name": "vulnerable-pkg", "ecosystem": "PyPI"},
                    "version": "1.0.0",
                },
            }
        ]
        findings = _osv_to_findings(vulns)
        assert len(findings) == 1
        f = findings[0]
        assert f.cve == "CVE-2024-1234"
        assert f.category == "dependency-cve"
        assert f.scanner == "cve"
        assert "vulnerable-pkg" in f.title
        assert f.cwe == "CWE-89"

    def test_deduplication(self) -> None:
        vuln = {
            "id": "GHSA-1234",
            "summary": "Bug",
            "_queried_package": {"package": {"name": "pkg"}, "version": "1.0"},
        }
        findings = _osv_to_findings([vuln, vuln])
        assert len(findings) == 1

    def test_no_vulns(self) -> None:
        findings = _osv_to_findings([])
        assert findings == []


class TestCVEScanner:
    def test_no_manifests(self, tmp_path: Path) -> None:
        scanner = CVEScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert result.findings == []

    def test_successful_scan(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-test",
                            "summary": "Test vuln",
                            "aliases": ["CVE-2024-9999"],
                            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                            "references": [],
                            "database_specific": {},
                        }
                    ]
                }
            ]
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.cve_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = CVEScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].cve == "CVE-2024-9999"

    def test_api_error(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error", request=MagicMock(), response=mock_response
        )

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.repo_scanner.cve_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = CVEScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is not None
        assert "OSV API error" in result.error


# ---------------------------------------------------------------------------
# Severity adjustment tests
# ---------------------------------------------------------------------------


class TestDowngradeSeverity:
    def test_one_level(self) -> None:
        assert _downgrade_severity(Severity.MEDIUM, 1) == Severity.LOW

    def test_two_levels(self) -> None:
        assert _downgrade_severity(Severity.MEDIUM, 2) == Severity.INFO

    def test_clamps_at_info(self) -> None:
        assert _downgrade_severity(Severity.LOW, 5) == Severity.INFO

    def test_zero_levels_unchanged(self) -> None:
        assert _downgrade_severity(Severity.HIGH, 0) == Severity.HIGH


class TestAdjustSeverityForDepContext:
    def test_direct_prod_unchanged(self) -> None:
        assert (
            _adjust_severity_for_dep_context(
                Severity.MEDIUM, is_dev=False, is_direct=True
            )
            == Severity.MEDIUM
        )

    def test_transitive_prod_unchanged(self) -> None:
        assert (
            _adjust_severity_for_dep_context(
                Severity.MEDIUM, is_dev=False, is_direct=False
            )
            == Severity.MEDIUM
        )

    def test_direct_dev_downgrade_one(self) -> None:
        assert (
            _adjust_severity_for_dep_context(
                Severity.MEDIUM, is_dev=True, is_direct=True
            )
            == Severity.LOW
        )

    def test_transitive_dev_downgrade_two(self) -> None:
        assert (
            _adjust_severity_for_dep_context(
                Severity.MEDIUM, is_dev=True, is_direct=False
            )
            == Severity.INFO
        )

    def test_critical_direct_dev_becomes_high(self) -> None:
        assert (
            _adjust_severity_for_dep_context(
                Severity.CRITICAL, is_dev=True, is_direct=True
            )
            == Severity.HIGH
        )

    def test_critical_transitive_dev_becomes_medium(self) -> None:
        assert (
            _adjust_severity_for_dep_context(
                Severity.CRITICAL, is_dev=True, is_direct=False
            )
            == Severity.MEDIUM
        )


class TestDepContextLabel:
    def test_direct_prod_empty(self) -> None:
        assert _dep_context_label(is_dev=False, is_direct=True) == ""

    def test_transitive_dev(self) -> None:
        assert (
            _dep_context_label(is_dev=True, is_direct=False)
            == "transitive dev dependency"
        )

    def test_direct_dev(self) -> None:
        assert _dep_context_label(is_dev=True, is_direct=True) == "dev dependency"

    def test_transitive_prod(self) -> None:
        assert (
            _dep_context_label(is_dev=False, is_direct=False) == "transitive dependency"
        )


# ---------------------------------------------------------------------------
# Rich ecosystem detection tests
# ---------------------------------------------------------------------------


class TestDetectEcosystemsRich:
    def test_python_project_all_direct_prod(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        result = detect_ecosystems_rich(str(tmp_path))
        assert "PyPI" in result
        dep = result["PyPI"][0]
        assert dep.name == "requests"
        assert dep.version == "2.31.0"
        assert dep.is_direct is True
        assert dep.is_dev is False

    def test_package_json_only_classifies_dev(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.2"},
                    "devDependencies": {"jest": "~29.7.0"},
                }
            )
        )
        result = detect_ecosystems_rich(str(tmp_path))
        deps = {d.name: d for d in result["npm"]}
        assert deps["express"].is_dev is False
        assert deps["express"].is_direct is True
        assert deps["jest"].is_dev is True
        assert deps["jest"].is_direct is True

    def test_lockfile_preferred_over_package_json(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"express": "^4.18.2"}})
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "myapp"},
                        "node_modules/express": {"version": "4.18.2"},
                        "node_modules/body-parser": {"version": "1.20.1"},
                    },
                }
            )
        )
        result = detect_ecosystems_rich(str(tmp_path))
        deps = {d.name: d for d in result["npm"]}
        assert "express" in deps
        assert "body-parser" in deps
        assert deps["express"].is_direct is True
        assert deps["body-parser"].is_direct is False

    def test_lockfile_dev_flag(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.2"},
                    "devDependencies": {"eslint": "^8.0.0"},
                }
            )
        )
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "myapp"},
                        "node_modules/express": {"version": "4.18.2"},
                        "node_modules/eslint": {"version": "8.50.0", "dev": True},
                        "node_modules/brace-expansion": {
                            "version": "1.1.12",
                            "dev": True,
                        },
                    },
                }
            )
        )
        result = detect_ecosystems_rich(str(tmp_path))
        deps = {d.name: d for d in result["npm"]}
        assert deps["express"].is_dev is False
        assert deps["express"].is_direct is True
        assert deps["eslint"].is_dev is True
        assert deps["eslint"].is_direct is True
        assert deps["brace-expansion"].is_dev is True
        assert deps["brace-expansion"].is_direct is False

    def test_no_manifests(self, tmp_path: Path) -> None:
        result = detect_ecosystems_rich(str(tmp_path))
        assert result == {}

    def test_lockfile_without_package_json(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "myapp"},
                        "node_modules/lodash": {"version": "4.17.21"},
                    },
                }
            )
        )
        result = detect_ecosystems_rich(str(tmp_path))
        deps = {d.name: d for d in result["npm"]}
        assert deps["lodash"].is_direct is False
        assert deps["lodash"].is_dev is False


# ---------------------------------------------------------------------------
# Finding conversion with dep context
# ---------------------------------------------------------------------------


class TestOsvToFindingsDepContext:
    def _make_vuln(
        self, vuln_id: str, pkg: str, version: str, is_dev: bool, is_direct: bool
    ) -> dict:
        return {
            "id": vuln_id,
            "summary": f"Bug in {pkg}",
            "severity": [{"type": "CVSS_V3", "score": "5.0"}],
            "references": [],
            "database_specific": {},
            "_queried_package": {
                "package": {"name": pkg, "ecosystem": "npm"},
                "version": version,
            },
            "_dep_info": {"is_dev": is_dev, "is_direct": is_direct},
        }

    def test_transitive_dev_downgraded_to_info(self) -> None:
        vulns = [
            self._make_vuln(
                "GHSA-1", "brace-expansion", "1.1.12", is_dev=True, is_direct=False
            )
        ]
        findings = _osv_to_findings(vulns)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "transitive dev dependency" in findings[0].title

    def test_direct_dev_downgraded_to_low(self) -> None:
        vulns = [
            self._make_vuln("GHSA-2", "eslint", "8.50.0", is_dev=True, is_direct=True)
        ]
        findings = _osv_to_findings(vulns)
        assert findings[0].severity == Severity.LOW
        assert "dev dependency" in findings[0].title
        assert "transitive" not in findings[0].title

    def test_direct_prod_unchanged(self) -> None:
        vulns = [
            self._make_vuln("GHSA-3", "express", "4.18.2", is_dev=False, is_direct=True)
        ]
        findings = _osv_to_findings(vulns)
        assert findings[0].severity == Severity.MEDIUM
        assert "[" not in findings[0].title

    def test_transitive_prod_unchanged_but_labeled(self) -> None:
        vulns = [
            self._make_vuln("GHSA-4", "qs", "6.14.0", is_dev=False, is_direct=False)
        ]
        findings = _osv_to_findings(vulns)
        assert findings[0].severity == Severity.MEDIUM
        assert "transitive dependency" in findings[0].title
