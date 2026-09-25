"""Tests for the dependency pinning scanner."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.pinning_scanner import (
    DepSpec,
    PinningScanner,
    _check_missing_lockfiles,
    _classify_specifier,
    _deps_to_findings,
    _find_manifests,
    _parse_package_json_deps,
    _parse_pyproject_toml_deps,
    _parse_requirements_txt_deps,
)
from whiterabbit.report.models import Severity

# ---------------------------------------------------------------------------
# _classify_specifier
# ---------------------------------------------------------------------------


class TestClassifySpecifier:
    def test_empty_string_is_medium(self) -> None:
        assert _classify_specifier("") is Severity.MEDIUM

    def test_star_is_medium(self) -> None:
        assert _classify_specifier("*") is Severity.MEDIUM

    def test_latest_is_medium(self) -> None:
        assert _classify_specifier("latest") is Severity.MEDIUM

    def test_x_is_medium(self) -> None:
        assert _classify_specifier("x") is Severity.MEDIUM
        assert _classify_specifier("X") is Severity.MEDIUM

    def test_exact_pin_python_is_none(self) -> None:
        assert _classify_specifier("==2.31.0") is None

    def test_exact_pin_npm_is_none(self) -> None:
        assert _classify_specifier("4.18.2") is None

    def test_prerelease_exact_is_none(self) -> None:
        assert _classify_specifier("1.0.0-beta.1") is None

    def test_caret_is_low(self) -> None:
        assert _classify_specifier("^4.18.2") is Severity.LOW

    def test_tilde_is_low(self) -> None:
        assert _classify_specifier("~4.18.2") is Severity.LOW

    def test_tilde_compat_is_low(self) -> None:
        assert _classify_specifier("~=3.0") is Severity.LOW

    def test_gte_is_low(self) -> None:
        assert _classify_specifier(">=2.0") is Severity.LOW

    def test_gt_is_medium(self) -> None:
        assert _classify_specifier(">1.0") is Severity.MEDIUM

    def test_lt_is_medium(self) -> None:
        assert _classify_specifier("<3.0") is Severity.MEDIUM

    def test_lte_is_medium(self) -> None:
        assert _classify_specifier("<=3.0") is Severity.MEDIUM

    def test_ne_is_medium(self) -> None:
        assert _classify_specifier("!=1.0") is Severity.MEDIUM

    def test_range_starting_with_gte_is_low(self) -> None:
        assert _classify_specifier(">=1.0,<2.0") is Severity.LOW

    def test_whitespace_stripped(self) -> None:
        assert _classify_specifier("  ==2.0  ") is None
        assert _classify_specifier("  >=2.0  ") is Severity.LOW
        assert _classify_specifier("   ") is Severity.MEDIUM


# ---------------------------------------------------------------------------
# _parse_requirements_txt_deps
# ---------------------------------------------------------------------------


class TestParseRequirementsTxtDeps:
    def test_bare_name(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\n")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].specifier == ""

    def test_exact_pin(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\n")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].specifier == "==2.31.0"

    def test_loose_pin(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.0\nflask~=3.0\n")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 2
        assert deps[0].specifier == ">=2.0"
        assert deps[1].specifier == "~=3.0"

    def test_skips_comments(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("# this is a comment\nrequests==1.0\n")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 1

    def test_skips_flags(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text(
            "-r other.txt\n-e .\n-c constraints.txt\n--find-links url\nrequests\n"
        )
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_strips_extras(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests[security]>=2.0\n")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].specifier == ">=2.0"

    def test_strips_inline_comments(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests>=2.0 # needed for http\n")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].specifier == ">=2.0"

    def test_strips_environment_markers(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text('requests>=2.0; python_version>="3.8"\n')
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].specifier == ">=2.0"

    def test_empty_file(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert deps == []

    def test_line_numbers(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("# comment\nrequests\nflask==1.0\n")
        deps = _parse_requirements_txt_deps(req, str(tmp_path))
        assert deps[0].line_number == 2
        assert deps[1].line_number == 3


# ---------------------------------------------------------------------------
# _parse_pyproject_toml_deps
# ---------------------------------------------------------------------------


class TestParsePyprojectTomlDeps:
    def test_bare_dep(self, tmp_path: Path) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text('dependencies = [\n  "requests",\n]\n')
        deps = _parse_pyproject_toml_deps(toml, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].name == "requests"
        assert deps[0].specifier == ""

    def test_loose_pin(self, tmp_path: Path) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text('dependencies = [\n  "requests>=2.0",\n]\n')
        deps = _parse_pyproject_toml_deps(toml, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].specifier == ">=2.0"

    def test_exact_pin(self, tmp_path: Path) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text('dependencies = [\n  "requests==2.31.0",\n]\n')
        deps = _parse_pyproject_toml_deps(toml, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].specifier == "==2.31.0"

    def test_multiple_deps(self, tmp_path: Path) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            'dependencies = [\n  "requests>=2.0",\n  "flask==3.0.0",\n  "click",\n]\n'
        )
        deps = _parse_pyproject_toml_deps(toml, str(tmp_path))
        assert len(deps) == 3

    def test_with_extras(self, tmp_path: Path) -> None:
        toml = tmp_path / "pyproject.toml"
        toml.write_text('dependencies = [\n  "requests[security]>=2.0",\n]\n')
        deps = _parse_pyproject_toml_deps(toml, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].name == "requests"


# ---------------------------------------------------------------------------
# _parse_package_json_deps
# ---------------------------------------------------------------------------


class TestParsePackageJsonDeps:
    def test_caret_prefix(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "^4.18.2"}}))
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert len(deps) == 1
        assert deps[0].specifier == "^4.18.2"

    def test_tilde_prefix(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"jest": "~29.7.0"}}))
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert deps[0].specifier == "~29.7.0"

    def test_star_version(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"lodash": "*"}}))
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert deps[0].specifier == "*"

    def test_latest_version(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"lodash": "latest"}}))
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert deps[0].specifier == "latest"

    def test_exact_version(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "4.18.2"}}))
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert deps[0].specifier == "4.18.2"

    def test_dev_dependencies_included(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.2"},
                    "devDependencies": {"jest": "~29.7.0"},
                }
            )
        )
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert len(deps) == 2

    def test_empty_deps(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"name": "test"}))
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert deps == []

    def test_invalid_json(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text("not json")
        deps = _parse_package_json_deps(pkg, str(tmp_path))
        assert deps == []


# ---------------------------------------------------------------------------
# _check_missing_lockfiles
# ---------------------------------------------------------------------------


class TestCheckMissingLockfiles:
    def test_missing_lockfile_flagged(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text("{}")
        manifests = [("package.json", pkg)]
        findings = _check_missing_lockfiles(str(tmp_path), manifests)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Missing lockfile" in findings[0].title
        assert findings[0].category == "supply-chain"

    def test_package_lock_found(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text("{}")
        (tmp_path / "package-lock.json").write_text("{}")
        findings = _check_missing_lockfiles(str(tmp_path), [("package.json", pkg)])
        assert findings == []

    def test_yarn_lock_found(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text("{}")
        (tmp_path / "yarn.lock").write_text("")
        findings = _check_missing_lockfiles(str(tmp_path), [("package.json", pkg)])
        assert findings == []

    def test_pnpm_lock_found(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text("{}")
        (tmp_path / "pnpm-lock.yaml").write_text("")
        findings = _check_missing_lockfiles(str(tmp_path), [("package.json", pkg)])
        assert findings == []

    def test_requirements_txt_no_lockfile_check(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\n")
        findings = _check_missing_lockfiles(str(tmp_path), [("requirements.txt", req)])
        assert findings == []


# ---------------------------------------------------------------------------
# _deps_to_findings
# ---------------------------------------------------------------------------


class TestDepsToFindings:
    def test_unpinned_creates_medium(self) -> None:
        deps = [DepSpec("requests", "", "requirements.txt", 1)]
        findings = _deps_to_findings(deps)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Unpinned" in findings[0].title

    def test_loose_pin_creates_low(self) -> None:
        deps = [DepSpec("requests", ">=2.0", "requirements.txt", 1)]
        findings = _deps_to_findings(deps)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "Loosely pinned" in findings[0].title

    def test_exact_pin_creates_no_finding(self) -> None:
        deps = [DepSpec("requests", "==2.31.0", "requirements.txt", 1)]
        findings = _deps_to_findings(deps)
        assert findings == []

    def test_deduplication(self) -> None:
        deps = [
            DepSpec("requests", ">=2.0", "requirements.txt", 1),
            DepSpec("requests", ">=2.1", "requirements.txt", 5),
        ]
        findings = _deps_to_findings(deps)
        assert len(findings) == 1

    def test_scanner_and_category(self) -> None:
        deps = [DepSpec("requests", "", "requirements.txt", 1)]
        findings = _deps_to_findings(deps)
        assert findings[0].scanner == "pinning"
        assert findings[0].category == "unpinned-dependency"

    def test_raw_metadata(self) -> None:
        deps = [DepSpec("flask", ">=3.0", "requirements.txt", 5)]
        findings = _deps_to_findings(deps)
        raw = findings[0].raw
        assert raw["package"] == "flask"
        assert raw["specifier"] == ">=3.0"
        assert raw["manifest"] == "requirements.txt"
        assert raw["line"] == 5

    def test_package_json_remediation(self) -> None:
        deps = [DepSpec("express", "^4.18.2", "package.json", 0)]
        findings = _deps_to_findings(deps)
        assert "package.json" in findings[0].remediation
        assert "lockfile" in findings[0].remediation

    def test_pyproject_remediation(self) -> None:
        deps = [DepSpec("requests", ">=2.0", "pyproject.toml", 3)]
        findings = _deps_to_findings(deps)
        assert "==" in findings[0].remediation


# ---------------------------------------------------------------------------
# _find_manifests
# ---------------------------------------------------------------------------


class TestFindManifests:
    def test_finds_requirements_txt(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\n")
        manifests = _find_manifests(str(tmp_path))
        assert len(manifests) == 1
        assert manifests[0][0] == "requirements.txt"

    def test_finds_nested_manifests(self, tmp_path: Path) -> None:
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "package.json").write_text("{}")
        manifests = _find_manifests(str(tmp_path))
        assert len(manifests) == 1
        assert manifests[0][0] == "package.json"

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "some-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text("{}")
        (tmp_path / "package.json").write_text("{}")
        manifests = _find_manifests(str(tmp_path))
        assert len(manifests) == 1

    def test_no_manifests(self, tmp_path: Path) -> None:
        manifests = _find_manifests(str(tmp_path))
        assert manifests == []

    def test_finds_multiple_types(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\n")
        (tmp_path / "package.json").write_text("{}")
        manifests = _find_manifests(str(tmp_path))
        assert len(manifests) == 2


# ---------------------------------------------------------------------------
# PinningScanner integration
# ---------------------------------------------------------------------------


class TestPinningScanner:
    def test_no_manifests(self, tmp_path: Path) -> None:
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert result.findings == []

    def test_requirements_with_unpinned(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask==3.0.0\nclick>=8.0\n")
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert len(result.findings) == 2
        severities = {f.severity for f in result.findings}
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities

    def test_package_json_with_loose_pins(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(
            json.dumps(
                {
                    "dependencies": {
                        "express": "^4.18.2",
                        "lodash": "4.17.21",
                    }
                }
            )
        )
        (tmp_path / "package-lock.json").write_text("{}")
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.LOW

    def test_missing_lockfile_detected(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"express": "4.18.2"}}))
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        lockfile_findings = [f for f in result.findings if f.category == "supply-chain"]
        assert len(lockfile_findings) == 1

    def test_all_pinned_no_findings(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask==3.0.0\n")
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert result.findings == []

    def test_mixed_project(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\nflask==3.0\n")
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"express": "^4.18.2"}})
        )
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert len(result.findings) >= 3

    def test_consolidation_when_majority_unpinned(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask\nclick\nuvicorn\n")
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert len(result.findings) == 1
        assert "4 of 4" in result.findings[0].title
        assert result.findings[0].severity == Severity.MEDIUM

    def test_no_consolidation_below_threshold(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests\nflask==3.0.0\nclick==8.0\n")
        scanner = PinningScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        unpinned = [f for f in result.findings if "Unpinned" in f.title]
        assert len(unpinned) == 1

    def test_scanner_metadata(self) -> None:
        scanner = PinningScanner()
        assert scanner.name == "pinning"
        assert scanner.display_name == "Dependency Pinning Scanner"
        assert scanner.is_available()
