"""Tests for the Bandit scanner."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.bandit_scanner import (
    BanditScanner,
    _adjusted_severity,
    _build_command,
    _parse_bandit_output,
)
from whiterabbit.report.models import Severity

SAMPLE_BANDIT_OUTPUT = {
    "results": [
        {
            "test_id": "B101",
            "test_name": "assert_used",
            "filename": "app/auth.py",
            "line_number": 15,
            "issue_severity": "LOW",
            "issue_confidence": "HIGH",
            "issue_text": "Use of assert detected. Assertions are removed in optimized code.",
            "issue_cwe": {
                "id": 703,
                "link": "https://cwe.mitre.org/data/definitions/703.html",
            },
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b101.html",
        },
        {
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "filename": "app/utils.py",
            "line_number": 42,
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "issue_text": "subprocess call with shell=True identified, security issue.",
            "issue_cwe": {
                "id": 78,
                "link": "https://cwe.mitre.org/data/definitions/78.html",
            },
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b602.html",
        },
        {
            "test_id": "B105",
            "test_name": "hardcoded_password_string",
            "filename": "app/config.py",
            "line_number": 8,
            "issue_severity": "MEDIUM",
            "issue_confidence": "LOW",
            "issue_text": "Possible hardcoded password.",
            "issue_cwe": {"id": 259},
            "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105.html",
        },
    ]
}


class TestAdjustedSeverity:
    def test_high_severity_high_confidence(self) -> None:
        assert _adjusted_severity("HIGH", "HIGH") == Severity.HIGH

    def test_high_severity_medium_confidence(self) -> None:
        assert _adjusted_severity("HIGH", "MEDIUM") == Severity.MEDIUM

    def test_medium_severity_high_confidence(self) -> None:
        assert _adjusted_severity("MEDIUM", "HIGH") == Severity.MEDIUM

    def test_low_severity_high_confidence(self) -> None:
        assert _adjusted_severity("LOW", "HIGH") == Severity.LOW

    def test_does_not_go_below_info(self) -> None:
        assert _adjusted_severity("LOW", "LOW") == Severity.INFO


class TestBuildCommand:
    def test_default_command(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.bandit_scanner.resolve_binary",
            return_value="/usr/bin/bandit",
        ):
            cmd = _build_command("/tmp/repo")
        assert cmd[0] == "/usr/bin/bandit"
        assert "-r" in cmd
        assert "-f" in cmd
        assert "json" in cmd
        assert "-q" in cmd
        assert "--exit-zero" in cmd
        assert "/tmp/repo" in cmd


class TestParseBanditOutput:
    def test_filters_low_confidence(self) -> None:
        output = json.dumps(SAMPLE_BANDIT_OUTPUT)
        findings = _parse_bandit_output(output)
        test_ids = [f.raw["test_id"] for f in findings]
        assert "B105" not in test_ids

    def test_high_confidence_findings(self) -> None:
        output = json.dumps(SAMPLE_BANDIT_OUTPUT)
        findings = _parse_bandit_output(output)
        assert len(findings) == 2

    def test_severity_mapping(self) -> None:
        output = json.dumps(SAMPLE_BANDIT_OUTPUT)
        findings = _parse_bandit_output(output)
        by_id = {f.raw["test_id"]: f for f in findings}
        assert by_id["B602"].severity == Severity.HIGH
        assert by_id["B101"].severity == Severity.LOW

    def test_cwe_extraction(self) -> None:
        output = json.dumps(SAMPLE_BANDIT_OUTPUT)
        findings = _parse_bandit_output(output)
        by_id = {f.raw["test_id"]: f for f in findings}
        assert by_id["B602"].cwe == "CWE-78"
        assert by_id["B101"].cwe == "CWE-703"

    def test_references(self) -> None:
        output = json.dumps(SAMPLE_BANDIT_OUTPUT)
        findings = _parse_bandit_output(output)
        for f in findings:
            assert len(f.references) == 1
            assert "bandit.readthedocs.io" in f.references[0]

    def test_title_format(self) -> None:
        output = json.dumps(SAMPLE_BANDIT_OUTPUT)
        findings = _parse_bandit_output(output)
        f = next(f for f in findings if f.raw["test_id"] == "B602")
        assert "B602" in f.title
        assert "app/utils.py:42" in f.title

    def test_scanner_and_category(self) -> None:
        output = json.dumps(SAMPLE_BANDIT_OUTPUT)
        findings = _parse_bandit_output(output)
        assert all(f.scanner == "bandit" for f in findings)
        assert all(f.category == "python-security" for f in findings)

    def test_deduplication(self) -> None:
        data = {
            "results": [
                SAMPLE_BANDIT_OUTPUT["results"][1],
                SAMPLE_BANDIT_OUTPUT["results"][1],
            ]
        }
        findings = _parse_bandit_output(json.dumps(data))
        assert len(findings) == 1

    def test_empty_results(self) -> None:
        output = json.dumps({"results": []})
        findings = _parse_bandit_output(output)
        assert findings == []

    def test_invalid_json(self) -> None:
        findings = _parse_bandit_output("not json")
        assert findings == []


class TestBanditScanner:
    def test_is_available_without_bandit(self) -> None:
        with patch("whiterabbit.repo_scanner.base.resolve_binary", return_value=None):
            scanner = BanditScanner()
            assert not scanner.is_available()

    def test_is_available_with_bandit(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.base.resolve_binary",
            return_value="/usr/bin/bandit",
        ):
            scanner = BanditScanner()
            assert scanner.is_available()

    def test_successful_scan(self) -> None:
        bandit_output = json.dumps(SAMPLE_BANDIT_OUTPUT)

        proc = AsyncMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(bandit_output.encode(), b""))

        with patch(
            "whiterabbit.repo_scanner.bandit_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = BanditScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is None
            assert len(result.findings) == 2

    def test_bandit_not_found(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.bandit_scanner.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError,
        ):
            scanner = BanditScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "bandit not found" in result.error

    def test_bandit_error_exit(self) -> None:
        proc = AsyncMock()
        proc.returncode = 2
        proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch(
            "whiterabbit.repo_scanner.bandit_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = BanditScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "Bandit exited with code 2" in result.error

    def test_timeout(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)

        with (
            patch(
                "whiterabbit.repo_scanner.bandit_scanner.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
            patch(
                "whiterabbit.repo_scanner.bandit_scanner.asyncio.wait_for",
                side_effect=TimeoutError,
            ),
        ):
            scanner = BanditScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "timed out" in result.error
