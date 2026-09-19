"""Tests for the OWASP SAST scanner."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.owasp_scanner import (
    OWASPScanner,
    _build_command,
    _parse_semgrep_output,
)
from whiterabbit.report.models import Severity


class TestBuildCommand:
    def test_default_command(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.resolve_binary",
            return_value="/usr/bin/semgrep",
        ):
            cmd = _build_command("/tmp/repo", 300)
        assert cmd[0] == "/usr/bin/semgrep"
        assert "--config" in cmd
        assert "p/owasp-top-ten" in cmd
        assert "--json" in cmd
        assert "--quiet" in cmd
        assert "/tmp/repo" in cmd

    def test_timeout_in_command(self) -> None:
        cmd = _build_command("/tmp/repo", 600)
        idx = cmd.index("--timeout")
        assert cmd[idx + 1] == "600"


class TestParseSemgrepOutput:
    def test_single_finding(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.django.security.injection.sql-injection",
                        "path": "app/views.py",
                        "start": {"line": 42, "col": 1},
                        "end": {"line": 42, "col": 50},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Detected SQL injection vulnerability.",
                            "metadata": {
                                "cwe": ["CWE-89"],
                                "owasp": ["A03:2021 Injection"],
                                "references": [
                                    "https://owasp.org/Top10/A03_2021-Injection/"
                                ],
                            },
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.category == "sast-owasp"
        assert f.scanner == "owasp"
        assert f.cwe == "CWE-89"
        assert "sql injection" in f.title.lower()
        assert "app/views.py:42" in f.title

    def test_multiple_findings(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule1",
                        "path": "a.py",
                        "start": {"line": 1},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Bug 1",
                            "metadata": {},
                        },
                    },
                    {
                        "check_id": "rule2",
                        "path": "b.py",
                        "start": {"line": 2},
                        "extra": {
                            "severity": "WARNING",
                            "message": "Bug 2",
                            "metadata": {},
                        },
                    },
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert len(findings) == 2
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.MEDIUM

    def test_deduplication(self) -> None:
        result = {
            "check_id": "rule1",
            "path": "a.py",
            "start": {"line": 1},
            "extra": {"severity": "INFO", "message": "Dup", "metadata": {}},
        }
        output = json.dumps({"results": [result, result]})
        findings = _parse_semgrep_output(output)
        assert len(findings) == 1

    def test_empty_results(self) -> None:
        output = json.dumps({"results": []})
        findings = _parse_semgrep_output(output)
        assert findings == []

    def test_invalid_json(self) -> None:
        findings = _parse_semgrep_output("not json")
        assert findings == []

    def test_info_severity(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule1",
                        "path": "a.py",
                        "start": {"line": 1},
                        "extra": {
                            "severity": "INFO",
                            "message": "Info",
                            "metadata": {},
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert findings[0].severity == Severity.LOW

    def test_owasp_tag_in_title(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.xss-detected",
                        "path": "app.py",
                        "start": {"line": 10},
                        "extra": {
                            "severity": "ERROR",
                            "message": "XSS",
                            "metadata": {"owasp": ["A07:2017 XSS"]},
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert "A07:2017" in findings[0].title


class TestOWASPScanner:
    def test_is_available_without_semgrep(self) -> None:
        with patch("whiterabbit.repo_scanner.base.resolve_binary", return_value=None):
            scanner = OWASPScanner()
            assert not scanner.is_available()

    def test_is_available_with_semgrep(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.base.resolve_binary",
            return_value="/usr/bin/semgrep",
        ):
            scanner = OWASPScanner()
            assert scanner.is_available()

    def test_successful_scan(self) -> None:
        semgrep_output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule1",
                        "path": "app.py",
                        "start": {"line": 5},
                        "extra": {
                            "severity": "WARNING",
                            "message": "Found issue",
                            "metadata": {},
                        },
                    }
                ]
            }
        )

        proc = AsyncMock()
        proc.returncode = 1
        proc.communicate = AsyncMock(return_value=(semgrep_output.encode(), b""))

        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.MEDIUM

    def test_semgrep_not_found(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError,
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "semgrep not found" in result.error

    def test_semgrep_error_exit(self) -> None:
        proc = AsyncMock()
        proc.returncode = 2
        proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "Semgrep exited with code 2" in result.error

    def test_timeout(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)

        with (
            patch(
                "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
            patch(
                "whiterabbit.repo_scanner.owasp_scanner.asyncio.wait_for",
                side_effect=TimeoutError,
            ),
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "timed out" in result.error
