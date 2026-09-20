"""Tests for the Nuclei scanner."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Severity
from whiterabbit.scanner.nuclei_scanner import (
    EXCLUDED_TAGS,
    NucleiScanner,
    _build_command,
    _parse_finding,
)


class TestBuildCommand:
    def test_basic_command(self) -> None:
        with patch(
            "whiterabbit.scanner.nuclei_scanner.resolve_binary",
            return_value="/usr/bin/nuclei",
        ):
            cmd = _build_command("https://example.com", ["exposure", "misconfig"], 300)
        assert cmd[0] == "/usr/bin/nuclei"
        assert "-u" in cmd
        assert cmd[cmd.index("-u") + 1] == "https://example.com"
        assert "-jsonl" in cmd
        assert "-silent" in cmd
        assert "-tags" in cmd
        assert "-exclude-tags" in cmd

    def test_excluded_tags_present(self) -> None:
        cmd = _build_command("https://example.com", ["exposure"], 300)
        idx = cmd.index("-exclude-tags")
        excluded = cmd[idx + 1].split(",")
        for tag in EXCLUDED_TAGS:
            assert tag in excluded

    def test_timeout_included(self) -> None:
        cmd = _build_command("https://example.com", ["exposure"], 120)
        idx = cmd.index("-timeout")
        assert cmd[idx + 1] == "120"


class TestParseFinding:
    def test_valid_finding(self) -> None:
        line = json.dumps(
            {
                "template-id": "git-config",
                "info": {
                    "name": "Git Config Exposure",
                    "severity": "medium",
                    "description": "Git configuration file is publicly accessible.",
                    "tags": ["exposure", "git"],
                    "reference": ["https://example.com/ref"],
                    "classification": {
                        "cve-id": ["CVE-2024-1234"],
                        "cwe-id": ["CWE-200"],
                    },
                    "remediation": "Block access to .git directory.",
                },
                "matched-at": "https://example.com/.git/config",
                "host": "https://example.com",
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert "Git Config Exposure" in finding.title
        assert finding.cve == "CVE-2024-1234"
        assert finding.cwe == "CWE-200"
        assert finding.category == "exposure"
        assert finding.scanner == "nuclei"
        assert "Block access" in finding.remediation

    def test_critical_finding(self) -> None:
        line = json.dumps(
            {
                "template-id": "env-file",
                "info": {
                    "name": "Environment File Exposed",
                    "severity": "critical",
                    "description": ".env file is publicly accessible.",
                    "tags": ["exposure"],
                },
                "matched-at": "https://example.com/.env",
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_info_finding(self) -> None:
        line = json.dumps(
            {
                "template-id": "tech-detect",
                "info": {
                    "name": "Nginx Detected",
                    "severity": "info",
                    "tags": ["tech"],
                },
                "matched-at": "https://example.com",
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.severity == Severity.INFO
        assert finding.category == "tech"

    def test_misconfig_category(self) -> None:
        line = json.dumps(
            {
                "template-id": "cors-misconfig",
                "info": {
                    "name": "CORS Misconfiguration",
                    "severity": "high",
                    "tags": ["misconfig"],
                },
                "matched-at": "https://example.com",
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.category == "misconfig"

    def test_secret_category(self) -> None:
        line = json.dumps(
            {
                "template-id": "aws-key-exposed",
                "info": {
                    "name": "AWS Access Key Exposed",
                    "severity": "high",
                    "tags": ["token", "secret", "exposure"],
                },
                "matched-at": "https://example.com/config.js",
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.category == "secret"
        assert finding.severity == Severity.HIGH

    def test_token_only_category(self) -> None:
        line = json.dumps(
            {
                "template-id": "api-key-leak",
                "info": {
                    "name": "API Key in Response",
                    "severity": "medium",
                    "tags": ["token"],
                },
                "matched-at": "https://example.com/api/config",
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.category == "secret"

    def test_invalid_json(self) -> None:
        assert _parse_finding("not json") is None

    def test_no_matched_at(self) -> None:
        line = json.dumps(
            {
                "template-id": "test",
                "info": {
                    "name": "Test Finding",
                    "severity": "low",
                    "tags": [],
                },
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.title == "Test Finding"

    def test_string_reference(self) -> None:
        line = json.dumps(
            {
                "template-id": "test",
                "info": {
                    "name": "Test",
                    "severity": "low",
                    "reference": "https://example.com",
                    "tags": [],
                },
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.references == ["https://example.com"]

    def test_string_cve_id(self) -> None:
        line = json.dumps(
            {
                "template-id": "test",
                "info": {
                    "name": "Test",
                    "severity": "low",
                    "classification": {"cve-id": "CVE-2024-0001"},
                    "tags": [],
                },
            }
        )
        finding = _parse_finding(line)
        assert finding is not None
        assert finding.cve == "CVE-2024-0001"


class TestNucleiScanner:
    def test_scanner_attributes(self) -> None:
        scanner = NucleiScanner()
        assert scanner.name == "nuclei"
        assert scanner.display_name == "Nuclei Scanner"
        assert "nuclei" in scanner.required_binaries

    def test_successful_scan(self) -> None:
        findings_json = [
            json.dumps(
                {
                    "template-id": "git-config",
                    "info": {
                        "name": "Git Config Exposure",
                        "severity": "medium",
                        "description": "Git config exposed.",
                        "tags": ["exposure"],
                    },
                    "matched-at": "https://example.com/.git/config",
                }
            ),
            json.dumps(
                {
                    "template-id": "env-file",
                    "info": {
                        "name": "Env File Exposed",
                        "severity": "high",
                        "description": ".env file exposed.",
                        "tags": ["exposure"],
                    },
                    "matched-at": "https://example.com/.env",
                }
            ),
        ]
        stdout = "\n".join(findings_json).encode()

        async def mock_communicate() -> tuple[bytes, bytes]:
            return stdout, b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            return_value=proc_mock,
        ):
            scanner = NucleiScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 2
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[1].severity == Severity.HIGH

    def test_no_findings(self) -> None:
        async def mock_communicate() -> tuple[bytes, bytes]:
            return b"", b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            return_value=proc_mock,
        ):
            scanner = NucleiScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 0

    def test_nuclei_not_found(self) -> None:
        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("nuclei not found"),
        ):
            scanner = NucleiScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "nuclei not found" in result.error

    def test_nuclei_error_exit(self) -> None:
        async def mock_communicate() -> tuple[bytes, bytes]:
            return b"", b"template loading error"

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 2

        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            return_value=proc_mock,
        ):
            scanner = NucleiScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "exited with code 2" in result.error

    def test_nuclei_timeout(self) -> None:
        async def mock_create(*args, **kwargs):
            raise TimeoutError()

        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            side_effect=mock_create,
        ):
            scanner = NucleiScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig(timeout=10)))

        assert result.error is not None
        assert "timed out" in result.error

    def test_general_exception(self) -> None:
        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            side_effect=RuntimeError("unexpected error"),
        ):
            scanner = NucleiScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "unexpected error" in result.error

    def test_target_normalization(self) -> None:
        async def mock_communicate() -> tuple[bytes, bytes]:
            return b"", b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        calls = []

        async def capture_exec(*args, **kwargs):
            calls.append(args)
            return proc_mock

        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            side_effect=capture_exec,
        ):
            scanner = NucleiScanner()
            asyncio.run(scanner.scan("example.com", ScanConfig()))

        cmd_args = calls[0]
        assert "https://example.com" in cmd_args

    def test_exit_code_1_ok(self) -> None:
        stdout = json.dumps(
            {
                "template-id": "test",
                "info": {"name": "Test", "severity": "low", "tags": []},
                "matched-at": "https://example.com",
            }
        ).encode()

        async def mock_communicate() -> tuple[bytes, bytes]:
            return stdout, b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 1

        with patch(
            "whiterabbit.scanner.nuclei_scanner.asyncio.create_subprocess_exec",
            return_value=proc_mock,
        ):
            scanner = NucleiScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 1


class TestExcludedTagsNotOverridable:
    def test_excluded_tags_always_present(self) -> None:
        cmd = _build_command("https://example.com", ["exposure", "fuzz"], 300)
        idx = cmd.index("-exclude-tags")
        excluded = set(cmd[idx + 1].split(","))
        assert "fuzz" in excluded
        assert "exploit" in excluded
        assert "intrusive" in excluded
        assert "dos" in excluded
        assert "brute" in excluded
        assert "sqli" in excluded
        assert "xss" in excluded
        assert "rce" in excluded
        assert "auth-bypass" in excluded
