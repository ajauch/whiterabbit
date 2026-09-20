"""Tests for the Trivy scanner."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.trivy_scanner import (
    TrivyScanner,
    _build_command,
    _parse_trivy_output,
)
from whiterabbit.report.models import Severity

SAMPLE_TRIVY_OUTPUT = {
    "Results": [
        {
            "Target": "requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "HIGH",
                    "Title": "HTTP request smuggling vulnerability",
                    "Description": "A vulnerability in requests allows HTTP smuggling.",
                    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-1234"],
                    "CweIDs": ["CWE-444"],
                },
                {
                    "VulnerabilityID": "CVE-2023-5678",
                    "PkgName": "flask",
                    "InstalledVersion": "2.2.0",
                    "FixedVersion": "",
                    "Severity": "CRITICAL",
                    "Title": "Remote code execution",
                    "References": [],
                },
            ],
            "Misconfigurations": None,
        },
        {
            "Target": "Dockerfile",
            "Vulnerabilities": None,
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Root user in Dockerfile",
                    "Message": "Running as root is a security risk.",
                    "Severity": "HIGH",
                    "Resolution": "Use a non-root user.",
                    "References": ["https://docs.docker.com/develop/security/"],
                }
            ],
        },
    ]
}


class TestBuildCommand:
    def test_default_command(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.trivy_scanner.resolve_binary",
            return_value="/usr/bin/trivy",
        ):
            cmd = _build_command("/tmp/repo", 300)
        assert cmd[0] == "/usr/bin/trivy"
        assert "fs" in cmd
        assert "--format" in cmd
        assert "json" in cmd
        assert "--scanners" in cmd
        assert "vuln,misconfig,license" in cmd
        assert "/tmp/repo" in cmd

    def test_timeout_in_command(self) -> None:
        cmd = _build_command("/tmp/repo", 600)
        idx = cmd.index("--timeout")
        assert cmd[idx + 1] == "600s"


class TestParseTrivyOutput:
    def test_vulnerabilities(self) -> None:
        output = json.dumps(SAMPLE_TRIVY_OUTPUT)
        findings = _parse_trivy_output(output)
        vuln_findings = [f for f in findings if f.category == "dependency-cve"]
        assert len(vuln_findings) == 2
        assert vuln_findings[0].severity == Severity.HIGH
        assert vuln_findings[0].cve == "CVE-2023-1234"
        assert vuln_findings[0].cwe == "CWE-444"
        assert "requests" in vuln_findings[0].title
        assert "2.31.0" in vuln_findings[0].remediation

    def test_critical_vulnerability(self) -> None:
        output = json.dumps(SAMPLE_TRIVY_OUTPUT)
        findings = _parse_trivy_output(output)
        vuln_findings = [f for f in findings if f.category == "dependency-cve"]
        flask_finding = next(f for f in vuln_findings if "flask" in f.title.lower())
        assert flask_finding.severity == Severity.CRITICAL
        assert "patched version" in flask_finding.remediation

    def test_misconfigurations(self) -> None:
        output = json.dumps(SAMPLE_TRIVY_OUTPUT)
        findings = _parse_trivy_output(output)
        mc_findings = [f for f in findings if f.category == "iac-misconfig"]
        assert len(mc_findings) == 1
        assert mc_findings[0].severity == Severity.HIGH
        assert "DS002" in mc_findings[0].title
        assert "non-root" in mc_findings[0].remediation.lower()

    def test_deduplication(self) -> None:
        data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "requests",
                            "InstalledVersion": "2.28.0",
                            "Severity": "HIGH",
                        },
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "requests",
                            "InstalledVersion": "2.28.0",
                            "Severity": "HIGH",
                        },
                    ],
                }
            ]
        }
        findings = _parse_trivy_output(json.dumps(data))
        assert len(findings) == 1

    def test_empty_results(self) -> None:
        output = json.dumps({"Results": []})
        findings = _parse_trivy_output(output)
        assert findings == []

    def test_invalid_json(self) -> None:
        findings = _parse_trivy_output("not json")
        assert findings == []

    def test_no_results_key(self) -> None:
        findings = _parse_trivy_output(json.dumps({}))
        assert findings == []

    def test_scanner_field(self) -> None:
        output = json.dumps(SAMPLE_TRIVY_OUTPUT)
        findings = _parse_trivy_output(output)
        assert all(f.scanner == "trivy" for f in findings)


class TestTrivyScanner:
    def test_is_available_without_trivy(self) -> None:
        with patch("whiterabbit.repo_scanner.base.resolve_binary", return_value=None):
            scanner = TrivyScanner()
            assert not scanner.is_available()

    def test_is_available_with_trivy(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.base.resolve_binary",
            return_value="/usr/bin/trivy",
        ):
            scanner = TrivyScanner()
            assert scanner.is_available()

    def test_successful_scan(self) -> None:
        trivy_output = json.dumps(SAMPLE_TRIVY_OUTPUT)

        proc = AsyncMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(trivy_output.encode(), b""))

        with patch(
            "whiterabbit.repo_scanner.trivy_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = TrivyScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is None
            assert len(result.findings) == 3

    def test_trivy_not_found(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.trivy_scanner.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError,
        ):
            scanner = TrivyScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "trivy not found" in result.error

    def test_trivy_error_exit(self) -> None:
        proc = AsyncMock()
        proc.returncode = 2
        proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch(
            "whiterabbit.repo_scanner.trivy_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = TrivyScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "Trivy exited with code 2" in result.error

    def test_timeout(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)

        with (
            patch(
                "whiterabbit.repo_scanner.trivy_scanner.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
            patch(
                "whiterabbit.repo_scanner.trivy_scanner.asyncio.wait_for",
                side_effect=TimeoutError,
            ),
        ):
            scanner = TrivyScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "timed out" in result.error
