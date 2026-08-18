"""Tests for the testssl.sh scanner."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock, patch

import pytest

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Severity
from whiterabbit.scanner.testssl_scanner import (
    TestSSLScanner,
    _is_duplicate_of_ssl_scanner,
    _parse_testssl_finding,
)


class TestIsDuplicateOfSSLScanner:
    def test_heartbleed_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("heartbleed", "Not vulnerable to Heartbleed") is True

    def test_robot_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("ROBOT", "ROBOT test") is True

    def test_sslv2_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("sslv2", "SSLv2 offered") is True

    def test_sslv3_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("sslv3", "SSLv3 offered") is True

    def test_cert_expired_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("cert_expired", "Certificate expired") is True

    def test_cert_chain_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("cert_chain", "Certificate chain issue") is True

    def test_beast_not_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("BEAST", "BEAST vulnerability") is False

    def test_sweet32_not_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("SWEET32", "SWEET32 vulnerability") is False

    def test_poodle_not_duplicate(self) -> None:
        assert _is_duplicate_of_ssl_scanner("POODLE", "POODLE on TLS") is False


class TestParseTestsslFinding:
    def test_known_vuln_beast(self) -> None:
        entry = {"id": "BEAST", "finding": "BEAST: CBC in TLS 1.0", "severity": "HIGH"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "BEAST" in finding.title
        assert finding.cve == "CVE-2011-3389"
        assert finding.scanner == "testssl"

    def test_known_vuln_poodle(self) -> None:
        entry = {"id": "POODLE", "finding": "POODLE on TLS", "severity": "HIGH"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "POODLE" in finding.title
        assert finding.cve == "CVE-2014-8730"

    def test_known_vuln_drown(self) -> None:
        entry = {"id": "DROWN", "finding": "DROWN vulnerability", "severity": "CRITICAL"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.cve == "CVE-2016-0800"

    def test_known_vuln_freak(self) -> None:
        entry = {"id": "FREAK", "finding": "FREAK attack possible", "severity": "HIGH"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_known_vuln_logjam(self) -> None:
        entry = {"id": "Logjam", "finding": "Logjam attack", "severity": "HIGH"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.cve == "CVE-2015-4000"

    def test_known_vuln_sweet32(self) -> None:
        entry = {"id": "SWEET32", "finding": "SWEET32 attack", "severity": "MEDIUM"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_known_vuln_ticketbleed(self) -> None:
        entry = {"id": "Ticketbleed", "finding": "Ticketbleed attack", "severity": "HIGH"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.cve == "CVE-2016-9244"

    def test_known_vuln_lucky13(self) -> None:
        entry = {"id": "Lucky13", "finding": "Lucky13 timing", "severity": "MEDIUM"}
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_ok_finding_skipped(self) -> None:
        entry = {"id": "some_check", "finding": "All good", "severity": "OK"}
        finding = _parse_testssl_finding(entry)
        assert finding is None

    def test_info_finding_skipped(self) -> None:
        entry = {"id": "cert_info", "finding": "Certificate info", "severity": "INFO"}
        finding = _parse_testssl_finding(entry)
        assert finding is None

    def test_known_vuln_ok_severity_skipped(self) -> None:
        entry = {"id": "DROWN", "finding": "not vulnerable (OK)", "severity": "OK"}
        finding = _parse_testssl_finding(entry)
        assert finding is None

    def test_known_vuln_info_severity_skipped(self) -> None:
        entry = {"id": "FREAK", "finding": "not vulnerable", "severity": "INFO"}
        finding = _parse_testssl_finding(entry)
        assert finding is None

    def test_heartbleed_duplicate_skipped(self) -> None:
        entry = {"id": "heartbleed", "finding": "Heartbleed not vulnerable", "severity": "OK"}
        finding = _parse_testssl_finding(entry)
        assert finding is None

    def test_generic_warn_finding(self) -> None:
        entry = {
            "id": "cipher_order",
            "finding": "Server does not enforce cipher order",
            "severity": "WARN",
        }
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_generic_high_finding(self) -> None:
        entry = {
            "id": "some_new_check",
            "finding": "Some new TLS issue detected",
            "severity": "HIGH",
            "cve": "CVE-2025-9999",
        }
        finding = _parse_testssl_finding(entry)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.cve == "CVE-2025-9999"


class TestTestSSLScanner:
    def test_scanner_attributes(self) -> None:
        scanner = TestSSLScanner()
        assert scanner.name == "testssl"
        assert scanner.display_name == "Deep TLS Scanner"
        assert "testssl.sh" in scanner.required_binaries

    def test_successful_scan_with_findings(self) -> None:
        output = json.dumps([
            {"id": "BEAST", "finding": "BEAST CBC in TLS 1.0", "severity": "HIGH"},
            {"id": "SWEET32", "finding": "SWEET32 64-bit block", "severity": "MEDIUM"},
            {"id": "some_ok", "finding": "All good", "severity": "OK"},
        ]).encode()

        async def mock_communicate() -> tuple[bytes, bytes]:
            return output, b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", return_value=proc_mock):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 2
        titles = [f.title for f in result.findings]
        assert any("BEAST" in t for t in titles)
        assert any("SWEET32" in t for t in titles)

    def test_no_findings(self) -> None:
        output = json.dumps([
            {"id": "check1", "finding": "OK", "severity": "OK"},
            {"id": "check2", "finding": "Info", "severity": "INFO"},
        ]).encode()

        async def mock_communicate() -> tuple[bytes, bytes]:
            return output, b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", return_value=proc_mock):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 0

    def test_deduplicates_ssl_scanner_findings(self) -> None:
        output = json.dumps([
            {"id": "heartbleed", "finding": "Heartbleed not vulnerable", "severity": "OK"},
            {"id": "sslv2", "finding": "SSLv2 offered", "severity": "CRITICAL"},
            {"id": "BEAST", "finding": "BEAST CBC in TLS 1.0", "severity": "HIGH"},
        ]).encode()

        async def mock_communicate() -> tuple[bytes, bytes]:
            return output, b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", return_value=proc_mock):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 1
        assert "BEAST" in result.findings[0].title

    def test_testssl_not_found(self) -> None:
        with patch(
            "whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError("testssl.sh not found"),
        ):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "testssl.sh not found" in result.error

    def test_testssl_error_exit(self) -> None:
        async def mock_communicate() -> tuple[bytes, bytes]:
            return b"", b"Fatal error"

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 2

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", return_value=proc_mock):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "exited with code 2" in result.error

    def test_testssl_timeout(self) -> None:
        async def mock_create(*args, **kwargs):
            raise asyncio.TimeoutError()

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", side_effect=mock_create):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig(timeout=10)))

        assert result.error is not None
        assert "timed out" in result.error

    def test_general_exception(self) -> None:
        with patch(
            "whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec",
            side_effect=RuntimeError("unexpected"),
        ):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "unexpected" in result.error

    def test_jsonl_output_format(self) -> None:
        lines = [
            json.dumps({"id": "BEAST", "finding": "BEAST CBC", "severity": "HIGH"}),
            json.dumps({"id": "Logjam", "finding": "Logjam weak DH", "severity": "HIGH"}),
        ]
        output = "\n".join(lines).encode()

        async def mock_communicate() -> tuple[bytes, bytes]:
            return output, b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", return_value=proc_mock):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 2

    def test_target_normalization(self) -> None:
        output = json.dumps([]).encode()

        async def mock_communicate() -> tuple[bytes, bytes]:
            return output, b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        calls = []

        async def capture_exec(*args, **kwargs):
            calls.append(args)
            return proc_mock

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", side_effect=capture_exec):
            scanner = TestSSLScanner()
            asyncio.run(scanner.scan("example.com", ScanConfig()))

        cmd_args = calls[0]
        assert "https://example.com" in cmd_args

    def test_empty_output_no_error(self) -> None:
        async def mock_communicate() -> tuple[bytes, bytes]:
            return b"", b""

        proc_mock = MagicMock()
        proc_mock.communicate = mock_communicate
        proc_mock.returncode = 0

        with patch("whiterabbit.scanner.testssl_scanner.asyncio.create_subprocess_exec", return_value=proc_mock):
            scanner = TestSSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 0
