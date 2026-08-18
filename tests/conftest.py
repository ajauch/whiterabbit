"""Shared test fixtures."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanReport, ScanResult, Severity


@pytest.fixture
def sample_config() -> ScanConfig:
    return ScanConfig()


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        severity=Severity.HIGH,
        title="Missing HSTS header",
        description="The Strict-Transport-Security header is not set.",
        remediation="Add the HSTS header to your server configuration.",
        category="headers",
        scanner="headers",
        cwe="CWE-523",
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(
            severity=Severity.CRITICAL,
            title="Expired certificate",
            description="The SSL certificate has expired.",
            remediation="Renew the certificate.",
            category="ssl",
            scanner="ssl",
        ),
        Finding(
            severity=Severity.HIGH,
            title="Missing HSTS",
            description="HSTS header not set.",
            remediation="Add HSTS header.",
            category="headers",
            scanner="headers",
        ),
        Finding(
            severity=Severity.MEDIUM,
            title="TLS 1.3 not supported",
            description="Server does not support TLS 1.3.",
            remediation="Enable TLS 1.3.",
            category="ssl",
            scanner="ssl",
        ),
        Finding(
            severity=Severity.LOW,
            title="Server header exposed",
            description="Server header reveals version info.",
            remediation="Remove or obscure the Server header.",
            category="headers",
            scanner="headers",
        ),
        Finding(
            severity=Severity.INFO,
            title="HTTP/2 supported",
            description="Server supports HTTP/2.",
            remediation="No action needed.",
            category="headers",
            scanner="headers",
        ),
    ]


@pytest.fixture
def sample_scan_result(sample_findings: list[Finding]) -> ScanResult:
    return ScanResult(
        target="example.com",
        scanner_name="test_scanner",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 0, 0, 30, tzinfo=timezone.utc),
        findings=sample_findings,
    )


@pytest.fixture
def sample_report(sample_scan_result: ScanResult) -> ScanReport:
    return ScanReport(
        target="example.com",
        scan_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
        duration_seconds=30.0,
        grade="F",
        summary={
            Severity.CRITICAL: 1,
            Severity.HIGH: 1,
            Severity.MEDIUM: 1,
            Severity.LOW: 1,
            Severity.INFO: 1,
        },
        results=[sample_scan_result],
        whiterabbit_version="0.1.0",
    )
