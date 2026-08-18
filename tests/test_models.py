"""Tests for Pydantic data models."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from whiterabbit.report.models import Finding, ScanReport, ScanResult, Severity


class TestSeverity:
    def test_values(self) -> None:
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_all_members(self) -> None:
        assert len(Severity) == 5


class TestFinding:
    def test_minimal(self) -> None:
        f = Finding(
            severity=Severity.HIGH,
            title="Test",
            description="A test finding",
            remediation="Fix it",
            category="test",
            scanner="test_scanner",
        )
        assert f.severity == Severity.HIGH
        assert f.cwe is None
        assert f.cve is None
        assert f.references == []
        assert f.raw is None

    def test_full(self) -> None:
        f = Finding(
            severity=Severity.CRITICAL,
            title="Expired cert",
            description="Certificate expired",
            remediation="Renew",
            category="ssl",
            scanner="ssl",
            cwe="CWE-295",
            cve="CVE-2024-0001",
            references=["https://example.com"],
            raw={"detail": "expired"},
        )
        assert f.cwe == "CWE-295"
        assert f.cve == "CVE-2024-0001"
        assert len(f.references) == 1

    def test_json_round_trip(self, sample_finding: Finding) -> None:
        data = sample_finding.model_dump_json()
        restored = Finding.model_validate_json(data)
        assert restored == sample_finding


class TestScanResult:
    def test_creation(self) -> None:
        r = ScanResult(
            target="example.com",
            scanner_name="test",
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            finished_at=datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
        )
        assert r.findings == []
        assert r.error is None

    def test_with_error(self) -> None:
        r = ScanResult(
            target="example.com",
            scanner_name="test",
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            finished_at=datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc),
            error="Connection refused",
        )
        assert r.error == "Connection refused"

    def test_json_round_trip(self, sample_scan_result: ScanResult) -> None:
        data = sample_scan_result.model_dump_json()
        restored = ScanResult.model_validate_json(data)
        assert restored.target == sample_scan_result.target
        assert len(restored.findings) == len(sample_scan_result.findings)


class TestScanReport:
    def test_creation(self, sample_report: ScanReport) -> None:
        assert sample_report.grade == "F"
        assert sample_report.target == "example.com"
        assert len(sample_report.results) == 1
        assert sample_report.summary[Severity.CRITICAL] == 1

    def test_empty_report(self) -> None:
        r = ScanReport(
            target="clean.example.com",
            scan_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_seconds=5.0,
            grade="A+",
            summary={s: 0 for s in Severity},
            results=[],
            whiterabbit_version="0.1.0",
        )
        assert r.grade == "A+"
        assert sum(r.summary.values()) == 0

    def test_json_serialization(self, sample_report: ScanReport) -> None:
        json_str = sample_report.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["target"] == "example.com"
        assert parsed["grade"] == "F"
        assert "results" in parsed
