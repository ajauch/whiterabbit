"""Tests for HTML report generation."""

from __future__ import annotations

import tempfile
from datetime import UTC
from pathlib import Path

from whiterabbit.report.formatters.html import format_html, write_html
from whiterabbit.report.models import ScanReport


class TestHTMLReport:
    def test_generates_html(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "<!DOCTYPE html>" in html
        assert "WhiteRabbit Scan Report" in html
        assert "example.com" in html

    def test_contains_grade(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert sample_report.grade in html

    def test_contains_findings(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        for result in sample_report.results:
            for finding in result.findings:
                assert finding.title in html

    def test_contains_severity_badges(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "badge-critical" in html
        assert "badge-high" in html
        assert "badge-medium" in html
        assert "badge-low" in html

    def test_contains_remediation(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "Remediation" in html

    def test_contains_filter_buttons(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "filter-btn" in html
        assert "filterBy" in html

    def test_contains_sort_js(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "sortTable" in html

    def test_contains_scanner_details(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "Scanner Details" in html
        assert "test_scanner" in html

    def test_dark_mode_support(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "prefers-color-scheme: dark" in html

    def test_print_css(self, sample_report: ScanReport) -> None:
        html = format_html(sample_report)
        assert "@media print" in html

    def test_write_to_file(self, sample_report: ScanReport) -> None:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        write_html(sample_report, path)
        content = Path(path).read_text(encoding="utf-8")
        assert "WhiteRabbit Scan Report" in content
        assert "example.com" in content
        Path(path).unlink()

    def test_empty_report_shows_no_issues(self) -> None:
        from datetime import datetime

        from whiterabbit.report.models import Severity

        report = ScanReport(
            target="clean.example.com",
            scan_date=datetime(2026, 1, 1, tzinfo=UTC),
            duration_seconds=1.0,
            grade="A+",
            summary={s: 0 for s in Severity},
            results=[],
            whiterabbit_version="0.1.0",
        )
        html = format_html(report)
        assert "No issues found" in html
        assert "grade-aplus" in html
