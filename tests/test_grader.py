"""Tests for the grading system."""

from __future__ import annotations

from whiterabbit.report.grader import compute_grade
from whiterabbit.report.models import Finding, Severity


def _make_finding(severity: Severity) -> Finding:
    return Finding(
        severity=severity,
        title=f"Test {severity.value}",
        description="Test",
        remediation="Fix",
        category="test",
        scanner="test",
    )


class TestGrading:
    def test_no_findings_is_a_plus(self) -> None:
        assert compute_grade([]) == "A+"

    def test_info_only_is_a(self) -> None:
        findings = [_make_finding(Severity.INFO)]
        assert compute_grade(findings) == "A"

    def test_low_is_b(self) -> None:
        findings = [_make_finding(Severity.LOW)]
        assert compute_grade(findings) == "B"

    def test_low_and_info_is_b(self) -> None:
        findings = [_make_finding(Severity.LOW), _make_finding(Severity.INFO)]
        assert compute_grade(findings) == "B"

    def test_medium_is_c(self) -> None:
        findings = [_make_finding(Severity.MEDIUM)]
        assert compute_grade(findings) == "C"

    def test_high_is_d(self) -> None:
        findings = [_make_finding(Severity.HIGH)]
        assert compute_grade(findings) == "D"

    def test_critical_is_f(self) -> None:
        findings = [_make_finding(Severity.CRITICAL)]
        assert compute_grade(findings) == "F"

    def test_mixed_severities_highest_wins(self) -> None:
        findings = [
            _make_finding(Severity.INFO),
            _make_finding(Severity.LOW),
            _make_finding(Severity.MEDIUM),
            _make_finding(Severity.HIGH),
        ]
        assert compute_grade(findings) == "D"

    def test_critical_trumps_all(self) -> None:
        findings = [_make_finding(s) for s in Severity]
        assert compute_grade(findings) == "F"

    def test_multiple_of_same_severity(self) -> None:
        findings = [_make_finding(Severity.LOW)] * 10
        assert compute_grade(findings) == "B"
