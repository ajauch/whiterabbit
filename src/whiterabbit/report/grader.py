"""Compute an A+ through F letter grade from scan findings."""

from __future__ import annotations

from whiterabbit.report.models import Finding, Severity


def compute_grade(findings: list[Finding]) -> str:
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    if counts[Severity.CRITICAL] > 0:
        return "F"
    if counts[Severity.HIGH] > 0:
        return "D"
    if counts[Severity.MEDIUM] > 0:
        return "C"
    if counts[Severity.LOW] > 0:
        return "B"
    if counts[Severity.INFO] > 0:
        return "A"
    return "A+"
