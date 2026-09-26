"""Pydantic data models shared by all scanners and report formatters."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Finding(BaseModel):
    severity: Severity
    title: str
    description: str
    remediation: str
    category: str
    scanner: str
    cwe: str | None = None
    cve: str | None = None
    references: list[str] = Field(default_factory=list)
    raw: dict[str, object] | None = None


class ScanResult(BaseModel):
    target: str
    scanner_name: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None


class UnavailableScanner(BaseModel):
    scanner: str
    reason: str


class ScanReport(BaseModel):
    target: str
    scan_date: datetime
    duration_seconds: float
    grade: str
    summary: dict[Severity, int]
    results: list[ScanResult] = Field(default_factory=list)
    scanners_unavailable: list[UnavailableScanner] = Field(default_factory=list)
    whiterabbit_version: str
    languages: dict[str, int] | None = None
