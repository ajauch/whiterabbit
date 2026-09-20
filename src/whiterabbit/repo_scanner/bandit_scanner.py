"""Bandit scanner — Python-specific security linting."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import ClassVar

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.resolve import resolve_binary, subprocess_env

log = logging.getLogger("whiterabbit")

BANDIT_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

CONFIDENCE_BOOST: dict[str, int] = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
}

SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


_EXCLUDED_DIRS = "tests,test,.tox,.eggs"

_SKIPPED_TESTS = ",".join(
    [
        "B101",  # assert_used — standard in test code, not a security issue
    ]
)


def _build_command(repo_path: str) -> list[str]:
    return [
        resolve_binary("bandit") or "bandit",
        "-r",
        repo_path,
        "-f",
        "json",
        "-q",
        "--exit-zero",
        "--exclude",
        _EXCLUDED_DIRS,
        "--skip",
        _SKIPPED_TESTS,
    ]


def _adjusted_severity(severity: str, confidence: str) -> Severity:
    base = BANDIT_SEVERITY_MAP.get(severity, Severity.MEDIUM)
    downgrade = CONFIDENCE_BOOST.get(confidence, 0)
    idx = SEVERITY_ORDER.index(base)
    adjusted_idx = max(0, idx - downgrade)
    return SEVERITY_ORDER[adjusted_idx]


def _parse_bandit_output(raw: str) -> list[Finding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()

    for result in data.get("results", []):
        test_id = result.get("test_id", "")
        filename = result.get("filename", "")
        line = result.get("line_number", 0)

        dedup_key = f"{test_id}|{filename}|{line}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        confidence = result.get("issue_confidence", "MEDIUM")
        if confidence == "LOW":
            continue

        severity_str = result.get("issue_severity", "MEDIUM")
        severity = _adjusted_severity(severity_str, confidence)

        test_name = result.get("test_name", test_id)
        issue_text = result.get("issue_text", "")
        location = f"{filename}:{line}" if filename and line else filename

        title = f"{test_name} [{test_id}] — {location}"

        cwe_data = result.get("issue_cwe", {})
        cwe_id = None
        if isinstance(cwe_data, dict):
            cwe_num = cwe_data.get("id")
            if cwe_num:
                cwe_id = f"CWE-{cwe_num}"

        references: list[str] = []
        more_info = result.get("more_info", "")
        if more_info:
            references.append(more_info)

        findings.append(
            Finding(
                severity=severity,
                title=title,
                description=issue_text[:500],
                remediation="Review and fix the identified security issue.",
                category="python-security",
                scanner="bandit",
                cwe=cwe_id,
                references=references,
                raw={
                    "test_id": test_id,
                    "test_name": test_name,
                    "path": filename,
                    "line": line,
                    "confidence": confidence,
                },
            )
        )

    return findings


class BanditScanner(BaseRepoScanner):
    name = "bandit"
    display_name = "Bandit Scanner"
    description = "Python-specific security linting using Bandit"
    required_binaries: ClassVar[list[str]] = ["bandit"]

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(UTC)
        timeout = self.effective_timeout(config)
        cmd = _build_command(repo_path)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=subprocess_env(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout + 30,
            )

            if proc.returncode not in (0, 1):
                error_msg = stderr.decode(errors="replace").strip()
                return ScanResult(
                    target=repo_path,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                    error=f"Bandit exited with code {proc.returncode}: {error_msg}",
                )

            findings = _parse_bandit_output(stdout.decode(errors="replace"))

            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                findings=findings,
            )

        except FileNotFoundError:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error="bandit not found. Install: pip install bandit",
            )
        except TimeoutError:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Bandit timed out after {timeout + 30}s",
            )
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
