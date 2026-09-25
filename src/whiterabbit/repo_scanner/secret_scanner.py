"""Secret scanner — detects committed credentials using TruffleHog."""

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


def _build_command(repo_path: str) -> list[str]:
    return [
        resolve_binary("trufflehog") or "trufflehog",
        "filesystem",
        "--json",
        "--no-update",
        repo_path,
    ]


def _redact(raw: str, keep: int = 5) -> str:
    if len(raw) <= keep:
        return "***"
    return raw[:keep] + "***"


def _parse_trufflehog_output(raw: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        detector = obj.get("DetectorName", "") or obj.get("DetectorType", "unknown")
        verified = obj.get("Verified", False)

        source_meta = obj.get("SourceMetadata", {})
        data = source_meta.get("Data", {})
        filesystem = data.get("Filesystem", {})
        filepath = filesystem.get("file", "")
        line_num = filesystem.get("line", 0)

        secret_raw = obj.get("Raw", "")
        dedup_key = f"{detector}|{filepath}|{_redact(secret_raw, 10)}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        severity = Severity.CRITICAL if verified else Severity.MEDIUM
        status = "verified active" if verified else "unverified"

        location = f"{filepath}:{line_num}" if filepath and line_num else filepath

        title = f"{detector} secret ({status})"
        if location:
            title += f" — {location}"

        description = f"Detected a {detector} credential in the source code."
        if verified:
            description += " This secret was verified as currently active."

        findings.append(
            Finding(
                severity=severity,
                title=title,
                description=description,
                remediation=f"Revoke the {detector} credential immediately and rotate it. Remove the secret from source code and use environment variables or a secrets manager instead.",
                category="secret",
                scanner="secret",
                raw={
                    "detector": detector,
                    "verified": verified,
                    "file": filepath,
                    "line": line_num,
                    "redacted": _redact(secret_raw),
                },
            )
        )

    return findings


class SecretScanner(BaseRepoScanner):
    name = "secret"
    display_name = "Secret Scanner"
    description = "Detects committed secrets and credentials using TruffleHog"
    required_binaries: ClassVar[list[str]] = ["trufflehog"]

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
                    error=f"TruffleHog exited with code {proc.returncode}: {error_msg}",
                )

            findings = _parse_trufflehog_output(stdout.decode(errors="replace"))

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
                error="trufflehog not found. Install: https://github.com/trufflesecurity/trufflehog",
            )
        except TimeoutError:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"TruffleHog timed out after {timeout + 30}s",
            )
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
