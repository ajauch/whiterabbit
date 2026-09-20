"""Trivy scanner — filesystem scanning for vulnerabilities, IaC misconfigs, and licenses."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.resolve import resolve_binary, subprocess_env

log = logging.getLogger("whiterabbit")

TRIVY_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def _build_command(repo_path: str, timeout: int) -> list[str]:
    return [
        resolve_binary("trivy") or "trivy",
        "fs",
        "--scanners",
        "vuln,misconfig,license",
        "--format",
        "json",
        "--quiet",
        "--timeout",
        f"{timeout}s",
        repo_path,
    ]


def _parse_vulnerability(vuln: dict[str, Any], target: str) -> Finding:
    severity = TRIVY_SEVERITY_MAP.get(vuln.get("Severity", ""), Severity.MEDIUM)
    vuln_id = vuln.get("VulnerabilityID", "")
    pkg = vuln.get("PkgName", "")
    installed = vuln.get("InstalledVersion", "")
    fixed = vuln.get("FixedVersion", "")

    title = f"{vuln_id}: {pkg}" if pkg else vuln_id
    if installed:
        title += f" ({installed})"

    description = vuln.get("Title", "") or vuln.get("Description", "")

    remediation = (
        f"Update {pkg} to {fixed}." if fixed else f"Update {pkg} to a patched version."
    )
    if not pkg:
        remediation = "Update the affected dependency to a patched version."

    references: list[str] = []
    for ref in vuln.get("References", [])[:5]:
        if isinstance(ref, str):
            references.append(ref)

    cwe_ids = vuln.get("CweIDs", [])
    cwe = str(cwe_ids[0]) if cwe_ids else None

    return Finding(
        severity=severity,
        title=title,
        description=description[:500],
        remediation=remediation,
        category="dependency-cve",
        scanner="trivy",
        cwe=cwe,
        cve=vuln_id if vuln_id.startswith("CVE-") else None,
        references=references,
        raw={"target": target, "pkg": pkg, "installed": installed, "fixed": fixed},
    )


def _parse_misconfig(mc: dict[str, Any], target: str) -> Finding:
    severity = TRIVY_SEVERITY_MAP.get(mc.get("Severity", ""), Severity.MEDIUM)
    mc_id = mc.get("ID", "")
    title_text = mc.get("Title", mc_id)
    title = f"{mc_id}: {title_text}" if mc_id and title_text != mc_id else title_text

    description = mc.get("Message", "") or mc.get("Description", "")
    remediation = mc.get(
        "Resolution", "Review and fix the identified misconfiguration."
    )

    references: list[str] = []
    for ref in mc.get("References", [])[:5]:
        if isinstance(ref, str):
            references.append(ref)

    return Finding(
        severity=severity,
        title=f"{title} — {target}",
        description=description[:500],
        remediation=remediation or "Review and fix the identified misconfiguration.",
        category="iac-misconfig",
        scanner="trivy",
        references=references,
        raw={"target": target, "id": mc_id},
    )


def _parse_trivy_output(raw: str) -> list[Finding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()

    for result in data.get("Results", []):
        target = result.get("Target", "")

        for vuln in result.get("Vulnerabilities", []) or []:
            vuln_id = vuln.get("VulnerabilityID", "")
            pkg = vuln.get("PkgName", "")
            dedup_key = f"vuln|{vuln_id}|{pkg}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(_parse_vulnerability(vuln, target))

        for mc in result.get("Misconfigurations", []) or []:
            mc_id = mc.get("ID", "")
            dedup_key = f"mc|{mc_id}|{target}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(_parse_misconfig(mc, target))

    return findings


class TrivyScanner(BaseRepoScanner):
    name = "trivy"
    display_name = "Trivy Scanner"
    description = "Scans for dependency CVEs, IaC misconfigurations, and license issues using Trivy"
    required_binaries: ClassVar[list[str]] = ["trivy"]

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(UTC)
        timeout = self.effective_timeout(config)
        cmd = _build_command(repo_path, timeout)

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
                    error=f"Trivy exited with code {proc.returncode}: {error_msg}",
                )

            findings = _parse_trivy_output(stdout.decode(errors="replace"))

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
                error="trivy not found. Install: https://aquasecurity.github.io/trivy/",
            )
        except TimeoutError:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Trivy timed out after {timeout + 30}s",
            )
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
