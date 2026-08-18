"""Nuclei scanner — passive templates only (misconfig, exposure, tech detection)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.scanner.base import BaseScanner

EXCLUDED_TAGS = frozenset({
    "fuzz", "exploit", "intrusive", "dos", "brute",
    "sqli", "xss", "rce", "auth-bypass",
})

DEFAULT_TAGS = ["exposure", "misconfig", "tech"]

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _normalize_target(target: str) -> str:
    if "://" not in target:
        return f"https://{target}"
    return target


def _build_command(target: str, tags: list[str], timeout: int) -> list[str]:
    cmd = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-silent",
        "-tags", ",".join(tags),
        "-exclude-tags", ",".join(sorted(EXCLUDED_TAGS)),
        "-timeout", str(timeout),
        "-no-color",
    ]
    return cmd


def _parse_finding(line: str) -> Finding | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    info = data.get("info", {})
    severity_str = info.get("severity", "info").lower()
    severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

    template_id = data.get("template-id", "unknown")
    name = info.get("name", template_id)
    matched_at = data.get("matched-at", data.get("host", ""))
    description = info.get("description", f"Nuclei template {template_id} matched.")

    references = info.get("reference", [])
    if isinstance(references, str):
        references = [references]

    classification = info.get("classification", {})
    cve_id = None
    cwe_id = None
    cve_list = classification.get("cve-id")
    if cve_list and isinstance(cve_list, list) and cve_list[0]:
        cve_id = cve_list[0]
    elif isinstance(cve_list, str) and cve_list:
        cve_id = cve_list
    cwe_list = classification.get("cwe-id")
    if cwe_list and isinstance(cwe_list, list) and cwe_list[0]:
        cwe_id = cwe_list[0]
    elif isinstance(cwe_list, str) and cwe_list:
        cwe_id = cwe_list

    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]

    remediation = info.get("remediation", "Review the matched endpoint and apply appropriate security controls.")

    category = "nuclei"
    if any(t in tags for t in ("exposure", "exposed")):
        category = "exposure"
    elif "misconfig" in tags:
        category = "misconfig"
    elif "tech" in tags:
        category = "tech"

    return Finding(
        severity=severity,
        title=f"{name} — {matched_at}" if matched_at else name,
        description=description,
        remediation=remediation,
        category=category,
        scanner="nuclei",
        cwe=cwe_id,
        cve=cve_id,
        references=references if references else [],
        raw=data,
    )


class NucleiScanner(BaseScanner):
    name = "nuclei"
    display_name = "Nuclei Scanner"
    description = "Detects misconfigurations and exposures using Nuclei (passive templates only)"
    required_binaries: list[str] = ["nuclei"]

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        url = _normalize_target(target)
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []

        tags = list(DEFAULT_TAGS)
        cmd = _build_command(url, tags, config.timeout)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=config.timeout + 30,
            )

            if proc.returncode not in (0, 1):
                error_msg = stderr.decode(errors="replace").strip()
                return ScanResult(
                    target=target,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(timezone.utc),
                    error=f"Nuclei exited with code {proc.returncode}: {error_msg}",
                )

            for line in stdout.decode(errors="replace").strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                finding = _parse_finding(line)
                if finding:
                    findings.append(finding)

        except FileNotFoundError:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                error="nuclei not found. Install: https://github.com/projectdiscovery/nuclei#install-nuclei",
            )
        except asyncio.TimeoutError:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                error=f"Nuclei timed out after {config.timeout + 30}s",
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                error=str(exc),
            )

        return ScanResult(
            target=target,
            scanner_name=self.name,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
        )
