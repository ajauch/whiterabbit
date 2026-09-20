"""Dependency CVE scanner — queries the OSV.dev API for known vulnerabilities."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import httpx

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.repo_scanner.manifest import detect_ecosystems
from whiterabbit.report.models import Finding, ScanResult, Severity

log = logging.getLogger("whiterabbit")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 1000


# ---------------------------------------------------------------------------
# OSV API query
# ---------------------------------------------------------------------------


def _chunks(items: list[Any], size: int) -> Iterator[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _cvss_to_severity(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFO


def _extract_cvss_score(vuln: dict[str, object]) -> float | None:
    severity_list = vuln.get("severity", [])
    if not isinstance(severity_list, list):
        return None
    for entry in severity_list:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if isinstance(score, str):
            parts = score.split("/")
            for part in parts:
                try:
                    return float(part)
                except ValueError:
                    continue
        elif isinstance(score, int | float):
            return float(score)
    return None


async def _query_osv(
    client: httpx.AsyncClient,
    ecosystem: str,
    packages: list[tuple[str, str]],
) -> list[dict[str, object]]:
    """Query OSV.dev for vulnerabilities in the given packages."""
    all_results: list[dict[str, object]] = []
    queries = [
        {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        for name, version in packages
    ]
    for chunk in _chunks(queries, OSV_BATCH_SIZE):
        response = await client.post(
            OSV_BATCH_URL,
            json={"queries": chunk},
            timeout=30,
        )
        response.raise_for_status()
        batch_results = response.json().get("results", [])
        for i, result in enumerate(batch_results):
            vulns = result.get("vulns", [])
            if vulns and i < len(chunk):
                pkg_info = chunk[i]
                for vuln in vulns:
                    vuln["_queried_package"] = pkg_info
                    all_results.append(vuln)
    return all_results


# ---------------------------------------------------------------------------
# Finding conversion
# ---------------------------------------------------------------------------


def _osv_to_findings(vulns: list[dict[str, object]]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for vuln in vulns:
        vuln_id = str(vuln.get("id", ""))
        if not vuln_id or vuln_id in seen:
            continue
        seen.add(vuln_id)

        aliases = vuln.get("aliases", [])
        cve_id = None
        if isinstance(aliases, list):
            for alias in aliases:
                if isinstance(alias, str) and alias.startswith("CVE-"):
                    cve_id = alias
                    break
        if cve_id is None and vuln_id.startswith("CVE-"):
            cve_id = vuln_id

        cvss = _extract_cvss_score(vuln)
        severity = _cvss_to_severity(cvss)

        summary = str(vuln.get("summary", "")) or str(vuln.get("details", ""))
        if not summary:
            summary = f"Known vulnerability {vuln_id}"

        queried = vuln.get("_queried_package", {})
        pkg_name = ""
        pkg_version = ""
        if isinstance(queried, dict):
            pkg = queried.get("package", {})
            if isinstance(pkg, dict):
                pkg_name = str(pkg.get("name", ""))
            pkg_version = str(queried.get("version", ""))

        title = f"{vuln_id}: {pkg_name}" if pkg_name else vuln_id
        if pkg_version:
            title += f" ({pkg_version})"

        references: list[str] = []
        refs = vuln.get("references", [])
        if isinstance(refs, list):
            for ref in refs:
                if isinstance(ref, dict):
                    url = ref.get("url")
                    if isinstance(url, str):
                        references.append(url)

        db_specific = vuln.get("database_specific", {})
        cwe_id = None
        if isinstance(db_specific, dict):
            cwe_ids = db_specific.get("cwe_ids", [])
            if isinstance(cwe_ids, list) and cwe_ids:
                cwe_id = str(cwe_ids[0])

        findings.append(
            Finding(
                severity=severity,
                title=title,
                description=summary[:500],
                remediation=f"Update {pkg_name} to a patched version."
                if pkg_name
                else "Update the affected dependency to a patched version.",
                category="dependency-cve",
                scanner="cve",
                cwe=cwe_id,
                cve=cve_id,
                references=references[:5],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class CVEScanner(BaseRepoScanner):
    name = "cve"
    display_name = "Dependency CVE Scanner"
    description = "Detects known vulnerabilities in project dependencies via OSV.dev"

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(UTC)
        try:
            ecosystems = detect_ecosystems(repo_path)
            if not ecosystems:
                log.info("[cve] no supported manifest files found")
                return ScanResult(
                    target=repo_path,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                )

            all_findings: list[Finding] = []
            async with httpx.AsyncClient() as client:
                for ecosystem, packages in ecosystems.items():
                    log.info(
                        "[cve] querying OSV for %d %s packages",
                        len(packages),
                        ecosystem,
                    )
                    vulns = await _query_osv(client, ecosystem, packages)
                    all_findings.extend(_osv_to_findings(vulns))

            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                findings=all_findings,
            )
        except httpx.HTTPStatusError as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"OSV API error: HTTP {exc.response.status_code}",
            )
        except httpx.ConnectError:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error="Could not connect to OSV API (api.osv.dev)",
            )
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
