"""Dependency CVE scanner — parses manifests and queries the OSV.dev API."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity

log = logging.getLogger("whiterabbit")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 1000


# ---------------------------------------------------------------------------
# Manifest parsers — each returns (package_name, version) pairs
# ---------------------------------------------------------------------------


def _parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
        if match:
            deps.append((match.group(1), match.group(2)))
    return deps


def _parse_pyproject_toml(path: Path) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped in ("dependencies = [", "dependencies= ["):
            in_deps = True
            continue
        if re.match(r"^\[?(dependencies)\]?\s*=\s*\[", stripped):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            match = re.match(
                r"""["']([A-Za-z0-9_.-]+)\s*([><=!~]+\s*[^"',]+)?["']""", stripped
            )
            if match:
                name = match.group(1)
                version_spec = (match.group(2) or "").strip()
                pinned = re.match(r"==\s*(.+)", version_spec)
                if pinned:
                    deps.append((name, pinned.group(1).strip()))
    return deps


def _parse_package_json(path: Path) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean = re.sub(r"^[~^>=<]*", "", version).strip()
            if clean:
                deps.append((name, clean))
    return deps


def _parse_package_lock_json(path: Path) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return deps
    packages = data.get("packages", {})
    if packages:
        for key, info in packages.items():
            if not key:
                continue
            name = key.split("node_modules/")[-1]
            version = info.get("version", "")
            if name and version:
                deps.append((name, version))
    else:
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if version:
                deps.append((name, version))
    return deps


MANIFEST_PARSERS: dict[str, tuple[str, object]] = {
    "requirements.txt": ("PyPI", _parse_requirements_txt),
    "pyproject.toml": ("PyPI", _parse_pyproject_toml),
    "package.json": ("npm", _parse_package_json),
    "package-lock.json": ("npm", _parse_package_lock_json),
}


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------


_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", ".tox"}


def _detect_ecosystems(repo_path: str) -> dict[str, list[tuple[str, str]]]:
    """Recursively find known manifests and parse them."""
    import os

    results: dict[str, list[tuple[str, str]]] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            if filename not in MANIFEST_PARSERS:
                continue
            ecosystem, parser = MANIFEST_PARSERS[filename]
            manifest = Path(dirpath) / filename
            parsed = parser(manifest)  # type: ignore[operator]
            if parsed:
                results.setdefault(ecosystem, []).extend(parsed)
    return results


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
        elif isinstance(score, (int, float)):
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
            ecosystems = _detect_ecosystems(repo_path)
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
