"""Slopsquat scanner — detects hallucinated packages in dependency manifests."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

import httpx

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.repo_scanner.manifest import extract_package_names
from whiterabbit.report.models import Finding, ScanResult, Severity

log = logging.getLogger("whiterabbit")

PYPI_URL = "https://pypi.org/pypi/{package}/json"
NPM_URL = "https://registry.npmjs.org/{package}"
CONCURRENT_CHECKS = 10
SUSPICIOUS_AGE_DAYS = 7


class PackageStatus(NamedTuple):
    name: str
    exists: bool | None  # None = network error (fail-open)
    created: datetime | None = None


async def _check_pypi(client: httpx.AsyncClient, name: str) -> PackageStatus:
    url = PYPI_URL.format(package=name)
    try:
        resp = await client.get(url, timeout=10, follow_redirects=True)
        if resp.status_code == 404:
            return PackageStatus(name=name, exists=False)
        resp.raise_for_status()
        data = resp.json()
        created = _extract_pypi_created(data)
        return PackageStatus(name=name, exists=True, created=created)
    except Exception:
        log.warning(
            "[slopsquat] network error checking PyPI for %s, assuming exists", name
        )
        return PackageStatus(name=name, exists=None)


async def _check_npm(client: httpx.AsyncClient, name: str) -> PackageStatus:
    encoded = name.replace("/", "%2F") if name.startswith("@") else name
    url = NPM_URL.format(package=encoded)
    try:
        resp = await client.get(url, timeout=10, follow_redirects=True)
        if resp.status_code == 404:
            return PackageStatus(name=name, exists=False)
        resp.raise_for_status()
        data = resp.json()
        created = _extract_npm_created(data)
        return PackageStatus(name=name, exists=True, created=created)
    except Exception:
        log.warning(
            "[slopsquat] network error checking npm for %s, assuming exists", name
        )
        return PackageStatus(name=name, exists=None)


def _extract_pypi_created(data: dict[str, Any]) -> datetime | None:
    try:
        releases = data.get("releases", {})
        earliest = None
        for version_files in releases.values():
            for file_info in version_files:
                upload_time = file_info.get("upload_time_iso_8601")
                if upload_time:
                    dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                    if earliest is None or dt < earliest:
                        earliest = dt
        return earliest
    except Exception:
        return None


def _extract_npm_created(data: dict[str, Any]) -> datetime | None:
    try:
        time_info = data.get("time", {})
        created_str = time_info.get("created")
        if created_str:
            return datetime.fromisoformat(created_str.replace("Z", "+00:00"))
    except Exception:  # nosec B110 — best-effort date parse; None means "age unknown"
        pass
    return None


async def _check_packages(
    client: httpx.AsyncClient,
    ecosystem: str,
    names: set[str],
) -> list[PackageStatus]:
    sem = asyncio.Semaphore(CONCURRENT_CHECKS)
    checker = _check_pypi if ecosystem == "PyPI" else _check_npm

    async def _check_one(name: str) -> PackageStatus:
        async with sem:
            return await checker(client, name)

    return list(await asyncio.gather(*[_check_one(n) for n in sorted(names)]))


def _statuses_to_findings(
    statuses: list[PackageStatus],
    ecosystem: str,
) -> list[Finding]:
    findings: list[Finding] = []
    now = datetime.now(UTC)

    for status in statuses:
        if status.exists is False:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"Hallucinated package: {status.name} ({ecosystem})",
                    description=(
                        f"The package '{status.name}' does not exist on "
                        f"{ecosystem}. This may be an AI-hallucinated dependency "
                        f"name. An attacker could register this package name and "
                        f"execute arbitrary code when dependencies are installed "
                        f"(slopsquatting attack)."
                    ),
                    remediation=(
                        f"Remove '{status.name}' from your dependency manifest "
                        f"or replace it with a verified, real package that "
                        f"provides the needed functionality."
                    ),
                    category="hallucinated-dependency",
                    scanner="slopsquat",
                    cwe="CWE-829",
                    raw={
                        "package": status.name,
                        "ecosystem": ecosystem,
                        "registry_status": 404,
                    },
                )
            )
        elif status.exists is True and status.created is not None:
            age = now - status.created
            if age < timedelta(days=SUSPICIOUS_AGE_DAYS):
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        title=f"Recently created package: {status.name} ({ecosystem})",
                        description=(
                            f"The package '{status.name}' was created on "
                            f"{status.created.strftime('%Y-%m-%d')}, which is less "
                            f"than {SUSPICIOUS_AGE_DAYS} days ago. Recently created "
                            f"packages that match dependency names could indicate "
                            f"a slopsquatting attack where someone registered a "
                            f"hallucinated package name."
                        ),
                        remediation=(
                            f"Verify that '{status.name}' is a legitimate package "
                            f"by checking its source repository, maintainer "
                            f"identity, and download history."
                        ),
                        category="hallucinated-dependency",
                        scanner="slopsquat",
                        cwe="CWE-829",
                        raw={
                            "package": status.name,
                            "ecosystem": ecosystem,
                            "created": status.created.isoformat(),
                            "registry_status": 200,
                        },
                    )
                )

    return findings


class SlopsquatScanner(BaseRepoScanner):
    name = "slopsquat"
    display_name = "Slopsquat Scanner"
    description = (
        "Detects hallucinated or non-existent packages in dependency manifests"
    )

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(UTC)
        try:
            ecosystems = extract_package_names(repo_path)
            if not ecosystems:
                log.info("[slopsquat] no dependency manifests found")
                return ScanResult(
                    target=repo_path,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                )

            all_findings: list[Finding] = []
            async with httpx.AsyncClient() as client:
                for ecosystem, names in ecosystems.items():
                    log.info(
                        "[slopsquat] checking %d %s packages against registry",
                        len(names),
                        ecosystem,
                    )
                    statuses = await _check_packages(client, ecosystem, names)
                    all_findings.extend(_statuses_to_findings(statuses, ecosystem))

            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                findings=all_findings,
            )
        except httpx.ConnectError:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error="Could not connect to package registry",
            )
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
