"""Slopsquat scanner — detects hallucinated and slopsquatted packages."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.repo_scanner.manifest import extract_package_names
from whiterabbit.report.models import Finding, ScanResult, Severity

log = logging.getLogger("whiterabbit")

PYPI_URL = "https://pypi.org/pypi/{package}/json"
NPM_URL = "https://registry.npmjs.org/{package}"
PYPI_DOWNLOADS_URL = "https://pypistats.org/api/packages/{package}/recent"
NPM_DOWNLOADS_URL = "https://api.npmjs.org/downloads/point/last-month/{package}"
CONCURRENT_CHECKS = 10

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PackageMetadata:
    name: str
    exists: bool | None = None
    created: datetime | None = None
    description: str = ""
    has_author: bool = False
    has_source_repo: bool = False
    has_license: bool = False
    release_count: int = 0
    has_classifiers: bool = False
    monthly_downloads: int | None = None


@dataclass
class ThreatSignal:
    name: str
    points: int
    detail: str


# ---------------------------------------------------------------------------
# Threat scoring
# ---------------------------------------------------------------------------

SCORE_NO_DESCRIPTION = 15
SCORE_NO_AUTHOR = 10
SCORE_NO_SOURCE_REPO = 15
SCORE_NO_LICENSE = 5
SCORE_SINGLE_RELEASE = 10
SCORE_FEW_RELEASES = 5
SCORE_VERY_RECENT = 15
SCORE_RECENT = 10
SCORE_VERY_LOW_DOWNLOADS = 25
SCORE_LOW_DOWNLOADS = 20
SCORE_NO_CLASSIFIERS = 5

THREAT_CRITICAL = 65
THREAT_HIGH = 45
THREAT_MEDIUM = 25
THREAT_MIN = 15


def _score_package(meta: PackageMetadata) -> tuple[int, list[ThreatSignal]]:
    signals: list[ThreatSignal] = []

    if not meta.description or len(meta.description.strip()) < 10:
        signals.append(
            ThreatSignal(
                "no_description", SCORE_NO_DESCRIPTION, "No meaningful description"
            )
        )

    if not meta.has_author:
        signals.append(
            ThreatSignal("no_author", SCORE_NO_AUTHOR, "No author or maintainer info")
        )

    if not meta.has_source_repo:
        signals.append(
            ThreatSignal(
                "no_source_repo", SCORE_NO_SOURCE_REPO, "No source repository URL"
            )
        )

    if not meta.has_license:
        signals.append(
            ThreatSignal("no_license", SCORE_NO_LICENSE, "No license specified")
        )

    if meta.release_count == 1:
        signals.append(
            ThreatSignal("single_release", SCORE_SINGLE_RELEASE, "Only 1 release")
        )
    elif 2 <= meta.release_count <= 3:
        signals.append(
            ThreatSignal(
                "few_releases",
                SCORE_FEW_RELEASES,
                f"Only {meta.release_count} releases",
            )
        )

    if meta.created is not None:
        age = datetime.now(UTC) - meta.created
        if age < timedelta(days=30):
            signals.append(
                ThreatSignal(
                    "very_recent", SCORE_VERY_RECENT, f"Created {age.days} days ago"
                )
            )
        elif age < timedelta(days=180):
            signals.append(
                ThreatSignal("recent", SCORE_RECENT, f"Created {age.days} days ago")
            )

    if meta.monthly_downloads is not None:
        if meta.monthly_downloads < 10:
            signals.append(
                ThreatSignal(
                    "very_low_downloads",
                    SCORE_VERY_LOW_DOWNLOADS,
                    f"{meta.monthly_downloads} downloads/month",
                )
            )
        elif meta.monthly_downloads < 100:
            signals.append(
                ThreatSignal(
                    "low_downloads",
                    SCORE_LOW_DOWNLOADS,
                    f"{meta.monthly_downloads} downloads/month",
                )
            )

    if not meta.has_classifiers:
        signals.append(
            ThreatSignal(
                "no_classifiers", SCORE_NO_CLASSIFIERS, "No classifiers/categories"
            )
        )

    return sum(s.points for s in signals), signals


def _score_to_severity(score: int) -> Severity:
    if score >= THREAT_CRITICAL:
        return Severity.CRITICAL
    if score >= THREAT_HIGH:
        return Severity.HIGH
    if score >= THREAT_MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# PyPI helpers
# ---------------------------------------------------------------------------


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


def _extract_pypi_metadata(name: str, data: dict[str, Any]) -> PackageMetadata:
    info = data.get("info", {})
    releases = data.get("releases", {})

    description = info.get("description", "") or info.get("summary", "") or ""

    author = (
        info.get("author")
        or info.get("author_email")
        or info.get("maintainer")
        or info.get("maintainer_email")
        or ""
    )

    project_urls = info.get("project_urls") or {}
    home_page = info.get("home_page") or ""

    license_val = info.get("license") or info.get("license_expression") or ""

    return PackageMetadata(
        name=name,
        exists=True,
        created=_extract_pypi_created(data),
        description=description,
        has_author=bool(author.strip()),
        has_source_repo=bool(project_urls) or bool(home_page.strip()),
        has_license=bool(license_val.strip()),
        release_count=len(releases),
        has_classifiers=bool(info.get("classifiers")),
    )


# ---------------------------------------------------------------------------
# npm helpers
# ---------------------------------------------------------------------------


def _extract_npm_created(data: dict[str, Any]) -> datetime | None:
    try:
        time_info = data.get("time", {})
        created_str = time_info.get("created")
        if created_str:
            return datetime.fromisoformat(created_str.replace("Z", "+00:00"))
    except Exception:  # nosec B110 — best-effort date parse; None means "age unknown"
        pass
    return None


def _extract_npm_metadata(name: str, data: dict[str, Any]) -> PackageMetadata:
    maintainers = data.get("maintainers", [])
    repo = data.get("repository")
    homepage = data.get("homepage", "") or ""
    readme = data.get("readme", "") or ""

    return PackageMetadata(
        name=name,
        exists=True,
        created=_extract_npm_created(data),
        description=data.get("description", "") or "",
        has_author=len(maintainers) > 0,
        has_source_repo=bool(repo) or bool(homepage.strip()),
        has_license=bool(data.get("license")),
        release_count=len(data.get("versions", {})),
        has_classifiers=len(readme) > 100,
    )


# ---------------------------------------------------------------------------
# Download-count fetchers
# ---------------------------------------------------------------------------


async def _fetch_pypi_downloads(client: httpx.AsyncClient, name: str) -> int | None:
    try:
        resp = await client.get(
            PYPI_DOWNLOADS_URL.format(package=name),
            timeout=10,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        return resp.json().get("data", {}).get("last_month")  # type: ignore[no-any-return]
    except Exception:
        return None


async def _fetch_npm_downloads(client: httpx.AsyncClient, name: str) -> int | None:
    try:
        resp = await client.get(
            NPM_DOWNLOADS_URL.format(package=name),
            timeout=10,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            return None
        return resp.json().get("downloads")  # type: ignore[no-any-return]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Registry checkers
# ---------------------------------------------------------------------------


async def _check_pypi(client: httpx.AsyncClient, name: str) -> PackageMetadata:
    url = PYPI_URL.format(package=name)
    try:
        resp = await client.get(url, timeout=10, follow_redirects=True)
        if resp.status_code == 404:
            return PackageMetadata(name=name, exists=False)
        resp.raise_for_status()
        data = resp.json()
        meta = _extract_pypi_metadata(name, data)
        meta.monthly_downloads = await _fetch_pypi_downloads(client, name)
        return meta
    except Exception:
        log.warning(
            "[slopsquat] network error checking PyPI for %s, assuming exists", name
        )
        return PackageMetadata(name=name, exists=None)


async def _check_npm(client: httpx.AsyncClient, name: str) -> PackageMetadata:
    encoded = name.replace("/", "%2F") if name.startswith("@") else name
    url = NPM_URL.format(package=encoded)
    try:
        resp = await client.get(url, timeout=10, follow_redirects=True)
        if resp.status_code == 404:
            return PackageMetadata(name=name, exists=False)
        resp.raise_for_status()
        data = resp.json()
        meta = _extract_npm_metadata(name, data)
        meta.monthly_downloads = await _fetch_npm_downloads(client, name)
        return meta
    except Exception:
        log.warning(
            "[slopsquat] network error checking npm for %s, assuming exists", name
        )
        return PackageMetadata(name=name, exists=None)


async def _check_packages(
    client: httpx.AsyncClient,
    ecosystem: str,
    names: set[str],
) -> list[PackageMetadata]:
    sem = asyncio.Semaphore(CONCURRENT_CHECKS)
    checker = _check_pypi if ecosystem == "PyPI" else _check_npm

    async def _check_one(name: str) -> PackageMetadata:
        async with sem:
            return await checker(client, name)

    return list(await asyncio.gather(*[_check_one(n) for n in sorted(names)]))


# ---------------------------------------------------------------------------
# Finding conversion
# ---------------------------------------------------------------------------


def _metadata_to_findings(
    metadata_list: list[PackageMetadata],
    ecosystem: str,
) -> list[Finding]:
    findings: list[Finding] = []

    for meta in metadata_list:
        if meta.exists is None:
            continue

        if meta.exists is False:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"Non-existent package: {meta.name} ({ecosystem})",
                    description=(
                        f"The package '{meta.name}' does not exist on "
                        f"{ecosystem}. This may be an AI-hallucinated dependency "
                        f"name. An attacker could register this package name and "
                        f"execute arbitrary code when dependencies are installed "
                        f"(slopsquatting attack)."
                    ),
                    remediation=(
                        f"Remove '{meta.name}' from your dependency manifest "
                        f"or replace it with a verified, real package that "
                        f"provides the needed functionality."
                    ),
                    category="hallucinated-dependency",
                    scanner="slopsquat",
                    cwe="CWE-829",
                    raw={
                        "package": meta.name,
                        "ecosystem": ecosystem,
                        "registry_status": 404,
                        "threat_score": 0,
                        "threat_signals": [],
                    },
                )
            )
            continue

        score, signals = _score_package(meta)
        if score < THREAT_MIN:
            continue

        severity = _score_to_severity(score)
        signal_details = "; ".join(f"{s.detail} (+{s.points})" for s in signals)

        findings.append(
            Finding(
                severity=severity,
                title=(
                    f"Suspicious package: {meta.name} ({ecosystem}) "
                    f"— threat score {score}"
                ),
                description=(
                    f"The package '{meta.name}' on {ecosystem} has a "
                    f"slopsquatting threat score of {score}. This package "
                    f"exists but shows signs of being a squatted package "
                    f"name that may have been AI-hallucinated. "
                    f"Signals: {signal_details}."
                ),
                remediation=(
                    f"Verify that '{meta.name}' is a legitimate package by "
                    f"checking its source repository, maintainer identity, "
                    f"download history, and comparing against known "
                    f"alternatives. If it cannot be verified, remove it "
                    f"and use a known-good package."
                ),
                category="slopsquatted-dependency",
                scanner="slopsquat",
                cwe="CWE-829",
                raw={
                    "package": meta.name,
                    "ecosystem": ecosystem,
                    "registry_status": 200,
                    "threat_score": score,
                    "threat_signals": [
                        {"name": s.name, "points": s.points, "detail": s.detail}
                        for s in signals
                    ],
                    "created": meta.created.isoformat() if meta.created else None,
                    "monthly_downloads": meta.monthly_downloads,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SlopsquatScanner(BaseRepoScanner):
    name = "slopsquat"
    display_name = "Slopsquat Scanner"
    description = (
        "Detects hallucinated or slopsquatted packages in dependency manifests"
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
                    metadata = await _check_packages(client, ecosystem, names)
                    all_findings.extend(_metadata_to_findings(metadata, ecosystem))

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
