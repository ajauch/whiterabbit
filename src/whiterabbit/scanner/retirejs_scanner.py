"""JavaScript library vulnerability scanner using the retire.js vulnerability database (pure Python)."""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.scanner.base import BaseScanner

RETIREJS_DB_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"

DB_CACHE_DIR = Path.home() / ".whiterabbit" / "cache"
DB_CACHE_FILE = DB_CACHE_DIR / "jsrepository.json"
DB_MAX_AGE_SECONDS = 30 * 24 * 3600
DB_DOWNLOAD_TIMEOUT_SECONDS = 30

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
}

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)


def _cache_is_fresh() -> bool:
    if not DB_CACHE_FILE.exists():
        return False
    age = time.time() - DB_CACHE_FILE.stat().st_mtime
    return age < DB_MAX_AGE_SECONDS


async def _fetch_vuln_db() -> dict[str, Any]:
    if _cache_is_fresh():
        return json.loads(DB_CACHE_FILE.read_text(encoding="utf-8"))  # type: ignore[no-any-return]

    # Verify the database host's certificate independently of scan-target TLS.
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=DB_DOWNLOAD_TIMEOUT_SECONDS
        ) as client:
            response = await client.get(RETIREJS_DB_URL)
            response.raise_for_status()
            db = response.json()
    except httpx.TimeoutException as exc:
        raise RuntimeError(
            f"Download of the retire.js vulnerability database from {RETIREJS_DB_URL} "
            f"timed out after {DB_DOWNLOAD_TIMEOUT_SECONDS}s"
        ) from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Could not download the retire.js vulnerability database from {RETIREJS_DB_URL}: "
            f"{str(exc) or type(exc).__name__}"
        ) from exc

    DB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    DB_CACHE_FILE.write_text(json.dumps(db), encoding="utf-8")
    return db  # type: ignore[no-any-return]


def _extract_script_urls(html: str, base_url: str) -> list[str]:
    urls: list[str] = []
    for match in SCRIPT_SRC_RE.finditer(html):
        src = match.group(1)
        if src.startswith("data:") or src.startswith("javascript:"):
            continue
        absolute = urljoin(base_url, src)
        urls.append(absolute)
    return urls


def _extract_version_from_filename(
    filename: str, extractors: dict[str, Any]
) -> str | None:
    filename_patterns = extractors.get("filename")
    uri_patterns = extractors.get("uri")

    for pattern_source in [uri_patterns, filename_patterns]:
        if not pattern_source:
            continue
        patterns = (
            pattern_source if isinstance(pattern_source, list) else [pattern_source]
        )
        for pattern in patterns:
            try:
                m = re.search(pattern, filename)
                if m and m.lastindex and m.lastindex >= 1:
                    return m.group(1)
            except re.error:
                continue
    return None


def _extract_version_from_content(
    content: str, extractors: dict[str, Any]
) -> str | None:
    filecontent_patterns = extractors.get("filecontent")
    if not filecontent_patterns:
        return None
    patterns = (
        filecontent_patterns
        if isinstance(filecontent_patterns, list)
        else [filecontent_patterns]
    )
    for pattern in patterns:
        try:
            m = re.search(pattern, content)
            if m and m.lastindex and m.lastindex >= 1:
                return m.group(1)
        except re.error:
            continue
    return None


def _check_hash(content: str, hashes: dict[str, str]) -> str | None:
    if not hashes:
        return None
    # not cryptographic; matching RetireJS DB lookup keys
    sha1 = hashlib.sha1(content.encode()).hexdigest()  # nosec B324 # nosemgrep
    return hashes.get(sha1)


def _version_in_range(
    version: str,
    below: str | None = None,
    above: str | None = None,
    at_or_above: str | None = None,
) -> bool:
    def parse_ver(v: str) -> tuple[int, ...]:
        parts: list[int] = []
        for p in v.split("."):
            try:
                parts.append(int(re.match(r"\d+", p).group()))  # type: ignore[union-attr]
            except (AttributeError, ValueError):
                parts.append(0)
        return tuple(parts)

    try:
        ver = parse_ver(version)
    except Exception:
        return False

    if at_or_above:
        try:
            lower = parse_ver(at_or_above)
            if ver < lower:
                return False
        except Exception:
            pass

    if above:
        try:
            lower = parse_ver(above)
            if ver <= lower:
                return False
        except Exception:
            pass

    if below:
        try:
            upper = parse_ver(below)
            if ver >= upper:
                return False
        except Exception:
            pass

    return True


def _check_vulnerabilities(
    library: str, version: str, vuln_list: list[dict[str, Any]]
) -> list[Finding]:
    findings: list[Finding] = []
    for vuln in vuln_list:
        below = vuln.get("below")
        above = vuln.get("above")
        at_or_above = vuln.get("atOrAbove")

        if not _version_in_range(
            version, below=below, above=above, at_or_above=at_or_above
        ):
            continue

        severity_str = vuln.get("severity", "medium").lower()
        severity = SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        identifiers = vuln.get("identifiers", {})
        cve_list = identifiers.get("CVE", [])
        cve = cve_list[0] if cve_list else None

        info = vuln.get("info", [])
        summary = identifiers.get(
            "summary", vuln.get("info", f"Known vulnerability in {library} {version}")
        )
        if isinstance(summary, list):
            summary = (
                summary[0] if summary else f"Known vulnerability in {library} {version}"
            )

        findings.append(
            Finding(
                severity=severity,
                title=f"{library} {version} has known vulnerability"
                + (f" ({cve})" if cve else ""),
                description=f"{library} version {version} has a known vulnerability: {summary}",
                remediation=f"Upgrade {library} to the latest version (requires at least {below})."
                if below
                else f"Upgrade {library} to the latest version.",
                category="js-vuln",
                scanner="retirejs",
                cve=cve,
                references=info if isinstance(info, list) else [info],
            )
        )

    return findings


class RetireJSScanner(BaseScanner):
    name = "retirejs"
    display_name = "JavaScript Library Scanner"
    description = "Detects known-vulnerable JavaScript libraries (retire.js database)"

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        url = f"https://{target}" if "://" not in target else target
        started = datetime.now(UTC)
        findings: list[Finding] = []

        try:
            vuln_db = await _fetch_vuln_db()

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(config.timeout),
                verify=False,  # nosec B501 — scanner must connect to TLS-misconfigured targets
            ) as client:
                response = await client.get(url)
                html = response.text
                script_urls = _extract_script_urls(html, str(response.url))

                for script_url in script_urls:
                    for lib_name, lib_data in vuln_db.items():
                        if not isinstance(lib_data, dict):
                            continue
                        extractors = lib_data.get("extractors", {})
                        vulnerabilities = lib_data.get("vulnerabilities", [])
                        if not vulnerabilities:
                            continue

                        version = _extract_version_from_filename(script_url, extractors)
                        if version:
                            findings.extend(
                                _check_vulnerabilities(
                                    lib_name, version, vulnerabilities
                                )
                            )
                            continue

                        hashes = extractors.get("hashes", {})
                        if hashes:
                            try:
                                js_resp = await client.get(script_url)
                                js_content = js_resp.text
                                hash_version = _check_hash(js_content, hashes)
                                if hash_version:
                                    findings.extend(
                                        _check_vulnerabilities(
                                            lib_name, hash_version, vulnerabilities
                                        )
                                    )
                                    continue
                            except Exception:
                                continue

                for lib_name, lib_data in vuln_db.items():
                    if not isinstance(lib_data, dict):
                        continue
                    extractors = lib_data.get("extractors", {})
                    vulnerabilities = lib_data.get("vulnerabilities", [])
                    if not vulnerabilities:
                        continue

                    version = _extract_version_from_content(html, extractors)
                    if version:
                        findings.extend(
                            _check_vulnerabilities(lib_name, version, vulnerabilities)
                        )

                seen: set[str] = set()
                deduped: list[Finding] = []
                for f in findings:
                    key = f"{f.title}|{f.cve}"
                    if key not in seen:
                        seen.add(key)
                        deduped.append(f)
                findings = deduped

                if _cache_is_fresh():
                    age_days = (time.time() - DB_CACHE_FILE.stat().st_mtime) / 86400
                    if age_days > 25:
                        findings.append(
                            Finding(
                                severity=Severity.INFO,
                                title=f"Vulnerability database is {int(age_days)} days old",
                                description="The retire.js vulnerability database may be outdated. Re-run the scan to refresh.",
                                remediation="Delete the cache at ~/.whiterabbit/cache/jsrepository.json to force a refresh.",
                                category="js-vuln",
                                scanner="retirejs",
                            )
                        )

        except httpx.TimeoutException:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Request timed out after {config.timeout}s",
            )
        except httpx.ConnectError:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Could not connect to {target}",
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc) or f"{type(exc).__name__} (no details)",
            )

        return ScanResult(
            target=target,
            scanner_name=self.name,
            started_at=started,
            finished_at=datetime.now(UTC),
            findings=findings,
        )
