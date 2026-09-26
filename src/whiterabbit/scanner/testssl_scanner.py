"""Deep TLS analysis scanner powered by testssl.sh."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from typing import Any

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.scanner.base import BaseScanner

SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.MEDIUM,
    "INFO": Severity.INFO,
    "OK": Severity.INFO,
}

VULN_FINDINGS: dict[str, dict[str, Any]] = {
    "BEAST": {
        "title": "Server vulnerable to BEAST (CBC in TLS 1.0)",
        "severity": Severity.HIGH,
        "description": "The server is vulnerable to the BEAST attack, which exploits CBC ciphers in TLS 1.0.",
        "remediation": "Disable TLS 1.0 or prioritize RC4 ciphers (less ideal). Best fix: use TLS 1.2+ only. For Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
        "cve": "CVE-2011-3389",
        "cwe": "CWE-326",
    },
    "POODLE": {
        "title": "Server vulnerable to POODLE on TLS",
        "severity": Severity.HIGH,
        "description": "The server is vulnerable to the POODLE attack on TLS (not just SSL 3.0).",
        "remediation": "Disable SSLv3 and TLS 1.0. Use TLS 1.2+ only. For Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
        "cve": "CVE-2014-8730",
        "cwe": "CWE-310",
    },
    "Lucky13": {
        "title": "Server may be vulnerable to Lucky13 timing attack",
        "severity": Severity.MEDIUM,
        "description": "The server may be susceptible to the Lucky13 timing side-channel attack on CBC ciphers.",
        "remediation": "Use AEAD cipher suites (GCM or ChaCha20-Poly1305) and disable CBC ciphers.",
        "cve": "CVE-2013-0169",
        "cwe": "CWE-310",
    },
    "DROWN": {
        "title": "Server vulnerable to DROWN (SSLv2 cross-protocol)",
        "severity": Severity.CRITICAL,
        "description": "The server is vulnerable to DROWN, allowing SSLv2 to be used to attack TLS connections.",
        "remediation": "Disable SSLv2 on all servers that share the same RSA key. For Nginx: remove `SSLv2` from `ssl_protocols`.",
        "cve": "CVE-2016-0800",
        "cwe": "CWE-326",
    },
    "FREAK": {
        "title": "Server vulnerable to FREAK (export cipher downgrade)",
        "severity": Severity.HIGH,
        "description": "The server supports export-grade cipher suites, enabling the FREAK factoring attack.",
        "remediation": "Disable all EXPORT cipher suites. For Nginx: remove export ciphers from `ssl_ciphers`.",
        "cve": "CVE-2015-0204",
        "cwe": "CWE-326",
    },
    "Logjam": {
        "title": "Server vulnerable to Logjam (weak DH parameters)",
        "severity": Severity.HIGH,
        "description": "The server uses weak Diffie-Hellman parameters (< 2048 bits), enabling the Logjam attack.",
        "remediation": "Generate DH parameters of at least 2048 bits: `openssl dhparam -out dhparams.pem 2048`. For Nginx: `ssl_dhparam dhparams.pem;`",
        "cve": "CVE-2015-4000",
        "cwe": "CWE-326",
    },
    "SWEET32": {
        "title": "Server vulnerable to SWEET32 (64-bit block ciphers)",
        "severity": Severity.MEDIUM,
        "description": "The server supports 64-bit block ciphers (3DES), vulnerable to the SWEET32 birthday attack.",
        "remediation": "Disable 3DES and other 64-bit block cipher suites. Use AES-GCM or ChaCha20.",
        "cve": "CVE-2016-2183",
        "cwe": "CWE-326",
    },
    "Ticketbleed": {
        "title": "Server vulnerable to Ticketbleed",
        "severity": Severity.HIGH,
        "description": "The server is vulnerable to Ticketbleed, which leaks session ticket memory.",
        "remediation": "Update your TLS stack (F5 BIG-IP: upgrade to a patched version).",
        "cve": "CVE-2016-9244",
        "cwe": "CWE-200",
    },
}

SSL_SCANNER_TITLES = frozenset(
    {
        "SSLv2",
        "SSLv3",
        "TLS 1.0",
        "TLS 1.1",
        "TLS 1.3",
        "Heartbleed",
        "ROBOT",
        "compression",
        "expired",
        "self-signed",
        "hostname mismatch",
        "weak cipher",
        "OCSP",
        "certificate chain",
        "RSA key",
    }
)


def _is_duplicate_of_ssl_scanner(finding_id: str, finding_text: str) -> bool:
    text_lower = finding_text.lower()
    id_lower = finding_id.lower()
    if "heartbleed" in id_lower or "heartbleed" in text_lower:
        return True
    if "robot" in id_lower and "robot" in text_lower:
        return True
    if id_lower in ("sslv2", "sslv3") or "sslv2" in text_lower or "sslv3" in text_lower:
        return True
    if "cert_expired" in id_lower or "cert_selfsigned" in id_lower:
        return True
    return "cert_chain" in id_lower


_NOISE_PATTERNS = [
    "--fast",
    "engine",
    "GOST",
    "openssl",
    "No engine",
]


def _is_noise(finding_id: str, finding_text: str) -> bool:
    if finding_id.startswith("scanProblem") or finding_id.startswith("info"):
        return True
    text_lower = finding_text.lower()
    for pat in _NOISE_PATTERNS:
        if pat.lower() in text_lower and "vulnerab" not in text_lower:
            return True
    return False


def _parse_testssl_finding(entry: dict[str, Any]) -> Finding | None:
    finding_id = entry.get("id", "")
    finding_text = entry.get("finding", "")
    severity_str = entry.get("severity", "INFO").upper()

    if severity_str in ("OK", "INFO"):
        return None

    if _is_duplicate_of_ssl_scanner(finding_id, finding_text):
        return None

    if _is_noise(finding_id, finding_text):
        return None

    if finding_id in VULN_FINDINGS:
        vuln = VULN_FINDINGS[finding_id]
        return Finding(
            severity=vuln["severity"],
            title=vuln["title"],
            description=vuln["description"],
            remediation=vuln["remediation"],
            category="ssl",
            scanner="testssl",
            cve=vuln.get("cve"),
            cwe=vuln.get("cwe"),
        )

    severity = SEVERITY_MAP.get(severity_str, Severity.INFO)
    if severity == Severity.INFO:
        return None

    cve = entry.get("cve") or entry.get("CVE")

    return Finding(
        severity=severity,
        title=finding_text[:120] if finding_text else f"testssl finding: {finding_id}",
        description=finding_text,
        remediation="Review the TLS configuration and apply recommended security settings for your server.",
        category="ssl",
        scanner="testssl",
        cve=cve,
    )


_WINDOWS_TESTSSL_PATH = os.environ.get(
    "WHITERABBIT_TESTSSL_PATH", "C:/Tools/testssl/testssl.sh"
)

_GIT_BASH_LOCATIONS = [
    r"C:\Program Files\Git\bin\bash.exe",
    r"C:\Program Files (x86)\Git\bin\bash.exe",
]


def _find_git_bash() -> str | None:
    path = shutil.which("bash")
    if path:
        return path
    for loc in _GIT_BASH_LOCATIONS:
        if os.path.isfile(loc):
            return loc
    return None


def _find_testssl() -> str | None:
    direct = shutil.which("testssl.sh")
    if direct:
        return direct
    if sys.platform == "win32" and os.path.isfile(_WINDOWS_TESTSSL_PATH):
        return _WINDOWS_TESTSSL_PATH
    return None


class TestSSLScanner(BaseScanner):
    name = "testssl"
    display_name = "Deep TLS Scanner"
    description = "Deep TLS/SSL analysis using testssl.sh (complements SSLyze)"
    min_timeout: int | None = 900
    slow: bool = True

    def is_available(self) -> bool:
        if _find_testssl() is None:
            return False
        if sys.platform == "win32" and not shutil.which("testssl.sh"):
            return _find_git_bash() is not None
        return True

    def check_dependencies(self) -> list[str]:
        missing: list[str] = []
        if _find_testssl() is None:
            missing.append(
                "  'testssl.sh' not found on PATH (or set WHITERABBIT_TESTSSL_PATH)"
            )
        elif (
            sys.platform == "win32"
            and not shutil.which("testssl.sh")
            and not _find_git_bash()
        ):
            missing.append("  Git Bash required to run testssl.sh on Windows")
        return missing

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        url = f"https://{target}" if "://" not in target else target
        started = datetime.now(UTC)
        findings: list[Finding] = []

        testssl_path = _find_testssl()
        if not testssl_path:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error="testssl.sh not found. Install: https://github.com/drwetter/testssl.sh#install",
            )

        fd, json_tmpfile = tempfile.mkstemp(suffix=".json", prefix="testssl_")
        os.close(fd)

        use_git_bash = sys.platform == "win32" and not shutil.which("testssl.sh")

        if use_git_bash:
            bash = _find_git_bash()
            if not bash:
                with contextlib.suppress(OSError):
                    os.unlink(json_tmpfile)
                return ScanResult(
                    target=target,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                    error="Git Bash required to run testssl.sh on Windows",
                )
            script_posix = testssl_path.replace("\\", "/")
            if len(script_posix) >= 2 and script_posix[1] == ":":
                script_posix = "/" + script_posix[0].lower() + script_posix[2:]
            testssl_dir = script_posix.rsplit("/", 1)[0]
            json_tmpfile_posix = json_tmpfile.replace("\\", "/")
            if len(json_tmpfile_posix) >= 2 and json_tmpfile_posix[1] == ":":
                json_tmpfile_posix = (
                    "/" + json_tmpfile_posix[0].lower() + json_tmpfile_posix[2:]
                )
            cmd: list[str] = [
                bash,
                "-c",
                f"export PATH='{testssl_dir}':$PATH; '{script_posix}' --jsonfile '{json_tmpfile_posix}' -U --quiet --color 0 --fast --warnings off '{url}'",
            ]
        else:
            cmd = [
                testssl_path,
                "--jsonfile",
                json_tmpfile,
                "-U",
                "--quiet",
                "--color",
                "0",
                "--fast",
                "--warnings",
                "off",
                url,
            ]

        testssl_timeout = self.effective_timeout(config) + 30
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=testssl_timeout,
            )

            try:
                with open(json_tmpfile, encoding="utf-8", errors="replace") as f:
                    output = f.read().strip()
            except FileNotFoundError:
                output = ""

            if not output and proc.returncode not in (0, 1):
                error_msg = stderr.decode(errors="replace").strip()
                return ScanResult(
                    target=target,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                    error=f"testssl.sh exited with code {proc.returncode}: {error_msg}",
                )

            try:
                entries = json.loads(output)
            except json.JSONDecodeError:
                entries = []
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:  # nosec B112
                        continue

            if not isinstance(entries, list):
                entries = [entries]

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                finding = _parse_testssl_finding(entry)
                if finding:
                    findings.append(finding)

        except FileNotFoundError:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error="testssl.sh not found. Install: https://github.com/drwetter/testssl.sh#install",
            )
        except TimeoutError:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"testssl.sh timed out after {testssl_timeout}s",
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
        finally:
            with contextlib.suppress(OSError):
                os.unlink(json_tmpfile)

        return ScanResult(
            target=target,
            scanner_name=self.name,
            started_at=started,
            finished_at=datetime.now(UTC),
            findings=findings,
        )
