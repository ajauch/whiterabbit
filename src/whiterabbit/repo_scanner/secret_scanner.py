"""Secret scanner — detects committed credentials using TruffleHog."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlparse

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.resolve import resolve_binary, subprocess_env

log = logging.getLogger("whiterabbit")

# ---------------------------------------------------------------------------
# Layer 1: binary / non-source extensions excluded before TruffleHog runs
# ---------------------------------------------------------------------------

_BINARY_EXTENSIONS = {
    ".wasm",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".jar",
    ".war",
    ".ear",
    ".so",
    ".dll",
    ".dylib",
    ".pyc",
    ".pyo",
    ".exe",
    ".bin",
    ".o",
    ".a",
    ".lib",
    ".class",
    ".obj",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp3",
    ".mp4",
    ".wav",
    ".ogg",
    ".webm",
    ".avi",
    ".mov",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
}

# ---------------------------------------------------------------------------
# Layer 2: post-parse context filters
# ---------------------------------------------------------------------------

_TEST_DIR_SEGMENTS = {
    "test",
    "tests",
    "__tests__",
    "__test__",
    "spec",
    "specs",
    "fixtures",
    "fixture",
    "mocks",
    "mock",
    "__mocks__",
    "testdata",
    "test_data",
    "testutils",
    "testing",
}

_KNOWN_PUBLIC_KEYS = {
    # YouTube innertube API keys — embedded in every YT/YTM client, not secret
    "AIzaSyC9XL3ZjWddXya6X74dJoCTL-WEYFDNX30",
    "AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8",
    "AIzaSyB-63vPrdThhKuerbB2N_l7Kwwcxj6yUAc",
}

_TEST_CREDENTIAL_VALUES = {
    "password",
    "pass",
    "secret",
    "changeme",
    "test",
    "example",
    "dummy",
    "placeholder",
    "admin",
    "root",
    "default",
}


def _is_test_path(filepath: str) -> bool:
    parts = Path(filepath).parts
    return bool(set(parts) & _TEST_DIR_SEGMENTS)


def _is_known_public_key(raw_secret: str) -> bool:
    return raw_secret.strip() in _KNOWN_PUBLIC_KEYS


def _looks_like_test_credential(raw_secret: str) -> bool:
    if "://" in raw_secret and "@" in raw_secret:
        try:
            parsed = urlparse(raw_secret)
            if parsed.password and parsed.password.lower() in _TEST_CREDENTIAL_VALUES:
                return True
            if parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "host.test"):
                return True
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Command building
# ---------------------------------------------------------------------------


def _write_exclude_file(path: str) -> None:
    """Write TruffleHog --exclude-paths regex file."""
    with open(path, "w") as f:
        for ext in sorted(_BINARY_EXTENSIONS):
            escaped = ext.replace(".", r"\.")
            f.write(f"{escaped}$\n")


def _build_command(repo_path: str, exclude_file: str | None = None) -> list[str]:
    cmd = [
        resolve_binary("trufflehog") or "trufflehog",
        "filesystem",
        "--json",
        "--no-update",
    ]
    if exclude_file:
        cmd += ["--exclude-paths", exclude_file]
    cmd.append(repo_path)
    return cmd


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

        # Layer 2: skip known-public keys
        if _is_known_public_key(secret_raw):
            continue

        # Layer 2 + 3: test directory handling
        in_test_dir = _is_test_path(filepath)
        if in_test_dir and _looks_like_test_credential(secret_raw):
            continue

        if verified:
            severity = Severity.CRITICAL
        elif in_test_dir:
            severity = Severity.INFO
        else:
            severity = Severity.MEDIUM

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
                asvs="v5.0.0-13.3.1",
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

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".txt",
                delete=False,
            ) as tmp:
                _write_exclude_file(tmp.name)
                exclude_path = tmp.name

            cmd = _build_command(repo_path, exclude_path)

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

            Path(exclude_path).unlink(missing_ok=True)

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
