"""Log leak scanner — detects logging of sensitive data."""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity

log = logging.getLogger("whiterabbit")

_SKIP_DIRS = {
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
    ".tox",
    "test",
    "tests",
    "__tests__",
    "spec",
    "specs",
    "fixtures",
    ".pytest_cache",
    "coverage",
}

_SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
}

# ---------------------------------------------------------------------------
# Sensitive name detection
# ---------------------------------------------------------------------------

_SENSITIVE_RE = re.compile(
    r"\b("
    r"pass(?:word|wd|phrase)"
    r"|pwd"
    r"|(?:api[_.]?)?secret(?:[_.]?key)?"
    r"|api[_.]?key"
    r"|(?:access[_.]?|refresh[_.]?|auth[_.]?)?token"
    r"|bearer"
    r"|(?:private|signing|encryption)[_.]?key"
    r"|ssn"
    r"|social[_.]?security"
    r"|credit[_.]?card"
    r"|card[_.]?number"
    r"|cvv"
    r"|authorization"
    r")\b",
    re.IGNORECASE,
)

_HIGH_SEVERITY_NAMES = {
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "secret",
    "api_secret",
    "apisecret",
    "secret_key",
    "secretkey",
    "private_key",
    "privatekey",
    "signing_key",
    "signingkey",
    "encryption_key",
    "encryptionkey",
    "ssn",
    "social_security",
    "socialsecurity",
    "credit_card",
    "creditcard",
    "card_number",
    "cardnumber",
    "cvv",
}

# ---------------------------------------------------------------------------
# Request body pattern
# ---------------------------------------------------------------------------

_REQUEST_BODY_RE = re.compile(
    r"(?:request|req)\s*\.\s*(?:body|data|params|form|json)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Logging call patterns (per language)
# ---------------------------------------------------------------------------

_PYTHON_LOG_RE = re.compile(
    r"(?:logging|log|logger)\s*\.\s*(?:debug|info|warning|error|critical|exception|log)\s*\("
    r"|print\s*\(",
)

_JS_LOG_RE = re.compile(
    r"console\s*\.\s*(?:log|warn|error|debug|info|trace|dir)\s*\(",
)

_JAVA_LOG_RE = re.compile(
    r"(?:logger|log|LOG)\s*\.\s*(?:debug|info|warn|error|trace|fatal)\s*\("
    r"|System\s*\.\s*(?:out|err)\s*\.\s*print(?:ln)?\s*\(",
    re.IGNORECASE,
)

_GO_LOG_RE = re.compile(
    r"(?:log|fmt)\s*\.\s*(?:Print|Printf|Println|Fatal|Fatalf|Fatalln)\s*\("
    r"|(?:log|slog)\s*\.\s*(?:Debug|Info|Warn|Error)(?:f|ln|w)?\s*\(",
)

_GENERIC_LOG_RE = re.compile(
    r"\blog\s*[.(]",
    re.IGNORECASE,
)

_EXTENSION_LOG_RE: dict[str, re.Pattern[str]] = {
    ".py": _PYTHON_LOG_RE,
    ".js": _JS_LOG_RE,
    ".jsx": _JS_LOG_RE,
    ".ts": _JS_LOG_RE,
    ".tsx": _JS_LOG_RE,
    ".java": _JAVA_LOG_RE,
    ".go": _GO_LOG_RE,
    ".rb": _GENERIC_LOG_RE,
    ".php": _GENERIC_LOG_RE,
}

# ---------------------------------------------------------------------------
# String literal stripping
# ---------------------------------------------------------------------------

_STRING_LITERAL_RE = re.compile(
    r'"""[\s\S]*?"""'
    r"|'''[\s\S]*?'''"
    r'|"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
    r"|`(?:[^`\\]|\\.)*`"
)

_FSTRING_EXPR_RE = re.compile(r"\{([^}]+)\}")


def _strip_string_literals(line: str) -> str:
    has_fstring = re.search(r'\bf"', line) or re.search(r"\bf'", line)
    has_template = "`" in line and "${" in line

    if has_fstring:
        parts: list[str] = []
        for match in _FSTRING_EXPR_RE.finditer(line):
            parts.append(match.group(1))
        non_string = _STRING_LITERAL_RE.sub("", line)
        return non_string + " " + " ".join(parts)

    if has_template:
        template_expr_re = re.compile(r"\$\{([^}]+)\}")
        parts = []
        for match in template_expr_re.finditer(line):
            parts.append(match.group(1))
        non_string = _STRING_LITERAL_RE.sub("", line)
        return non_string + " " + " ".join(parts)

    return _STRING_LITERAL_RE.sub("", line)


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------


def _find_source_files(repo_path: str) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext in _SOURCE_EXTENSIONS:
                yield Path(dirpath) / filename


def _scan_file(path: Path, repo_root: str) -> list[Finding]:
    findings: list[Finding] = []
    ext = path.suffix.lower()
    log_re = _EXTENSION_LOG_RE.get(ext)
    if log_re is None:
        return findings

    rel = os.path.relpath(str(path), repo_root)

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for line_num, raw_line in enumerate(lines, start=1):
        stripped_line = raw_line.strip()
        if (
            not stripped_line
            or stripped_line.startswith("#")
            or stripped_line.startswith("//")
        ):
            continue

        if not log_re.search(stripped_line):
            continue

        if _REQUEST_BODY_RE.search(stripped_line):
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"Full request body logged — {rel}:{line_num}",
                    description=(
                        "A logging statement outputs a full request body/data object, "
                        "which may contain passwords, tokens, PII, or other sensitive "
                        "data submitted by users."
                    ),
                    remediation=(
                        "Log only specific, non-sensitive fields from the request "
                        "instead of the entire body. Use structured logging with "
                        "explicit field selection."
                    ),
                    category="log-leak",
                    scanner="logleak",
                    cwe="CWE-532",
                    references=["https://cwe.mitre.org/data/definitions/532.html"],
                    raw={
                        "file": rel,
                        "line": line_num,
                        "matched": "request.body",
                        "language": ext,
                    },
                )
            )
            continue

        cleaned = _strip_string_literals(stripped_line)
        match = _SENSITIVE_RE.search(cleaned)
        if match:
            matched_name = match.group(1).lower()
            severity = (
                Severity.HIGH
                if matched_name in _HIGH_SEVERITY_NAMES
                else Severity.MEDIUM
            )
            findings.append(
                Finding(
                    severity=severity,
                    title=f"Sensitive data in log: {matched_name} — {rel}:{line_num}",
                    description=(
                        f"A logging statement appears to output the value of "
                        f"'{matched_name}'. Logging sensitive data can expose "
                        f"credentials in log files, monitoring systems, and error "
                        f"tracking services."
                    ),
                    remediation=(
                        "Remove the sensitive variable from the logging statement, "
                        "or redact/mask it before logging. Never log passwords, "
                        "secrets, tokens, or PII in plaintext."
                    ),
                    category="log-leak",
                    scanner="logleak",
                    cwe="CWE-532",
                    references=["https://cwe.mitre.org/data/definitions/532.html"],
                    raw={
                        "file": rel,
                        "line": line_num,
                        "matched": matched_name,
                        "language": ext,
                    },
                )
            )
    return findings


def _scan_all_files(repo_path: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in _find_source_files(repo_path):
        for finding in _scan_file(path, repo_path):
            raw = finding.raw or {}
            dedup_key = (
                f"{raw.get('file', '')}|{raw.get('line', 0)}|{raw.get('matched', '')}"
            )
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class LogLeakScanner(BaseRepoScanner):
    name = "logleak"
    display_name = "Log Leak Scanner"
    description = (
        "Detects logging statements that may expose sensitive data "
        "like passwords, tokens, and PII"
    )

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(UTC)
        try:
            findings = _scan_all_files(repo_path)
            if not findings:
                log.info("[logleak] no sensitive data logging detected")
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                findings=findings,
            )
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
