"""OWASP SAST scanner — static analysis using Semgrep."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import UTC, datetime
from typing import ClassVar

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.resolve import resolve_binary, subprocess_env

log = logging.getLogger("whiterabbit")

SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

DEFAULT_CONFIG = "p/owasp-top-ten"

# ---------------------------------------------------------------------------
# GitHub Actions shell-injection false-positive filtering
# ---------------------------------------------------------------------------
# Semgrep flags every ${{ }} in a workflow `run:` step as potential shell
# injection, but only expressions referencing *user-controlled* input are
# actually exploitable.  Everything else (github.sha, secrets.*, steps.*,
# env.*, etc.) is safe and produces noise that drowns real findings.

_GHA_UNTRUSTED_CONTEXTS: set[str] = {
    "github.head_ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
}

_GHA_UNTRUSTED_PREFIXES: tuple[str, ...] = (
    "github.event.commits[",
    "github.event.commits.",
    "github.event.pages[",
    "github.event.pages.",
)

_GHA_EXPR_RE = re.compile(r"\$\{\{\s*(.+?)\s*\}\}")


def _gha_expr_is_untrusted(expr: str) -> bool:
    """Check if a single GitHub Actions expression references untrusted input."""
    if any(ctx in expr for ctx in _GHA_UNTRUSTED_CONTEXTS):
        return True
    return any(prefix in expr for prefix in _GHA_UNTRUSTED_PREFIXES)


def _has_untrusted_gha_expression(source: str) -> bool:
    """Return True if any ``${{ }}`` expression in *source* references
    user-controlled input that could enable shell injection."""
    for match in _GHA_EXPR_RE.finditer(source):
        if _gha_expr_is_untrusted(match.group(1)):
            return True
    return False


def _build_command(repo_path: str, timeout: int) -> list[str]:
    return [
        resolve_binary("semgrep") or "semgrep",
        "--config",
        DEFAULT_CONFIG,
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--timeout",
        str(timeout),
        repo_path,
    ]


def _parse_semgrep_output(raw: str) -> list[Finding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    seen: set[str] = set()

    for result in data.get("results", []):
        check_id = result.get("check_id", "unknown")
        path = result.get("path", "")
        start = result.get("start", {})
        line = start.get("line", 0)

        dedup_key = f"{check_id}|{path}|{line}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        extra = result.get("extra", {})

        if "run-shell-injection" in check_id:
            lines = extra.get("lines", "")
            if lines and not _has_untrusted_gha_expression(lines):
                continue
        severity_str = extra.get("severity", "INFO")
        severity = SEMGREP_SEVERITY_MAP.get(severity_str, Severity.LOW)

        message = extra.get("message", f"Semgrep rule {check_id} matched.")
        metadata = extra.get("metadata", {})

        cwe_list = metadata.get("cwe", [])
        cwe_id = None
        if isinstance(cwe_list, list) and cwe_list:
            cwe_id = str(cwe_list[0])
        elif isinstance(cwe_list, str):
            cwe_id = cwe_list

        references: list[str] = []
        refs = metadata.get("references", [])
        if isinstance(refs, list):
            references = [str(r) for r in refs[:5]]

        fix = extra.get("fix", "")
        remediation = fix if fix else "Review and fix the identified vulnerability."

        location = f"{path}:{line}" if path and line else path

        owasp = metadata.get("owasp", [])
        owasp_tag = ""
        if isinstance(owasp, list) and owasp:
            owasp_tag = f" [{owasp[0]}]"
        elif isinstance(owasp, str):
            owasp_tag = f" [{owasp}]"

        rule_name = check_id.split(".")[-1].replace("-", " ").replace("_", " ")

        findings.append(
            Finding(
                severity=severity,
                title=f"{rule_name}{owasp_tag} — {location}",
                description=message[:500],
                remediation=remediation,
                category="sast-owasp",
                scanner="owasp",
                cwe=cwe_id,
                references=references,
                raw={"check_id": check_id, "path": path, "line": line},
            )
        )

    return findings


class OWASPScanner(BaseRepoScanner):
    name = "owasp"
    display_name = "OWASP SAST Scanner"
    description = "Static analysis for OWASP vulnerabilities using Semgrep"
    required_binaries: ClassVar[list[str]] = ["semgrep"]

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(UTC)
        cmd = _build_command(repo_path, config.timeout)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=subprocess_env(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=config.timeout + 30,
            )

            if proc.returncode not in (0, 1):
                error_msg = stderr.decode(errors="replace").strip()
                return ScanResult(
                    target=repo_path,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                    error=f"Semgrep exited with code {proc.returncode}: {error_msg}",
                )

            findings = _parse_semgrep_output(stdout.decode(errors="replace"))

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
                error="semgrep not found. Install: pip install semgrep",
            )
        except TimeoutError:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Semgrep timed out after {config.timeout + 30}s",
            )
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )
