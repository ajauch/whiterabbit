"""Dependency pinning scanner — flags unpinned or loosely pinned dependencies."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity

log = logging.getLogger("whiterabbit")

_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", ".tox"}

_LOCKFILE_NAMES: dict[str, list[str]] = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
}


@dataclass
class DepSpec:
    name: str
    specifier: str
    manifest: str
    line_number: int


# ---------------------------------------------------------------------------
# Specifier classification
# ---------------------------------------------------------------------------

_EXACT_NPM_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:-[\w.]+)?(?:\+[\w.]+)?$")


def _classify_specifier(specifier: str) -> Severity | None:
    stripped = specifier.strip()
    if not stripped or stripped in ("*", "latest", "x", "X"):
        return Severity.HIGH
    if stripped.startswith("=="):
        return None
    if _EXACT_NPM_VERSION_RE.match(stripped):
        return None
    if stripped.startswith((">=", "~=", "^", "~")):
        return Severity.LOW
    return Severity.MEDIUM


# ---------------------------------------------------------------------------
# Manifest parsers
# ---------------------------------------------------------------------------

_DEP_LINE_RE = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[.*?\])?\s*(.*?)$")


def _parse_requirements_txt_deps(path: Path, repo_root: str) -> list[DepSpec]:
    deps: list[DepSpec] = []
    rel = os.path.relpath(str(path), repo_root)
    for line_num, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-e", "-r", "-c", "--", "-f", "-i")):
            continue
        comment_pos = line.find(" #")
        if comment_pos != -1:
            line = line[:comment_pos].strip()
        semi_pos = line.find(";")
        if semi_pos != -1:
            line = line[:semi_pos].strip()
        match = _DEP_LINE_RE.match(line)
        if match:
            deps.append(
                DepSpec(
                    name=match.group(1),
                    specifier=match.group(2).strip(),
                    manifest=rel,
                    line_number=line_num,
                )
            )
    return deps


def _parse_pyproject_toml_deps(path: Path, repo_root: str) -> list[DepSpec]:
    deps: list[DepSpec] = []
    rel = os.path.relpath(str(path), repo_root)
    text = path.read_text(encoding="utf-8", errors="replace")
    in_deps = False
    for line_num, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if re.match(
            r"^(?:\[?dependencies\]?\s*=\s*\[|dependencies\s*=\s*\[)", stripped
        ):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            match = re.match(
                r"""["']([A-Za-z0-9_.-]+)(?:\[.*?\])?\s*([^"']*)?["']""", stripped
            )
            if match:
                deps.append(
                    DepSpec(
                        name=match.group(1),
                        specifier=(match.group(2) or "").strip(),
                        manifest=rel,
                        line_number=line_num,
                    )
                )
    return deps


def _parse_package_json_deps(path: Path, repo_root: str) -> list[DepSpec]:
    deps: list[DepSpec] = []
    rel = os.path.relpath(str(path), repo_root)
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version_spec in data.get(section, {}).items():
            if isinstance(version_spec, str):
                deps.append(
                    DepSpec(
                        name=name,
                        specifier=version_spec.strip(),
                        manifest=rel,
                        line_number=0,
                    )
                )
    return deps


MANIFEST_PARSERS: dict[str, object] = {
    "requirements.txt": _parse_requirements_txt_deps,
    "pyproject.toml": _parse_pyproject_toml_deps,
    "package.json": _parse_package_json_deps,
}


# ---------------------------------------------------------------------------
# Manifest discovery
# ---------------------------------------------------------------------------


def _find_manifests(repo_path: str) -> list[tuple[str, Path]]:
    results: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            if filename in MANIFEST_PARSERS:
                results.append((filename, Path(dirpath) / filename))
    return results


# ---------------------------------------------------------------------------
# Missing lockfile detection
# ---------------------------------------------------------------------------


def _check_missing_lockfiles(
    repo_path: str, manifests: list[tuple[str, Path]]
) -> list[Finding]:
    findings: list[Finding] = []
    for manifest_type, manifest_path in manifests:
        lockfile_names = _LOCKFILE_NAMES.get(manifest_type)
        if not lockfile_names:
            continue
        parent = manifest_path.parent
        has_lockfile = any((parent / lf).exists() for lf in lockfile_names)
        if not has_lockfile:
            rel = os.path.relpath(str(manifest_path), repo_path)
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"Missing lockfile for {rel}",
                    description=(
                        f"No lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml) "
                        f"found alongside {rel}. Without a lockfile, dependency resolution "
                        f"is non-deterministic and vulnerable to supply-chain attacks."
                    ),
                    remediation=(
                        "Generate a lockfile by running 'npm install', 'yarn install', "
                        "or 'pnpm install' and commit it to version control."
                    ),
                    category="supply-chain",
                    scanner="pinning",
                    raw={"manifest": rel},
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Finding conversion
# ---------------------------------------------------------------------------


def _deps_to_findings(deps: list[DepSpec]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for dep in deps:
        severity = _classify_specifier(dep.specifier)
        if severity is None:
            continue
        dedup_key = f"{dep.name}|{dep.manifest}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        if severity == Severity.HIGH:
            title = f"Unpinned dependency: {dep.name} in {dep.manifest}"
            desc_detail = dep.specifier if dep.specifier else "bare name"
            description = (
                f"{dep.name} has no version constraint ({desc_detail}). "
                f"Without pinning, any version — including compromised ones — "
                f"can be installed."
            )
        else:
            title = (
                f"Loosely pinned dependency: {dep.name} "
                f"({dep.specifier}) in {dep.manifest}"
            )
            description = (
                f"{dep.name} uses a loose version constraint ({dep.specifier}). "
                f"This allows automatic upgrades that may introduce vulnerabilities."
            )

        if dep.manifest.endswith("package.json"):
            remediation = (
                f"Pin {dep.name} to an exact version in package.json "
                f"and ensure a lockfile is committed."
            )
        elif dep.manifest.endswith("pyproject.toml"):
            remediation = f'Pin {dep.name} to an exact version: "{dep.name}==<version>"'
        else:
            remediation = f"Pin {dep.name} to an exact version: {dep.name}==<version>"

        findings.append(
            Finding(
                severity=severity,
                title=title,
                description=description[:500],
                remediation=remediation,
                category="unpinned-dependency",
                scanner="pinning",
                raw={
                    "package": dep.name,
                    "specifier": dep.specifier,
                    "manifest": dep.manifest,
                    "line": dep.line_number,
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Scanner class
# ---------------------------------------------------------------------------


class PinningScanner(BaseRepoScanner):
    name = "pinning"
    display_name = "Dependency Pinning Scanner"
    description = (
        "Detects unpinned or loosely pinned dependencies that create supply-chain risk"
    )

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(UTC)
        try:
            manifests = _find_manifests(repo_path)
            if not manifests:
                log.info("[pinning] no supported manifest files found")
                return ScanResult(
                    target=repo_path,
                    scanner_name=self.name,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                )

            all_deps: list[DepSpec] = []
            for manifest_type, path in manifests:
                parser = MANIFEST_PARSERS[manifest_type]
                all_deps.extend(parser(path, repo_path))  # type: ignore[operator]

            findings = _deps_to_findings(all_deps)
            findings.extend(_check_missing_lockfiles(repo_path, manifests))

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
