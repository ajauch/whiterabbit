"""Shared manifest parsing for repo scanners."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class DepInfo:
    """A dependency with classification metadata."""

    name: str
    version: str
    is_dev: bool = False
    is_direct: bool = True


def parse_requirements_txt(path: Path) -> list[tuple[str, str]]:
    """Parse requirements.txt, returning (name, version) for pinned deps."""
    deps: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
        if match:
            deps.append((match.group(1), match.group(2)))
    return deps


def parse_pyproject_toml(path: Path) -> list[tuple[str, str]]:
    """Parse pyproject.toml dependencies, returning (name, version) for pinned deps."""
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


def parse_package_json(path: Path) -> list[tuple[str, str]]:
    """Parse package.json, returning (name, version) for all deps."""
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


def parse_package_lock_json(path: Path) -> list[tuple[str, str]]:
    """Parse package-lock.json (v1 and v2+), returning (name, version)."""
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


MANIFEST_PARSERS: dict[str, tuple[str, Any]] = {
    "requirements.txt": ("PyPI", parse_requirements_txt),
    "pyproject.toml": ("PyPI", parse_pyproject_toml),
    "package.json": ("npm", parse_package_json),
    "package-lock.json": ("npm", parse_package_lock_json),
}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv", "vendor", ".tox"}


def detect_ecosystems(repo_path: str) -> dict[str, list[tuple[str, str]]]:
    """Recursively find known manifests and parse them into (name, version) pairs."""
    results: dict[str, list[tuple[str, str]]] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename not in MANIFEST_PARSERS:
                continue
            ecosystem, parser = MANIFEST_PARSERS[filename]
            manifest = Path(dirpath) / filename
            parsed = parser(manifest)
            if parsed:
                results.setdefault(ecosystem, []).extend(parsed)
    return results


# ---------------------------------------------------------------------------
# Rich dependency detection — adds dev/direct classification
# ---------------------------------------------------------------------------


def _classify_package_json(path: Path) -> tuple[set[str], set[str]]:
    """Return (prod_names, dev_names) from a package.json."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return set(), set()
    prod = set(data.get("dependencies", {}).keys())
    dev = set(data.get("devDependencies", {}).keys())
    return prod, dev


def _parse_package_lock_rich(
    lock_path: Path,
    prod_names: set[str],
    dev_names: set[str],
) -> list[DepInfo]:
    """Parse a lockfile and classify each entry as dev/direct using package.json context."""
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    direct_names = prod_names | dev_names
    deps: list[DepInfo] = []

    packages = data.get("packages", {})
    if packages:
        for key, info in packages.items():
            if not key:
                continue
            name = key.split("node_modules/")[-1]
            version = info.get("version", "")
            if not name or not version:
                continue
            is_dev = bool(info.get("dev", False))
            is_direct = name in direct_names
            deps.append(DepInfo(name, version, is_dev=is_dev, is_direct=is_direct))
    else:
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if not version:
                continue
            is_dev = bool(info.get("dev", False))
            is_direct = name in direct_names
            deps.append(DepInfo(name, version, is_dev=is_dev, is_direct=is_direct))

    return deps


def _parse_package_json_rich(path: Path) -> list[DepInfo]:
    """Parse package.json into DepInfo when no lockfile is available."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []
    deps: list[DepInfo] = []
    for section, is_dev in (("dependencies", False), ("devDependencies", True)):
        for name, version in data.get(section, {}).items():
            clean = re.sub(r"^[~^>=<]*", "", version).strip()
            if clean:
                deps.append(DepInfo(name, clean, is_dev=is_dev, is_direct=True))
    return deps


def detect_ecosystems_rich(repo_path: str) -> dict[str, list[DepInfo]]:
    """Like detect_ecosystems but returns DepInfo with dev/direct classification.

    For npm: when both package.json and package-lock.json exist in the same
    directory, only the lockfile is scanned (it has exact versions for every
    transitive dep).  package.json is used solely to classify direct vs.
    transitive and prod vs. dev.  When only package.json exists, its entries
    are returned as direct deps.

    For PyPI: all dependencies from requirements.txt / pyproject.toml are
    treated as direct prod deps (Python tooling lacks a standard dev marker
    in these files).
    """
    results: dict[str, list[DepInfo]] = {}

    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        has_package_json = "package.json" in filenames
        has_lock = "package-lock.json" in filenames

        for filename in filenames:
            fpath = Path(dirpath) / filename

            if filename == "package-lock.json" and has_package_json:
                pj_path = Path(dirpath) / "package.json"
                prod_names, dev_names = _classify_package_json(pj_path)
                deps = _parse_package_lock_rich(fpath, prod_names, dev_names)
                if deps:
                    results.setdefault("npm", []).extend(deps)
                continue

            if filename == "package-lock.json":
                deps = _parse_package_lock_rich(fpath, set(), set())
                if deps:
                    results.setdefault("npm", []).extend(deps)
                continue

            if filename == "package.json" and has_lock:
                continue

            if filename == "package.json":
                deps = _parse_package_json_rich(fpath)
                if deps:
                    results.setdefault("npm", []).extend(deps)
                continue

            if filename == "requirements.txt":
                for name, version in parse_requirements_txt(fpath):
                    results.setdefault("PyPI", []).append(
                        DepInfo(name, version, is_dev=False, is_direct=True)
                    )
                continue

            if filename == "pyproject.toml":
                for name, version in parse_pyproject_toml(fpath):
                    results.setdefault("PyPI", []).append(
                        DepInfo(name, version, is_dev=False, is_direct=True)
                    )
                continue

    return results


# ---------------------------------------------------------------------------
# Name-only extraction (for slopsquat scanner — captures all deps, not just
# pinned ones, and skips lockfiles since those can't be hallucinated)
# ---------------------------------------------------------------------------

_DIRECT_DEP_MANIFESTS: dict[str, str] = {
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
}


def _extract_names_requirements_txt(path: Path) -> set[str]:
    """Extract all package names from requirements.txt regardless of version pin."""
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)", line)
        if match:
            names.add(match.group(1))
    return names


def _extract_names_pyproject_toml(path: Path) -> set[str]:
    """Extract all package names from pyproject.toml regardless of version pin."""
    names: set[str] = set()
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
            match = re.match(r"""["']([A-Za-z0-9_.-]+)""", stripped)
            if match:
                names.add(match.group(1))
    return names


def _extract_names_package_json(path: Path) -> set[str]:
    """Extract all package names from package.json."""
    names: set[str] = set()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return names
    for section in ("dependencies", "devDependencies"):
        for name in data.get(section, {}):
            names.add(name)
    return names


_NAME_EXTRACTORS: dict[str, Any] = {
    "requirements.txt": _extract_names_requirements_txt,
    "pyproject.toml": _extract_names_pyproject_toml,
    "package.json": _extract_names_package_json,
}


def extract_package_names(repo_path: str) -> dict[str, set[str]]:
    """Recursively find direct-dependency manifests and extract package names.

    Skips lockfiles (package-lock.json) since lockfile entries were resolved
    by the package manager and cannot be hallucinated.
    """
    results: dict[str, set[str]] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename not in _DIRECT_DEP_MANIFESTS:
                continue
            ecosystem = _DIRECT_DEP_MANIFESTS[filename]
            extractor = _NAME_EXTRACTORS[filename]
            manifest = Path(dirpath) / filename
            names = extractor(manifest)
            if names:
                results.setdefault(ecosystem, set()).update(names)
    return results
