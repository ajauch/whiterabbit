"""Repo scanner registry — all repo scanners are explicitly registered here."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from whiterabbit.repo_scanner.base import BaseRepoScanner

from whiterabbit.repo_scanner.cve_scanner import CVEScanner
from whiterabbit.repo_scanner.owasp_scanner import OWASPScanner

REPO_SCANNER_REGISTRY: dict[str, type[BaseRepoScanner]] = {
    "cve": CVEScanner,
    "owasp": OWASPScanner,
}


def get_repo_scanner(name: str) -> type[BaseRepoScanner]:
    if name not in REPO_SCANNER_REGISTRY:
        available = ", ".join(sorted(REPO_SCANNER_REGISTRY)) or "(none)"
        msg = f"Unknown repo scanner: {name!r}. Available: {available}"
        raise KeyError(msg)
    return REPO_SCANNER_REGISTRY[name]


def get_all_repo_scanners() -> dict[str, type[BaseRepoScanner]]:
    return dict(REPO_SCANNER_REGISTRY)
