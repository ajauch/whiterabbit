"""Repo scanner registry — all repo scanners are explicitly registered here."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from whiterabbit.repo_scanner.base import BaseRepoScanner

from whiterabbit.repo_scanner.bandit_scanner import BanditScanner
from whiterabbit.repo_scanner.cve_scanner import CVEScanner
from whiterabbit.repo_scanner.logleak_scanner import LogLeakScanner
from whiterabbit.repo_scanner.owasp_scanner import OWASPScanner
from whiterabbit.repo_scanner.pinning_scanner import PinningScanner
from whiterabbit.repo_scanner.secret_scanner import SecretScanner
from whiterabbit.repo_scanner.slopsquat_scanner import SlopsquatScanner
from whiterabbit.repo_scanner.trivy_scanner import TrivyScanner

REPO_SCANNER_REGISTRY: dict[str, type[BaseRepoScanner]] = {
    "cve": CVEScanner,
    "owasp": OWASPScanner,
    "trivy": TrivyScanner,
    "secret": SecretScanner,
    "bandit": BanditScanner,
    "slopsquat": SlopsquatScanner,
    "pinning": PinningScanner,
    "logleak": LogLeakScanner,
}


def get_repo_scanner(name: str) -> type[BaseRepoScanner]:
    if name not in REPO_SCANNER_REGISTRY:
        available = ", ".join(sorted(REPO_SCANNER_REGISTRY)) or "(none)"
        msg = f"Unknown repo scanner: {name!r}. Available: {available}"
        raise KeyError(msg)
    return REPO_SCANNER_REGISTRY[name]


def get_all_repo_scanners() -> dict[str, type[BaseRepoScanner]]:
    return dict(REPO_SCANNER_REGISTRY)
