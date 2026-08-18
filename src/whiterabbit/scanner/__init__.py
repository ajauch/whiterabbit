"""Scanner registry — all scanners are explicitly registered here."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from whiterabbit.scanner.base import BaseScanner

from whiterabbit.scanner.header_scanner import HeaderScanner
from whiterabbit.scanner.nuclei_scanner import NucleiScanner
from whiterabbit.scanner.retirejs_scanner import RetireJSScanner
from whiterabbit.scanner.ssl_scanner import SSLScanner
from whiterabbit.scanner.testssl_scanner import TestSSLScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    "ssl": SSLScanner,
    "headers": HeaderScanner,
    "nuclei": NucleiScanner,
    "retirejs": RetireJSScanner,
    "testssl": TestSSLScanner,
}


def get_scanner(name: str) -> type[BaseScanner]:
    if name not in SCANNER_REGISTRY:
        available = ", ".join(sorted(SCANNER_REGISTRY)) or "(none)"
        msg = f"Unknown scanner: {name!r}. Available: {available}"
        raise KeyError(msg)
    return SCANNER_REGISTRY[name]


def get_all_scanners() -> dict[str, type[BaseScanner]]:
    return dict(SCANNER_REGISTRY)
