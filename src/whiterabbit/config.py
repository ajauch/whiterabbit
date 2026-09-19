"""Scan configuration and profiles."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    timeout: int = 300
    verbose: bool = False
    format: str = "terminal"
    output: str | None = None
    scanners: list[str] = field(default_factory=list)
    quick: bool = False
    full: bool = False


@dataclass
class RepoScanConfig:
    timeout: int = 300
    verbose: bool = False
    format: str = "terminal"
    output: str | None = None
    scanners: list[str] = field(default_factory=list)
    quick: bool = False
    full: bool = False
    branch: str | None = None
    depth: int | None = 1
    keep_clone: bool = False
