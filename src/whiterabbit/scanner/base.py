"""Base scanner interface that all scanners must implement."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import ScanResult


class BaseScanner(ABC):
    name: str
    display_name: str
    description: str
    required_binaries: list[str] = []
    min_timeout: int | None = None

    @abstractmethod
    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        ...

    def effective_timeout(self, config: ScanConfig) -> int:
        if self.min_timeout is not None:
            return max(config.timeout, self.min_timeout)
        return config.timeout

    def is_available(self) -> bool:
        return all(shutil.which(b) is not None for b in self.required_binaries)

    def check_dependencies(self) -> list[str]:
        missing: list[str] = []
        for binary in self.required_binaries:
            if shutil.which(binary) is None:
                missing.append(f"  {binary!r} not found on PATH")
        return missing
