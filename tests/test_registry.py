"""Tests for scanner and repo scanner registries and base scanner utilities."""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import patch

import pytest

from whiterabbit.config import RepoScanConfig, ScanConfig
from whiterabbit.repo_scanner import get_all_repo_scanners, get_repo_scanner
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import ScanResult
from whiterabbit.scanner import get_all_scanners, get_scanner
from whiterabbit.scanner.base import BaseScanner


class TestScannerRegistry:
    def test_get_all_scanners(self) -> None:
        scanners = get_all_scanners()
        assert "ssl" in scanners
        assert "headers" in scanners
        assert len(scanners) >= 2

    def test_get_scanner_known(self) -> None:
        cls = get_scanner("ssl")
        assert cls is not None

    def test_get_scanner_unknown(self) -> None:
        with pytest.raises(KeyError, match="Unknown scanner"):
            get_scanner("nonexistent")


class TestRepoScannerRegistry:
    def test_get_all_repo_scanners(self) -> None:
        scanners = get_all_repo_scanners()
        assert "cve" in scanners
        assert "owasp" in scanners

    def test_get_repo_scanner_known(self) -> None:
        cls = get_repo_scanner("cve")
        assert cls is not None

    def test_get_repo_scanner_unknown(self) -> None:
        with pytest.raises(KeyError, match="Unknown repo scanner"):
            get_repo_scanner("nonexistent")


class _StubScanner(BaseScanner):
    name = "stub"
    display_name = "Stub"
    description = "Stub scanner"
    required_binaries: ClassVar[list[str]] = ["some_binary"]

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        raise NotImplementedError


class _NoDepsScanner(BaseScanner):
    name = "nodeps"
    display_name = "No Deps"
    description = "Scanner with no deps"
    required_binaries: ClassVar[list[str]] = []

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        raise NotImplementedError


class TestBaseScanner:
    def test_is_available_when_binary_exists(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/some_binary"):
            scanner = _StubScanner()
            assert scanner.is_available() is True

    def test_is_available_when_binary_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            scanner = _StubScanner()
            assert scanner.is_available() is False

    def test_is_available_no_binaries(self) -> None:
        scanner = _NoDepsScanner()
        assert scanner.is_available() is True

    def test_check_dependencies_all_present(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/some_binary"):
            scanner = _StubScanner()
            assert scanner.check_dependencies() == []

    def test_check_dependencies_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            scanner = _StubScanner()
            missing = scanner.check_dependencies()
            assert len(missing) == 1
            assert "some_binary" in missing[0]

    def test_effective_timeout_default(self) -> None:
        scanner = _NoDepsScanner()
        config = ScanConfig(timeout=60)
        assert scanner.effective_timeout(config) == 60

    def test_effective_timeout_with_min(self) -> None:
        scanner = _NoDepsScanner()
        scanner.min_timeout = 120
        config = ScanConfig(timeout=60)
        assert scanner.effective_timeout(config) == 120

    def test_effective_timeout_config_higher(self) -> None:
        scanner = _NoDepsScanner()
        scanner.min_timeout = 120
        config = ScanConfig(timeout=300)
        assert scanner.effective_timeout(config) == 300


class _StubRepoScanner(BaseRepoScanner):
    name = "stub"
    display_name = "Stub Repo"
    description = "Stub repo scanner"
    required_binaries: ClassVar[list[str]] = ["semgrep"]

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        raise NotImplementedError


class TestBaseRepoScanner:
    def test_is_available_when_binary_exists(self) -> None:
        with patch("shutil.which", return_value="/usr/bin/semgrep"):
            scanner = _StubRepoScanner()
            assert scanner.is_available() is True

    def test_is_available_when_binary_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            scanner = _StubRepoScanner()
            assert scanner.is_available() is False

    def test_check_dependencies_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            scanner = _StubRepoScanner()
            missing = scanner.check_dependencies()
            assert len(missing) == 1
            assert "semgrep" in missing[0]

    def test_effective_timeout(self) -> None:
        scanner = _StubRepoScanner()
        config = RepoScanConfig(timeout=60)
        assert scanner.effective_timeout(config) == 60
