"""Tests for the Secret scanner (TruffleHog)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.secret_scanner import (
    SecretScanner,
    _build_command,
    _parse_trufflehog_output,
    _redact,
)
from whiterabbit.report.models import Severity


def _make_trufflehog_finding(
    detector: str = "AWS",
    verified: bool = False,
    filepath: str = "config/settings.py",
    line: int = 42,
    raw: str = "AKIAIOSFODNN7EXAMPLE",
) -> str:
    return json.dumps(
        {
            "DetectorName": detector,
            "DetectorType": 1,
            "Verified": verified,
            "Raw": raw,
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": filepath,
                        "line": line,
                    }
                }
            },
        }
    )


class TestRedact:
    def test_normal_string(self) -> None:
        assert _redact("AKIAIOSFODNN7EXAMPLE") == "AKIAI***"

    def test_short_string(self) -> None:
        assert _redact("abc") == "***"

    def test_exact_keep_length(self) -> None:
        assert _redact("abcde") == "***"

    def test_custom_keep(self) -> None:
        assert _redact("AKIAIOSFODNN7EXAMPLE", keep=3) == "AKI***"


class TestBuildCommand:
    def test_default_command(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.secret_scanner.resolve_binary",
            return_value="/usr/bin/trufflehog",
        ):
            cmd = _build_command("/tmp/repo")
        assert cmd[0] == "/usr/bin/trufflehog"
        assert "filesystem" in cmd
        assert "--json" in cmd
        assert "--no-update" in cmd
        assert "/tmp/repo" in cmd


class TestParseTrufflehogOutput:
    def test_single_unverified_finding(self) -> None:
        output = _make_trufflehog_finding(verified=False)
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.category == "secret"
        assert f.scanner == "secret"
        assert "AWS" in f.title
        assert "unverified" in f.title
        assert "config/settings.py:42" in f.title

    def test_verified_finding_is_critical(self) -> None:
        output = _make_trufflehog_finding(verified=True)
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "verified active" in findings[0].title
        assert "verified as currently active" in findings[0].description

    def test_multiple_findings(self) -> None:
        lines = "\n".join(
            [
                _make_trufflehog_finding(detector="AWS", filepath="a.py", raw="key1"),
                _make_trufflehog_finding(
                    detector="Slack", filepath="b.py", raw="xoxb-token"
                ),
            ]
        )
        findings = _parse_trufflehog_output(lines)
        assert len(findings) == 2

    def test_deduplication(self) -> None:
        line = _make_trufflehog_finding()
        output = f"{line}\n{line}"
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1

    def test_empty_output(self) -> None:
        findings = _parse_trufflehog_output("")
        assert findings == []

    def test_invalid_json_lines_skipped(self) -> None:
        output = f"not json\n{_make_trufflehog_finding()}\nalso not json"
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1

    def test_remediation_includes_detector(self) -> None:
        output = _make_trufflehog_finding(detector="GitHub")
        findings = _parse_trufflehog_output(output)
        assert "GitHub" in findings[0].remediation

    def test_redacted_in_raw(self) -> None:
        output = _make_trufflehog_finding(raw="AKIAIOSFODNN7EXAMPLE")
        findings = _parse_trufflehog_output(output)
        assert findings[0].raw["redacted"] == "AKIAI***"
        assert "AKIAIOSFODNN7EXAMPLE" not in str(findings[0].raw)


class TestSecretScanner:
    def test_is_available_without_trufflehog(self) -> None:
        with patch("whiterabbit.repo_scanner.base.resolve_binary", return_value=None):
            scanner = SecretScanner()
            assert not scanner.is_available()

    def test_is_available_with_trufflehog(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.base.resolve_binary",
            return_value="/usr/bin/trufflehog",
        ):
            scanner = SecretScanner()
            assert scanner.is_available()

    def test_successful_scan(self) -> None:
        trufflehog_output = _make_trufflehog_finding()

        proc = AsyncMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(trufflehog_output.encode(), b""))

        with patch(
            "whiterabbit.repo_scanner.secret_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = SecretScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is None
            assert len(result.findings) == 1

    def test_trufflehog_not_found(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.secret_scanner.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError,
        ):
            scanner = SecretScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "trufflehog not found" in result.error

    def test_trufflehog_error_exit(self) -> None:
        proc = AsyncMock()
        proc.returncode = 2
        proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch(
            "whiterabbit.repo_scanner.secret_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = SecretScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "TruffleHog exited with code 2" in result.error

    def test_timeout(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)

        with (
            patch(
                "whiterabbit.repo_scanner.secret_scanner.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
            patch(
                "whiterabbit.repo_scanner.secret_scanner.asyncio.wait_for",
                side_effect=TimeoutError,
            ),
        ):
            scanner = SecretScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "timed out" in result.error

    def test_no_findings_clean_scan(self) -> None:
        proc = AsyncMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "whiterabbit.repo_scanner.secret_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = SecretScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is None
            assert len(result.findings) == 0
