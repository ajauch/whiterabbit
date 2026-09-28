"""Tests for the Secret scanner (TruffleHog)."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.secret_scanner import (
    _BINARY_EXTENSIONS,
    SecretScanner,
    _build_command,
    _is_known_public_key,
    _is_test_path,
    _looks_like_test_credential,
    _parse_trufflehog_output,
    _redact,
    _write_exclude_file,
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


# ---------------------------------------------------------------------------
# Layer 1: exclude file
# ---------------------------------------------------------------------------


class TestWriteExcludeFile:
    def test_generates_regex_patterns(self, tmp_path) -> None:
        path = tmp_path / "exclude.txt"
        _write_exclude_file(str(path))
        content = path.read_text()
        assert r"\.wasm$" in content
        assert r"\.zip$" in content
        assert r"\.png$" in content

    def test_one_pattern_per_line(self, tmp_path) -> None:
        path = tmp_path / "exclude.txt"
        _write_exclude_file(str(path))
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
        assert len(lines) == len(_BINARY_EXTENSIONS)


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

    def test_exclude_file_passed(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.secret_scanner.resolve_binary",
            return_value="trufflehog",
        ):
            cmd = _build_command("/tmp/repo", "/tmp/exclude.txt")
        assert "--exclude-paths" in cmd
        idx = cmd.index("--exclude-paths")
        assert cmd[idx + 1] == "/tmp/exclude.txt"

    def test_no_exclude_file(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.secret_scanner.resolve_binary",
            return_value="trufflehog",
        ):
            cmd = _build_command("/tmp/repo")
        assert "--exclude-paths" not in cmd


# ---------------------------------------------------------------------------
# Layer 2: context filters
# ---------------------------------------------------------------------------


class TestIsTestPath:
    def test_test_directory(self) -> None:
        assert _is_test_path("tests/conftest.py")
        assert _is_test_path("__tests__/envFilter.test.ts")
        assert _is_test_path("src/__tests__/utils.test.js")

    def test_fixture_directory(self) -> None:
        assert _is_test_path("fixtures/data.json")
        assert _is_test_path("test/fixtures/creds.yml")

    def test_non_test_directory(self) -> None:
        assert not _is_test_path("src/config.py")
        assert not _is_test_path("lib/auth/keys.js")

    def test_test_in_filename_not_dir(self) -> None:
        assert not _is_test_path("src/test_utils.py")


class TestIsKnownPublicKey:
    def test_innertube_key(self) -> None:
        assert _is_known_public_key("AIzaSyC9XL3ZjWddXya6X74dJoCTL-WEYFDNX30")

    def test_innertube_key_with_whitespace(self) -> None:
        assert _is_known_public_key("  AIzaSyC9XL3ZjWddXya6X74dJoCTL-WEYFDNX30  ")

    def test_unknown_key(self) -> None:
        assert not _is_known_public_key("AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")


class TestLooksLikeTestCredential:
    def test_localhost_uri(self) -> None:
        assert _looks_like_test_credential("http://user:pass@localhost:5432/db")

    def test_loopback_uri(self) -> None:
        assert _looks_like_test_credential("postgres://u:p@127.0.0.1/testdb")

    def test_password_placeholder(self) -> None:
        assert _looks_like_test_credential("http://admin:password@example.com/api")

    def test_changeme_placeholder(self) -> None:
        assert _looks_like_test_credential("mysql://root:changeme@db.host/mydb")

    def test_real_looking_uri(self) -> None:
        assert not _looks_like_test_credential(
            "postgres://produser:s3cReT_K3y@db.prod.example.com/app"
        )

    def test_non_uri(self) -> None:
        assert not _looks_like_test_credential("AKIAIOSFODNN7EXAMPLE")


# ---------------------------------------------------------------------------
# Parsing with layers 2 + 3
# ---------------------------------------------------------------------------


class TestParseTrufflehogOutput:
    def test_single_unverified_finding(self) -> None:
        output = _make_trufflehog_finding(verified=False)
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.MEDIUM
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

    # Layer 2: known public keys are dropped
    def test_known_public_key_dropped(self) -> None:
        output = _make_trufflehog_finding(
            detector="GoogleGeminiAPIKey",
            filepath="src/ytm/YtmSearch.kt",
            raw="AIzaSyC9XL3ZjWddXya6X74dJoCTL-WEYFDNX30",
        )
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 0

    # Layer 2: test credential URIs in test dirs are dropped
    def test_test_credential_in_test_dir_dropped(self) -> None:
        output = _make_trufflehog_finding(
            detector="URI",
            filepath="__tests__/envFilter.test.ts",
            raw="http://user:password@localhost:5432/db",
        )
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 0

    # Layer 3: unverified secret in test dir downgraded to INFO
    def test_unverified_in_test_dir_downgraded_to_info(self) -> None:
        output = _make_trufflehog_finding(
            detector="AWS",
            filepath="tests/integration/test_auth.py",
            raw="AKIAIOSFODNN7REAL123",
            verified=False,
        )
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    # Layer 3: verified secret in test dir stays CRITICAL
    def test_verified_in_test_dir_stays_critical(self) -> None:
        output = _make_trufflehog_finding(
            detector="AWS",
            filepath="tests/integration/test_auth.py",
            raw="AKIAIOSFODNN7REAL123",
            verified=True,
        )
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    # Layer 2: test credentials outside test dirs are NOT dropped
    def test_test_credential_outside_test_dir_kept(self) -> None:
        output = _make_trufflehog_finding(
            detector="URI",
            filepath="src/config.py",
            raw="http://user:password@localhost:5432/db",
        )
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


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

    def test_exclude_paths_passed_to_trufflehog(self) -> None:
        proc = AsyncMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))

        with patch(
            "whiterabbit.repo_scanner.secret_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ) as mock_exec:
            scanner = SecretScanner()
            config = RepoScanConfig()
            asyncio.run(scanner.scan("/tmp/repo", config))
            call_args = mock_exec.call_args[0]
            assert "--exclude-paths" in call_args
