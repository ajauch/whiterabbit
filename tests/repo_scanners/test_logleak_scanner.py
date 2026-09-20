"""Tests for the log leak scanner."""

from __future__ import annotations

import asyncio
from pathlib import Path

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.logleak_scanner import (
    _SENSITIVE_RE,
    LogLeakScanner,
    _scan_all_files,
    _scan_file,
    _strip_string_literals,
)
from whiterabbit.report.models import Severity

# ---------------------------------------------------------------------------
# _strip_string_literals
# ---------------------------------------------------------------------------


class TestStripStringLiterals:
    def test_removes_double_quoted(self) -> None:
        result = _strip_string_literals('log.info("password reset complete")')
        assert "password" not in result

    def test_removes_single_quoted(self) -> None:
        result = _strip_string_literals("log.info('password reset complete')")
        assert "password" not in result

    def test_keeps_non_string_content(self) -> None:
        result = _strip_string_literals("log.info(password)")
        assert "password" in result

    def test_handles_escaped_quotes(self) -> None:
        result = _strip_string_literals(r'log.info("it\'s a \"test\"")')
        assert "log.info" in result

    def test_handles_backtick_templates(self) -> None:
        result = _strip_string_literals("console.log(`hello world`)")
        assert "hello" not in result

    def test_preserves_fstring_expressions(self) -> None:
        result = _strip_string_literals('log.info(f"pwd={password}")')
        assert "password" in result

    def test_preserves_js_template_expressions(self) -> None:
        result = _strip_string_literals("console.log(`token=${token}`)")
        assert "token" in result

    def test_empty_string(self) -> None:
        assert _strip_string_literals("") == ""

    def test_no_strings_unchanged(self) -> None:
        line = "log.info(password, secret_key)"
        result = _strip_string_literals(line)
        assert "password" in result
        assert "secret_key" in result


# ---------------------------------------------------------------------------
# _SENSITIVE_RE
# ---------------------------------------------------------------------------


class TestSensitivePattern:
    def test_matches_password(self) -> None:
        assert _SENSITIVE_RE.search("password")

    def test_matches_passwd(self) -> None:
        assert _SENSITIVE_RE.search("passwd")

    def test_matches_api_key(self) -> None:
        assert _SENSITIVE_RE.search("api_key")

    def test_matches_apikey(self) -> None:
        assert _SENSITIVE_RE.search("apikey")

    def test_matches_access_token(self) -> None:
        assert _SENSITIVE_RE.search("access_token")

    def test_matches_refresh_token(self) -> None:
        assert _SENSITIVE_RE.search("refresh_token")

    def test_matches_auth_token(self) -> None:
        assert _SENSITIVE_RE.search("auth_token")

    def test_matches_secret(self) -> None:
        assert _SENSITIVE_RE.search("secret")

    def test_matches_private_key(self) -> None:
        assert _SENSITIVE_RE.search("private_key")

    def test_matches_ssn(self) -> None:
        assert _SENSITIVE_RE.search("ssn")

    def test_matches_credit_card(self) -> None:
        assert _SENSITIVE_RE.search("credit_card")

    def test_matches_cvv(self) -> None:
        assert _SENSITIVE_RE.search("cvv")

    def test_matches_authorization(self) -> None:
        assert _SENSITIVE_RE.search("authorization")

    def test_case_insensitive(self) -> None:
        assert _SENSITIVE_RE.search("PASSWORD")
        assert _SENSITIVE_RE.search("ApiKey")
        assert _SENSITIVE_RE.search("Secret_Key")

    def test_no_match_username(self) -> None:
        assert not _SENSITIVE_RE.search("username")

    def test_no_match_email(self) -> None:
        assert not _SENSITIVE_RE.search("email")

    def test_word_boundary_passport(self) -> None:
        assert not _SENSITIVE_RE.search("passport")

    def test_word_boundary_tokenizer(self) -> None:
        assert not _SENSITIVE_RE.search("tokenizer")


# ---------------------------------------------------------------------------
# _scan_file — Python
# ---------------------------------------------------------------------------


class TestScanFilePython:
    def test_detects_fstring_password(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text('logger.info(f"password={password}")\n')
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "password" in findings[0].title

    def test_detects_format_arg(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text('log.info("pwd: %s", password)\n')
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_detects_direct_variable(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.debug(api_key)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_ignores_string_literal_only(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text('log.info("password reset email sent")\n')
        findings = _scan_file(src, str(tmp_path))
        assert findings == []

    def test_ignores_invalid_password_message(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text('log.warning("Invalid password format")\n')
        findings = _scan_file(src, str(tmp_path))
        assert findings == []

    def test_detects_print_sensitive(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("print(secret_key)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_detects_request_body(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(request.body)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "request body" in findings[0].title.lower()

    def test_detects_req_data(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("logger.debug(req.data)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_skips_comments(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("# log.info(password)\n")
        findings = _scan_file(src, str(tmp_path))
        assert findings == []

    def test_cwe_set(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(password)\n")
        findings = _scan_file(src, str(tmp_path))
        assert findings[0].cwe == "CWE-532"

    def test_multiple_findings_in_file(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(password)\nlog.debug(api_key)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# _scan_file — JavaScript/TypeScript
# ---------------------------------------------------------------------------


class TestScanFileJavaScript:
    def test_console_log_token(self, tmp_path: Path) -> None:
        src = tmp_path / "app.js"
        src.write_text("console.log(access_token)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_console_log_string_only(self, tmp_path: Path) -> None:
        src = tmp_path / "app.js"
        src.write_text('console.log("invalid token format")\n')
        findings = _scan_file(src, str(tmp_path))
        assert findings == []

    def test_template_literal_variable(self, tmp_path: Path) -> None:
        src = tmp_path / "app.js"
        src.write_text("console.log(`token=${token}`)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_console_warn(self, tmp_path: Path) -> None:
        src = tmp_path / "app.ts"
        src.write_text("console.warn(password)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_console_error_string_only(self, tmp_path: Path) -> None:
        src = tmp_path / "app.tsx"
        src.write_text('console.error("Password must be 8 characters")\n')
        findings = _scan_file(src, str(tmp_path))
        assert findings == []


# ---------------------------------------------------------------------------
# _scan_file — Java
# ---------------------------------------------------------------------------


class TestScanFileJava:
    def test_logger_info_password(self, tmp_path: Path) -> None:
        src = tmp_path / "App.java"
        src.write_text('logger.info("Password: " + password);\n')
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_system_out_secret(self, tmp_path: Path) -> None:
        src = tmp_path / "App.java"
        src.write_text("System.out.println(secret);\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# _scan_file — Go
# ---------------------------------------------------------------------------


class TestScanFileGo:
    def test_log_printf_secret(self, tmp_path: Path) -> None:
        src = tmp_path / "main.go"
        src.write_text('log.Printf("secret: %s", secret)\n')
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_fmt_println_token(self, tmp_path: Path) -> None:
        src = tmp_path / "main.go"
        src.write_text("fmt.Println(token)\n")
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1

    def test_slog_info(self, tmp_path: Path) -> None:
        src = tmp_path / "main.go"
        src.write_text('slog.Info("auth", "token", token)\n')
        findings = _scan_file(src, str(tmp_path))
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# _scan_all_files
# ---------------------------------------------------------------------------


class TestScanAllFiles:
    def test_skips_test_directories(self, tmp_path: Path) -> None:
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        (test_dir / "test_app.py").write_text("log.info(password)\n")
        findings = _scan_all_files(str(tmp_path))
        assert findings == []

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("console.log(password)\n")
        findings = _scan_all_files(str(tmp_path))
        assert findings == []

    def test_scans_multiple_file_types(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("log.info(password)\n")
        (tmp_path / "app.js").write_text("console.log(secret)\n")
        findings = _scan_all_files(str(tmp_path))
        assert len(findings) == 2

    def test_empty_repo(self, tmp_path: Path) -> None:
        findings = _scan_all_files(str(tmp_path))
        assert findings == []

    def test_deduplication(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(password)\n")
        findings = _scan_all_files(str(tmp_path))
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# LogLeakScanner integration
# ---------------------------------------------------------------------------


class TestLogLeakScanner:
    def test_no_source_files(self, tmp_path: Path) -> None:
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert result.findings == []

    def test_detects_sensitive_logging(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(password)\nlog.debug(api_key)\n")
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.error is None
        assert len(result.findings) == 2

    def test_clean_code_no_findings(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text(
            'log.info("Server started on port %d", port)\n'
            'log.debug("Processing request from %s", ip_address)\n'
        )
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.findings == []

    def test_severity_high_for_password(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(password)\n")
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.findings[0].severity == Severity.HIGH

    def test_severity_medium_for_token(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(token)\n")
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.findings[0].severity == Severity.MEDIUM

    def test_severity_medium_for_authorization(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(authorization)\n")
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.findings[0].severity == Severity.MEDIUM

    def test_request_body_always_high(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(request.body)\n")
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        assert result.findings[0].severity == Severity.HIGH

    def test_scanner_metadata(self) -> None:
        scanner = LogLeakScanner()
        assert scanner.name == "logleak"
        assert scanner.display_name == "Log Leak Scanner"
        assert scanner.is_available()

    def test_finding_fields(self, tmp_path: Path) -> None:
        src = tmp_path / "app.py"
        src.write_text("log.info(password)\n")
        scanner = LogLeakScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))
        finding = result.findings[0]
        assert finding.scanner == "logleak"
        assert finding.category == "log-leak"
        assert finding.cwe == "CWE-532"
        assert finding.references == ["https://cwe.mitre.org/data/definitions/532.html"]
