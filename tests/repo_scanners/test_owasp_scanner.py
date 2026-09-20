"""Tests for the OWASP SAST scanner."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.owasp_scanner import (
    OWASPScanner,
    _build_command,
    _gha_expr_is_untrusted,
    _has_untrusted_gha_expression,
    _parse_semgrep_output,
)
from whiterabbit.report.models import Severity


class TestBuildCommand:
    def test_default_command(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.resolve_binary",
            return_value="/usr/bin/semgrep",
        ):
            cmd = _build_command("/tmp/repo", 300)
        assert cmd[0] == "/usr/bin/semgrep"
        assert "--config" in cmd
        assert "p/owasp-top-ten" in cmd
        assert "--json" in cmd
        assert "--quiet" in cmd
        assert "/tmp/repo" in cmd

    def test_timeout_in_command(self) -> None:
        cmd = _build_command("/tmp/repo", 600)
        idx = cmd.index("--timeout")
        assert cmd[idx + 1] == "600"


class TestParseSemgrepOutput:
    def test_single_finding(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.django.security.injection.sql-injection",
                        "path": "app/views.py",
                        "start": {"line": 42, "col": 1},
                        "end": {"line": 42, "col": 50},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Detected SQL injection vulnerability.",
                            "metadata": {
                                "cwe": ["CWE-89"],
                                "owasp": ["A03:2021 Injection"],
                                "references": [
                                    "https://owasp.org/Top10/A03_2021-Injection/"
                                ],
                            },
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.category == "sast-owasp"
        assert f.scanner == "owasp"
        assert f.cwe == "CWE-89"
        assert "sql injection" in f.title.lower()
        assert "app/views.py:42" in f.title

    def test_multiple_findings(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule1",
                        "path": "a.py",
                        "start": {"line": 1},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Bug 1",
                            "metadata": {},
                        },
                    },
                    {
                        "check_id": "rule2",
                        "path": "b.py",
                        "start": {"line": 2},
                        "extra": {
                            "severity": "WARNING",
                            "message": "Bug 2",
                            "metadata": {},
                        },
                    },
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert len(findings) == 2
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.MEDIUM

    def test_deduplication(self) -> None:
        result = {
            "check_id": "rule1",
            "path": "a.py",
            "start": {"line": 1},
            "extra": {"severity": "INFO", "message": "Dup", "metadata": {}},
        }
        output = json.dumps({"results": [result, result]})
        findings = _parse_semgrep_output(output)
        assert len(findings) == 1

    def test_empty_results(self) -> None:
        output = json.dumps({"results": []})
        findings = _parse_semgrep_output(output)
        assert findings == []

    def test_invalid_json(self) -> None:
        findings = _parse_semgrep_output("not json")
        assert findings == []

    def test_info_severity(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule1",
                        "path": "a.py",
                        "start": {"line": 1},
                        "extra": {
                            "severity": "INFO",
                            "message": "Info",
                            "metadata": {},
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert findings[0].severity == Severity.LOW

    def test_owasp_tag_in_title(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.xss-detected",
                        "path": "app.py",
                        "start": {"line": 10},
                        "extra": {
                            "severity": "ERROR",
                            "message": "XSS",
                            "metadata": {"owasp": ["A07:2017 XSS"]},
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert "A07:2017" in findings[0].title


class TestGHAExprIsTrusted:
    """Tests for GitHub Actions shell-injection false-positive filtering."""

    def test_trusted_sha(self) -> None:
        assert not _gha_expr_is_untrusted("github.sha")

    def test_trusted_ref(self) -> None:
        assert not _gha_expr_is_untrusted("github.ref")

    def test_trusted_secrets(self) -> None:
        assert not _gha_expr_is_untrusted("secrets.GITHUB_TOKEN")

    def test_trusted_steps_output(self) -> None:
        assert not _gha_expr_is_untrusted("steps.build.outputs.version")

    def test_trusted_env(self) -> None:
        assert not _gha_expr_is_untrusted("env.MY_VAR")

    def test_trusted_matrix(self) -> None:
        assert not _gha_expr_is_untrusted("matrix.os")

    def test_trusted_runner(self) -> None:
        assert not _gha_expr_is_untrusted("runner.os")

    def test_trusted_inputs(self) -> None:
        assert not _gha_expr_is_untrusted("inputs.version")

    def test_untrusted_pr_title(self) -> None:
        assert _gha_expr_is_untrusted("github.event.pull_request.title")

    def test_untrusted_pr_body(self) -> None:
        assert _gha_expr_is_untrusted("github.event.pull_request.body")

    def test_untrusted_issue_title(self) -> None:
        assert _gha_expr_is_untrusted("github.event.issue.title")

    def test_untrusted_issue_body(self) -> None:
        assert _gha_expr_is_untrusted("github.event.issue.body")

    def test_untrusted_comment_body(self) -> None:
        assert _gha_expr_is_untrusted("github.event.comment.body")

    def test_untrusted_head_ref(self) -> None:
        assert _gha_expr_is_untrusted("github.head_ref")

    def test_untrusted_head_commit_message(self) -> None:
        assert _gha_expr_is_untrusted("github.event.head_commit.message")

    def test_untrusted_discussion_title(self) -> None:
        assert _gha_expr_is_untrusted("github.event.discussion.title")

    def test_untrusted_commits_array(self) -> None:
        assert _gha_expr_is_untrusted("github.event.commits[0].message")

    def test_untrusted_pr_head_ref(self) -> None:
        assert _gha_expr_is_untrusted("github.event.pull_request.head.ref")

    def test_untrusted_review_body(self) -> None:
        assert _gha_expr_is_untrusted("github.event.review.body")

    def test_untrusted_review_comment_body(self) -> None:
        assert _gha_expr_is_untrusted("github.event.review_comment.body")

    def test_untrusted_nested_in_format(self) -> None:
        assert _gha_expr_is_untrusted("format('{0}', github.event.pull_request.title)")


class TestHasUntrustedGHAExpression:
    def test_trusted_only(self) -> None:
        source = 'echo "${{ github.sha }}" && echo "${{ env.FOO }}"'
        assert not _has_untrusted_gha_expression(source)

    def test_untrusted_present(self) -> None:
        source = 'echo "${{ github.event.issue.title }}"'
        assert _has_untrusted_gha_expression(source)

    def test_mixed_trusted_and_untrusted(self) -> None:
        source = 'echo "${{ github.sha }}" "${{ github.event.comment.body }}"'
        assert _has_untrusted_gha_expression(source)

    def test_no_expressions(self) -> None:
        source = "echo hello world"
        assert not _has_untrusted_gha_expression(source)

    def test_multiline_source(self) -> None:
        source = (
            "echo ${{ github.sha }}\n"
            "echo ${{ steps.check.outputs.result }}\n"
            "echo ${{ runner.os }}"
        )
        assert not _has_untrusted_gha_expression(source)

    def test_expression_with_spaces(self) -> None:
        source = "echo ${{  github.event.pull_request.body  }}"
        assert _has_untrusted_gha_expression(source)


class TestParseGHAFiltering:
    """Verify _parse_semgrep_output drops/keeps GHA shell injection findings."""

    def _gha_result(
        self,
        lines: str,
        check_id: str = "yaml.github-actions.security.run-shell-injection.run-shell-injection",
    ) -> str:
        return json.dumps(
            {
                "results": [
                    {
                        "check_id": check_id,
                        "path": ".github/workflows/ci.yml",
                        "start": {"line": 10},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Untrusted input in run step.",
                            "lines": lines,
                            "metadata": {
                                "owasp": ["A01:2017 - Injection"],
                            },
                        },
                    }
                ]
            }
        )

    def test_drops_trusted_gha_finding(self) -> None:
        output = self._gha_result('run: echo "${{ github.sha }}"')
        findings = _parse_semgrep_output(output)
        assert len(findings) == 0

    def test_keeps_untrusted_gha_finding(self) -> None:
        output = self._gha_result('run: echo "${{ github.event.pull_request.title }}"')
        findings = _parse_semgrep_output(output)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_keeps_finding_when_lines_missing(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "yaml.github-actions.security.run-shell-injection.run-shell-injection",
                        "path": ".github/workflows/ci.yml",
                        "start": {"line": 10},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Untrusted input in run step.",
                            "metadata": {},
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert len(findings) == 1

    def test_does_not_filter_non_gha_rules(self) -> None:
        output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "python.django.security.injection.sql-injection",
                        "path": "app/views.py",
                        "start": {"line": 5},
                        "extra": {
                            "severity": "ERROR",
                            "message": "SQL injection.",
                            "lines": 'echo "${{ github.sha }}"',
                            "metadata": {},
                        },
                    }
                ]
            }
        )
        findings = _parse_semgrep_output(output)
        assert len(findings) == 1

    def test_drops_steps_output_in_gha(self) -> None:
        output = self._gha_result('run: echo "${{ steps.build.outputs.artifact_url }}"')
        findings = _parse_semgrep_output(output)
        assert len(findings) == 0

    def test_drops_env_and_matrix_in_gha(self) -> None:
        output = self._gha_result(
            'run: echo "${{ env.CI }}" "${{ matrix.node-version }}"'
        )
        findings = _parse_semgrep_output(output)
        assert len(findings) == 0


class TestOWASPScanner:
    def test_is_available_without_semgrep(self) -> None:
        with patch("whiterabbit.repo_scanner.base.resolve_binary", return_value=None):
            scanner = OWASPScanner()
            assert not scanner.is_available()

    def test_is_available_with_semgrep(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.base.resolve_binary",
            return_value="/usr/bin/semgrep",
        ):
            scanner = OWASPScanner()
            assert scanner.is_available()

    def test_successful_scan(self) -> None:
        semgrep_output = json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule1",
                        "path": "app.py",
                        "start": {"line": 5},
                        "extra": {
                            "severity": "WARNING",
                            "message": "Found issue",
                            "metadata": {},
                        },
                    }
                ]
            }
        )

        proc = AsyncMock()
        proc.returncode = 1
        proc.communicate = AsyncMock(return_value=(semgrep_output.encode(), b""))

        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity == Severity.MEDIUM

    def test_semgrep_not_found(self) -> None:
        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
            side_effect=FileNotFoundError,
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "semgrep not found" in result.error

    def test_semgrep_error_exit(self) -> None:
        proc = AsyncMock()
        proc.returncode = 2
        proc.communicate = AsyncMock(return_value=(b"", b"error"))

        with patch(
            "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
            return_value=proc,
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "Semgrep exited with code 2" in result.error

    def test_timeout(self) -> None:
        proc = AsyncMock()
        proc.communicate = AsyncMock(side_effect=TimeoutError)

        with (
            patch(
                "whiterabbit.repo_scanner.owasp_scanner.asyncio.create_subprocess_exec",
                return_value=proc,
            ),
            patch(
                "whiterabbit.repo_scanner.owasp_scanner.asyncio.wait_for",
                side_effect=TimeoutError,
            ),
        ):
            scanner = OWASPScanner()
            config = RepoScanConfig()
            result = asyncio.run(scanner.scan("/tmp/repo", config))
            assert result.error is not None
            assert "timed out" in result.error
