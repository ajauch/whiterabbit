"""Tests for the HTTP security headers scanner."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Severity
from whiterabbit.scanner.header_scanner import (
    HeaderScanner,
    _check_cookies,
    _check_coop,
    _check_corp,
    _check_cors,
    _check_csp,
    _check_git_exposure,
    _check_hsts,
    _check_permissions_policy,
    _check_referrer_policy,
    _check_server_header,
    _check_trace_method,
    _check_x_content_type_options,
    _check_x_frame_options,
    _check_x_powered_by,
)


def _make_headers(header_dict: dict[str, str]) -> httpx.Headers:
    return httpx.Headers(header_dict)


class TestCheckHSTS:
    def test_missing_hsts(self) -> None:
        findings = _check_hsts(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "HSTS" in findings[0].title
        assert findings[0].asvs == "v5.0.0-3.4.1"

    def test_present_hsts(self) -> None:
        findings = _check_hsts(
            _make_headers(
                {"strict-transport-security": "max-age=31536000; includeSubDomains"}
            )
        )
        assert len(findings) == 0

    def test_short_max_age(self) -> None:
        findings = _check_hsts(
            _make_headers({"strict-transport-security": "max-age=3600"})
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "3600" in findings[0].title
        assert findings[0].asvs == "v5.0.0-3.4.1"


class TestCheckCSP:
    def test_missing_csp(self) -> None:
        findings = _check_csp(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].asvs == "v5.0.0-3.4.3"

    def test_present_csp_with_report(self) -> None:
        findings = _check_csp(
            _make_headers(
                {
                    "content-security-policy": "default-src 'self'; report-uri /csp-report"
                }
            )
        )
        assert len(findings) == 0

    def test_present_csp_no_report(self) -> None:
        findings = _check_csp(
            _make_headers({"content-security-policy": "default-src 'self'"})
        )
        assert len(findings) == 1
        assert findings[0].asvs == "v5.0.0-3.4.7"
        assert "reporting" in findings[0].title.lower()

    def test_csp_with_report_to(self) -> None:
        findings = _check_csp(
            _make_headers(
                {
                    "content-security-policy": "default-src 'self'; report-to csp-endpoint"
                }
            )
        )
        assert len(findings) == 0

    def test_unsafe_inline(self) -> None:
        findings = _check_csp(
            _make_headers(
                {
                    "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; report-uri /r"
                }
            )
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "unsafe-inline" in findings[0].title

    def test_unsafe_eval(self) -> None:
        findings = _check_csp(
            _make_headers(
                {
                    "content-security-policy": "default-src 'self'; script-src 'unsafe-eval'; report-uri /r"
                }
            )
        )
        assert len(findings) == 1
        assert "unsafe-eval" in findings[0].title

    def test_both_unsafe(self) -> None:
        findings = _check_csp(
            _make_headers(
                {
                    "content-security-policy": "script-src 'unsafe-inline' 'unsafe-eval'; report-uri /r"
                }
            )
        )
        assert len(findings) == 2


class TestCheckXContentTypeOptions:
    def test_missing(self) -> None:
        findings = _check_x_content_type_options(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].asvs == "v5.0.0-3.4.4"

    def test_present(self) -> None:
        findings = _check_x_content_type_options(
            _make_headers({"x-content-type-options": "nosniff"})
        )
        assert len(findings) == 0

    def test_wrong_value(self) -> None:
        findings = _check_x_content_type_options(
            _make_headers({"x-content-type-options": "none"})
        )
        assert len(findings) == 1


class TestCheckXFrameOptions:
    def test_missing_both(self) -> None:
        findings = _check_x_frame_options(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].asvs == "v5.0.0-3.4.6"

    def test_xfo_present(self) -> None:
        findings = _check_x_frame_options(_make_headers({"x-frame-options": "DENY"}))
        assert len(findings) == 0

    def test_csp_frame_ancestors(self) -> None:
        findings = _check_x_frame_options(
            _make_headers({"content-security-policy": "frame-ancestors 'none'"})
        )
        assert len(findings) == 0


class TestCheckReferrerPolicy:
    def test_missing(self) -> None:
        findings = _check_referrer_policy(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].asvs == "v5.0.0-3.4.5"

    def test_present(self) -> None:
        findings = _check_referrer_policy(
            _make_headers({"referrer-policy": "strict-origin-when-cross-origin"})
        )
        assert len(findings) == 0


class TestCheckPermissionsPolicy:
    def test_missing(self) -> None:
        findings = _check_permissions_policy(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_present(self) -> None:
        findings = _check_permissions_policy(
            _make_headers({"permissions-policy": "camera=(), microphone=()"})
        )
        assert len(findings) == 0


class TestCheckServerHeader:
    def test_no_server(self) -> None:
        findings = _check_server_header(_make_headers({}))
        assert len(findings) == 0

    def test_server_without_version(self) -> None:
        findings = _check_server_header(_make_headers({"server": "nginx"}))
        assert len(findings) == 0

    def test_server_with_version(self) -> None:
        findings = _check_server_header(_make_headers({"server": "nginx/1.24.0"}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "nginx/1.24.0" in findings[0].title
        assert findings[0].asvs == "v5.0.0-13.4.6"


class TestCheckXPoweredBy:
    def test_missing(self) -> None:
        findings = _check_x_powered_by(_make_headers({}))
        assert len(findings) == 0

    def test_present(self) -> None:
        findings = _check_x_powered_by(_make_headers({"x-powered-by": "Express"}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "Express" in findings[0].title
        assert findings[0].asvs == "v5.0.0-13.4.6"


class TestCheckCOOP:
    def test_missing(self) -> None:
        findings = _check_coop(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].asvs == "v5.0.0-3.4.8"

    def test_present(self) -> None:
        findings = _check_coop(
            _make_headers({"cross-origin-opener-policy": "same-origin"})
        )
        assert len(findings) == 0


class TestCheckCORP:
    def test_missing(self) -> None:
        findings = _check_corp(_make_headers({}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_present(self) -> None:
        findings = _check_corp(
            _make_headers({"cross-origin-resource-policy": "same-origin"})
        )
        assert len(findings) == 0


class TestCheckCORS:
    def test_no_cors(self) -> None:
        findings = _check_cors(_make_headers({}))
        assert len(findings) == 0

    def test_specific_origin(self) -> None:
        findings = _check_cors(
            _make_headers({"access-control-allow-origin": "https://example.com"})
        )
        assert len(findings) == 0

    def test_wildcard(self) -> None:
        findings = _check_cors(_make_headers({"access-control-allow-origin": "*"}))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].asvs == "v5.0.0-3.4.2"


class TestCheckCookies:
    def _make_response(self, cookies: list[str]) -> httpx.Response:
        response = MagicMock(spec=httpx.Response)
        response.headers = httpx.Headers([(b"set-cookie", c.encode()) for c in cookies])
        return response

    def test_no_cookies(self) -> None:
        response = self._make_response([])
        findings = _check_cookies(response)
        assert len(findings) == 0

    def test_secure_cookie(self) -> None:
        response = self._make_response(["sid=abc; Secure; HttpOnly; SameSite=Lax"])
        findings = _check_cookies(response)
        assert len(findings) == 0

    def test_missing_secure(self) -> None:
        response = self._make_response(["sid=abc; HttpOnly; SameSite=Lax"])
        findings = _check_cookies(response)
        secure_findings = [f for f in findings if "Secure" in f.title]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == Severity.HIGH
        assert secure_findings[0].asvs == "v5.0.0-3.3.1"

    def test_missing_httponly(self) -> None:
        response = self._make_response(["sid=abc; Secure; SameSite=Lax"])
        findings = _check_cookies(response)
        httponly_findings = [f for f in findings if "HttpOnly" in f.title]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == Severity.MEDIUM
        assert httponly_findings[0].asvs == "v5.0.0-3.3.4"

    def test_missing_samesite(self) -> None:
        response = self._make_response(["sid=abc; Secure; HttpOnly"])
        findings = _check_cookies(response)
        samesite_findings = [f for f in findings if "SameSite" in f.title]
        assert len(samesite_findings) == 1
        assert samesite_findings[0].severity == Severity.MEDIUM
        assert samesite_findings[0].asvs == "v5.0.0-3.3.2"

    def test_completely_insecure_cookie(self) -> None:
        response = self._make_response(["sid=abc"])
        findings = _check_cookies(response)
        assert len(findings) == 3

    def test_multiple_cookies(self) -> None:
        response = self._make_response(
            [
                "sid=abc; Secure; HttpOnly; SameSite=Lax",
                "prefs=dark",
            ]
        )
        findings = _check_cookies(response)
        assert len(findings) == 3


class TestCheckTraceMethod:
    def test_trace_enabled(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_client.request = AsyncMock(return_value=mock_response)

        findings = asyncio.run(_check_trace_method("https://example.com", mock_client))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "TRACE" in findings[0].title
        assert findings[0].asvs == "v5.0.0-13.4.4"

    def test_trace_disabled(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 405
        mock_client.request = AsyncMock(return_value=mock_response)

        findings = asyncio.run(_check_trace_method("https://example.com", mock_client))
        assert len(findings) == 0

    def test_trace_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.ConnectError("fail"))

        findings = asyncio.run(_check_trace_method("https://example.com", mock_client))
        assert len(findings) == 0


class TestCheckGitExposure:
    def test_git_exposed(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.text = "ref: refs/heads/main\n"
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = asyncio.run(_check_git_exposure("https://example.com", mock_client))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert ".git" in findings[0].title
        assert findings[0].asvs == "v5.0.0-13.4.1"

    def test_git_not_exposed(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 404
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = asyncio.run(_check_git_exposure("https://example.com", mock_client))
        assert len(findings) == 0

    def test_git_200_but_not_git(self) -> None:
        mock_client = AsyncMock()
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.text = "<html>Not Found</html>"
        mock_client.get = AsyncMock(return_value=mock_response)

        findings = asyncio.run(_check_git_exposure("https://example.com", mock_client))
        assert len(findings) == 0

    def test_git_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("fail"))

        findings = asyncio.run(_check_git_exposure("https://example.com", mock_client))
        assert len(findings) == 0


class TestHeaderScannerEndToEnd:
    def test_good_site(self) -> None:
        good_headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'; report-uri /csp",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
        }

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.headers = httpx.Headers(good_headers)

        mock_redirect = MagicMock(spec=httpx.Response)
        mock_redirect.status_code = 301
        mock_redirect.headers = httpx.Headers({"location": "https://example.com/"})

        mock_trace = MagicMock(spec=httpx.Response)
        mock_trace.status_code = 405

        mock_git = MagicMock(spec=httpx.Response)
        mock_git.status_code = 404

        async def mock_get(url: str, **kwargs: object) -> MagicMock:
            if url.startswith("http://"):
                return mock_redirect
            if "/.git/HEAD" in url:
                return mock_git
            return mock_response

        async def mock_request(method: str, url: str, **kwargs: object) -> MagicMock:
            return mock_trace

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.request = mock_request
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.scanner.header_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = HeaderScanner()
            result = asyncio.run(scanner.scan("https://example.com", ScanConfig()))
            assert result.error is None
            assert len(result.findings) == 0

    def test_bad_site(self) -> None:
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.headers = httpx.Headers({})

        mock_redirect = MagicMock(spec=httpx.Response)
        mock_redirect.status_code = 200
        mock_redirect.headers = httpx.Headers({})

        mock_trace = MagicMock(spec=httpx.Response)
        mock_trace.status_code = 200

        mock_git = MagicMock(spec=httpx.Response)
        mock_git.status_code = 200
        mock_git.text = "ref: refs/heads/main\n"

        async def mock_get(url: str, **kwargs: object) -> MagicMock:
            if url.startswith("http://"):
                return mock_redirect
            if "/.git/HEAD" in url:
                return mock_git
            return mock_response

        async def mock_request(method: str, url: str, **kwargs: object) -> MagicMock:
            return mock_trace

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.request = mock_request
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.scanner.header_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = HeaderScanner()
            result = asyncio.run(scanner.scan("https://example.com", ScanConfig()))
            assert result.error is None
            # Original 8 + CSP report-uri + TRACE + .git = 11
            assert len(result.findings) >= 10

    def test_connection_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "whiterabbit.scanner.header_scanner.httpx.AsyncClient",
            return_value=mock_client,
        ):
            scanner = HeaderScanner()
            result = asyncio.run(scanner.scan("https://nope.invalid", ScanConfig()))
            assert result.error is not None
