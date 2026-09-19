"""Tests for the retire.js JavaScript library scanner."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Severity
from whiterabbit.scanner.retirejs_scanner import (
    RetireJSScanner,
    _check_vulnerabilities,
    _extract_script_urls,
    _extract_version_from_content,
    _extract_version_from_filename,
    _version_in_range,
)


class TestExtractScriptUrls:
    def test_basic_script_tags(self) -> None:
        html = """
        <html>
        <head>
            <script src="js/jquery-3.6.0.min.js"></script>
            <script src="/static/app.js"></script>
        </head>
        </html>
        """
        urls = _extract_script_urls(html, "https://example.com/page")
        assert len(urls) == 2
        assert "https://example.com/js/jquery-3.6.0.min.js" in urls
        assert "https://example.com/static/app.js" in urls

    def test_absolute_urls(self) -> None:
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        urls = _extract_script_urls(html, "https://example.com")
        assert urls == ["https://cdn.example.com/lib.js"]

    def test_double_and_single_quotes(self) -> None:
        html = """
        <script src="a.js"></script>
        <script src='b.js'></script>
        """
        urls = _extract_script_urls(html, "https://example.com/")
        assert len(urls) == 2

    def test_skip_data_and_javascript_urls(self) -> None:
        html = """
        <script src="data:text/javascript,alert(1)"></script>
        <script src="javascript:void(0)"></script>
        <script src="real.js"></script>
        """
        urls = _extract_script_urls(html, "https://example.com/")
        assert len(urls) == 1
        assert "real.js" in urls[0]

    def test_no_scripts(self) -> None:
        html = "<html><body>No scripts here</body></html>"
        urls = _extract_script_urls(html, "https://example.com")
        assert urls == []


class TestVersionInRange:
    def test_below_only(self) -> None:
        assert _version_in_range("1.5.0", below="2.0.0") is True
        assert _version_in_range("2.0.0", below="2.0.0") is False
        assert _version_in_range("2.1.0", below="2.0.0") is False

    def test_at_or_above_and_below(self) -> None:
        assert _version_in_range("1.5.0", at_or_above="1.0.0", below="2.0.0") is True
        assert _version_in_range("0.9.0", at_or_above="1.0.0", below="2.0.0") is False
        assert _version_in_range("2.0.0", at_or_above="1.0.0", below="2.0.0") is False

    def test_above_and_below(self) -> None:
        assert _version_in_range("1.5.0", above="1.0.0", below="2.0.0") is True
        assert _version_in_range("1.0.0", above="1.0.0", below="2.0.0") is False

    def test_no_constraints(self) -> None:
        assert _version_in_range("1.0.0") is True

    def test_complex_version(self) -> None:
        assert _version_in_range("3.6.0", below="3.7.0") is True
        assert _version_in_range("3.7.0", below="3.7.0") is False


class TestExtractVersionFromFilename:
    def test_uri_pattern(self) -> None:
        extractors = {
            "uri": [r"jquery-(\d+\.\d+\.\d+)"],
        }
        v = _extract_version_from_filename(
            "https://example.com/jquery-3.6.0.min.js", extractors
        )
        assert v == "3.6.0"

    def test_filename_pattern(self) -> None:
        extractors = {
            "filename": [r"bootstrap-(\d+\.\d+\.\d+)"],
        }
        v = _extract_version_from_filename(
            "https://example.com/bootstrap-5.2.3.js", extractors
        )
        assert v == "5.2.3"

    def test_no_match(self) -> None:
        extractors = {
            "uri": [r"jquery-(\d+\.\d+\.\d+)"],
        }
        v = _extract_version_from_filename("https://example.com/app.js", extractors)
        assert v is None

    def test_no_extractors(self) -> None:
        v = _extract_version_from_filename("https://example.com/jquery-3.6.0.js", {})
        assert v is None


class TestExtractVersionFromContent:
    def test_filecontent_match(self) -> None:
        extractors = {
            "filecontent": [r"jQuery v(\d+\.\d+\.\d+)"],
        }
        content = "/*! jQuery v3.6.0 | MIT License */"
        v = _extract_version_from_content(content, extractors)
        assert v == "3.6.0"

    def test_no_filecontent(self) -> None:
        v = _extract_version_from_content("some content", {})
        assert v is None

    def test_no_match(self) -> None:
        extractors = {
            "filecontent": [r"jQuery v(\d+\.\d+\.\d+)"],
        }
        v = _extract_version_from_content("no version here", extractors)
        assert v is None


class TestCheckVulnerabilities:
    def test_vulnerable_version(self) -> None:
        vulns = [
            {
                "below": "3.5.0",
                "severity": "high",
                "identifiers": {
                    "CVE": ["CVE-2020-11022"],
                    "summary": "XSS vulnerability in jQuery",
                },
                "info": ["https://cve.example.com"],
            },
        ]
        findings = _check_vulnerabilities("jquery", "3.4.1", vulns)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cve == "CVE-2020-11022"
        assert "jquery" in findings[0].title.lower()

    def test_safe_version(self) -> None:
        vulns = [{"below": "3.5.0", "severity": "high", "identifiers": {}}]
        findings = _check_vulnerabilities("jquery", "3.6.0", vulns)
        assert len(findings) == 0

    def test_ranged_vulnerability(self) -> None:
        vulns = [
            {
                "atOrAbove": "1.0.0",
                "below": "2.0.0",
                "severity": "medium",
                "identifiers": {},
            },
        ]
        assert len(_check_vulnerabilities("lib", "1.5.0", vulns)) == 1
        assert len(_check_vulnerabilities("lib", "0.9.0", vulns)) == 0
        assert len(_check_vulnerabilities("lib", "2.0.0", vulns)) == 0

    def test_no_cve(self) -> None:
        vulns = [{"below": "2.0.0", "severity": "low", "identifiers": {}}]
        findings = _check_vulnerabilities("lib", "1.0.0", vulns)
        assert len(findings) == 1
        assert findings[0].cve is None

    def test_multiple_vulns(self) -> None:
        vulns = [
            {"below": "3.0.0", "severity": "high", "identifiers": {"CVE": ["CVE-1"]}},
            {"below": "3.0.0", "severity": "medium", "identifiers": {"CVE": ["CVE-2"]}},
        ]
        findings = _check_vulnerabilities("lib", "2.5.0", vulns)
        assert len(findings) == 2


MOCK_VULN_DB = {
    "jquery": {
        "extractors": {
            "uri": [r"/jquery-(\d+\.\d+\.\d+)"],
            "filecontent": [r"jQuery\s+v(\d+\.\d+\.\d+)"],
        },
        "vulnerabilities": [
            {
                "below": "3.5.0",
                "severity": "high",
                "identifiers": {
                    "CVE": ["CVE-2020-11022"],
                    "summary": "XSS in jQuery.htmlPrefilter",
                },
                "info": [
                    "https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2"
                ],
            },
        ],
    },
}


class TestRetireJSScanner:
    def test_scanner_attributes(self) -> None:
        scanner = RetireJSScanner()
        assert scanner.name == "retirejs"
        assert scanner.display_name == "JavaScript Library Scanner"
        assert scanner.required_binaries == []

    def test_finds_vulnerable_jquery(self) -> None:
        html = '<html><head><script src="/js/jquery-3.4.1.min.js"></script></head><body></body></html>'

        responses = {
            "https://example.com": httpx.Response(
                200, text=html, request=httpx.Request("GET", "https://example.com")
            ),
        }

        async def mock_get(url, **kwargs):
            if isinstance(url, str) and url in responses:
                return responses[url]
            return httpx.Response(
                200, text=json.dumps(MOCK_VULN_DB), request=httpx.Request("GET", url)
            )

        with (
            patch(
                "whiterabbit.scanner.retirejs_scanner._cache_is_fresh",
                return_value=False,
            ),
            patch(
                "whiterabbit.scanner.retirejs_scanner.httpx.AsyncClient"
            ) as mock_client_cls,
        ):
            client_instance = AsyncMock()
            client_instance.get = mock_get
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            scanner = RetireJSScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.severity == Severity.HIGH
        assert "jquery" in finding.title.lower()
        assert finding.cve == "CVE-2020-11022"

    def test_no_vulnerable_libs(self) -> None:
        html = (
            '<html><head><script src="/js/app.js"></script></head><body></body></html>'
        )

        async def mock_get(url, **kwargs):
            if "example.com" in str(url) and "jsrepository" not in str(url):
                return httpx.Response(
                    200, text=html, request=httpx.Request("GET", str(url))
                )
            return httpx.Response(
                200,
                text=json.dumps(MOCK_VULN_DB),
                request=httpx.Request("GET", str(url)),
            )

        with (
            patch(
                "whiterabbit.scanner.retirejs_scanner._cache_is_fresh",
                return_value=False,
            ),
            patch(
                "whiterabbit.scanner.retirejs_scanner.httpx.AsyncClient"
            ) as mock_client_cls,
        ):
            client_instance = AsyncMock()
            client_instance.get = mock_get
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            scanner = RetireJSScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert len(result.findings) == 0

    def test_timeout_error(self) -> None:
        with patch(
            "whiterabbit.scanner.retirejs_scanner.httpx.AsyncClient"
        ) as mock_client_cls:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch(
                "whiterabbit.scanner.retirejs_scanner._cache_is_fresh",
                return_value=False,
            ):
                scanner = RetireJSScanner()
                result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "timed out" in result.error

    def test_general_exception(self) -> None:
        with patch(
            "whiterabbit.scanner.retirejs_scanner.httpx.AsyncClient"
        ) as mock_client_cls:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(side_effect=RuntimeError("network error"))
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch(
                "whiterabbit.scanner.retirejs_scanner._cache_is_fresh",
                return_value=False,
            ):
                scanner = RetireJSScanner()
                result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is not None
        assert "network error" in result.error

    def test_content_based_detection(self) -> None:
        html = "<html><head></head><body><script>/*! jQuery v3.4.1 | MIT */</script></body></html>"

        async def mock_get(url, **kwargs):
            if "example.com" in str(url) and "jsrepository" not in str(url):
                return httpx.Response(
                    200, text=html, request=httpx.Request("GET", str(url))
                )
            return httpx.Response(
                200,
                text=json.dumps(MOCK_VULN_DB),
                request=httpx.Request("GET", str(url)),
            )

        with (
            patch(
                "whiterabbit.scanner.retirejs_scanner._cache_is_fresh",
                return_value=False,
            ),
            patch(
                "whiterabbit.scanner.retirejs_scanner.httpx.AsyncClient"
            ) as mock_client_cls,
        ):
            client_instance = AsyncMock()
            client_instance.get = mock_get
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            scanner = RetireJSScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        vuln_findings = [
            f
            for f in result.findings
            if f.category == "js-vuln" and "jquery" in f.title.lower()
        ]
        assert len(vuln_findings) >= 1

    def test_deduplication(self) -> None:
        html = """<html><head>
            <script src="/js/jquery-3.4.1.min.js"></script>
        </head><body>
            <script>/*! jQuery v3.4.1 | MIT */</script>
        </body></html>"""

        async def mock_get(url, **kwargs):
            if "example.com" in str(url) and "jsrepository" not in str(url):
                return httpx.Response(
                    200, text=html, request=httpx.Request("GET", str(url))
                )
            return httpx.Response(
                200,
                text=json.dumps(MOCK_VULN_DB),
                request=httpx.Request("GET", str(url)),
            )

        with (
            patch(
                "whiterabbit.scanner.retirejs_scanner._cache_is_fresh",
                return_value=False,
            ),
            patch(
                "whiterabbit.scanner.retirejs_scanner.httpx.AsyncClient"
            ) as mock_client_cls,
        ):
            client_instance = AsyncMock()
            client_instance.get = mock_get
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            scanner = RetireJSScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        jquery_findings = [f for f in result.findings if "jquery" in f.title.lower()]
        assert len(jquery_findings) == 1

    def test_target_normalization(self) -> None:
        html = "<html></html>"

        async def mock_get(url, **kwargs):
            if "example.com" in str(url) and "jsrepository" not in str(url):
                return httpx.Response(
                    200, text=html, request=httpx.Request("GET", str(url))
                )
            return httpx.Response(
                200,
                text=json.dumps(MOCK_VULN_DB),
                request=httpx.Request("GET", str(url)),
            )

        with (
            patch(
                "whiterabbit.scanner.retirejs_scanner._cache_is_fresh",
                return_value=False,
            ),
            patch(
                "whiterabbit.scanner.retirejs_scanner.httpx.AsyncClient"
            ) as mock_client_cls,
        ):
            client_instance = AsyncMock()
            client_instance.get = mock_get
            mock_client_cls.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            scanner = RetireJSScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert result.target == "example.com"
