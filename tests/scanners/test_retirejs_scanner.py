"""Tests for the retire.js JavaScript library scanner."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Severity
from whiterabbit.scanner import retirejs_scanner
from whiterabbit.scanner.retirejs_scanner import (
    RetireJSScanner,
    _check_vulnerabilities,
    _extract_script_urls,
    _extract_version_from_content,
    _extract_version_from_filename,
    _version_in_range,
)


@pytest.fixture(autouse=True)
def db_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache_dir = tmp_path / "cache"
    cache_file = cache_dir / "jsrepository.json"
    monkeypatch.setattr(retirejs_scanner, "DB_CACHE_DIR", cache_dir)
    monkeypatch.setattr(retirejs_scanner, "DB_CACHE_FILE", cache_file)
    return cache_file


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
    @pytest.mark.parametrize("cache_state", ["missing", "stale", "fresh"])
    def test_database_and_target_tls_verification(
        self,
        cache_state: str,
        db_cache: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        if cache_state != "missing":
            db_cache.parent.mkdir()
            db_cache.write_text(json.dumps(MOCK_VULN_DB), encoding="utf-8")
            if cache_state == "stale":
                expired = time.time() - retirejs_scanner.DB_MAX_AGE_SECONDS - 60
                os.utime(db_cache, (expired, expired))

        requests: list[tuple[str, bool]] = []
        real_client = httpx.AsyncClient

        def mock_client(**kwargs):
            verify = kwargs.get("verify", True)

            def handle(request: httpx.Request) -> httpx.Response:
                url = str(request.url)
                requests.append((url, verify))
                if url == retirejs_scanner.RETIREJS_DB_URL:
                    return httpx.Response(200, json=MOCK_VULN_DB)
                assert url == "https://example.com"
                return httpx.Response(
                    200, text='<script src="/jquery-3.4.1.min.js"></script>'
                )

            return real_client(**kwargs, transport=httpx.MockTransport(handle))

        monkeypatch.setattr(retirejs_scanner.httpx, "AsyncClient", mock_client)
        result = asyncio.run(RetireJSScanner().scan("example.com", ScanConfig()))

        assert result.error is None
        assert any(f.cve == "CVE-2020-11022" for f in result.findings)
        expected_requests = []
        if cache_state != "fresh":
            expected_requests.append((retirejs_scanner.RETIREJS_DB_URL, True))
        expected_requests.append(("https://example.com", False))
        assert requests == expected_requests
        assert json.loads(db_cache.read_text(encoding="utf-8")) == MOCK_VULN_DB

    @pytest.mark.parametrize("stale_cache", [False, True])
    def test_database_tls_error_stops_scan_without_unverified_retry(
        self,
        stale_cache: bool,
        db_cache: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        if stale_cache:
            db_cache.parent.mkdir()
            db_cache.write_text(json.dumps(MOCK_VULN_DB), encoding="utf-8")
            expired = time.time() - retirejs_scanner.DB_MAX_AGE_SECONDS - 60
            os.utime(db_cache, (expired, expired))
            cached_mtime = db_cache.stat().st_mtime

        requests: list[tuple[str, bool]] = []
        real_client = httpx.AsyncClient

        def mock_client(**kwargs):
            verify = kwargs.get("verify", True)

            def handle(request: httpx.Request) -> httpx.Response:
                url = str(request.url)
                requests.append((url, verify))
                if url == retirejs_scanner.RETIREJS_DB_URL:
                    if verify:
                        raise httpx.ConnectError(
                            "[SSL: CERTIFICATE_VERIFY_FAILED]", request=request
                        )
                    return httpx.Response(200, json={})
                return httpx.Response(200, text="<html></html>")

            return real_client(**kwargs, transport=httpx.MockTransport(handle))

        monkeypatch.setattr(retirejs_scanner.httpx, "AsyncClient", mock_client)
        result = asyncio.run(RetireJSScanner().scan("example.com", ScanConfig()))

        assert result.error is not None
        assert not result.findings
        assert requests == [(retirejs_scanner.RETIREJS_DB_URL, True)]
        if stale_cache:
            assert json.loads(db_cache.read_text(encoding="utf-8")) == MOCK_VULN_DB
            assert db_cache.stat().st_mtime == cached_mtime
        else:
            assert not db_cache.exists()

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
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
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
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
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
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
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
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
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
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
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
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
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
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            scanner = RetireJSScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))

        assert result.error is None
        assert result.target == "example.com"
