"""Tests for the SSL/TLS scanner."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Severity
from whiterabbit.scanner.ssl_scanner import SSLScanner, _parse_target


class TestParseTarget:
    def test_plain_hostname(self) -> None:
        assert _parse_target("example.com") == ("example.com", 443)

    def test_https_url(self) -> None:
        assert _parse_target("https://example.com") == ("example.com", 443)

    def test_custom_port(self) -> None:
        assert _parse_target("https://example.com:8443") == ("example.com", 8443)

    def test_http_url(self) -> None:
        assert _parse_target("http://example.com") == ("example.com", 443)

    def test_url_with_path(self) -> None:
        assert _parse_target("https://example.com/path") == ("example.com", 443)


def _mock_cert(
    *,
    expired: bool = False,
    self_signed: bool = False,
    days_left: int = 365,
    key_size: int = 2048,
    san_names: list[str] | None = None,
    hostname: str = "example.com",
    chain_valid: bool = True,
    ocsp_response: object | None = "present",
) -> MagicMock:
    now = datetime.now(timezone.utc)

    leaf = MagicMock()
    if expired:
        leaf.not_valid_after_utc = now - timedelta(days=10)
    else:
        leaf.not_valid_after_utc = now + timedelta(days=days_left)

    if self_signed:
        leaf.issuer = MagicMock()
        leaf.subject = leaf.issuer
    else:
        leaf.issuer = MagicMock()
        leaf.subject = MagicMock()

    from cryptography.hazmat.primitives.asymmetric import rsa
    key_mock = MagicMock(spec=rsa.RSAPublicKey)
    key_mock.key_size = key_size
    leaf.public_key.return_value = key_mock

    if san_names is not None:
        from cryptography.x509 import SubjectAlternativeName, DNSName
        from cryptography.x509.oid import ExtensionOID
        san_ext = MagicMock()
        san_ext.value.get_values_for_type.return_value = san_names
        leaf.extensions.get_extension_for_oid.return_value = san_ext
    else:
        from cryptography.x509 import ExtensionNotFound
        from cryptography.x509.oid import ExtensionOID
        leaf.extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            "Not found", ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        cn_str = f"CN={hostname}"
        leaf.subject.rfc4514_string.return_value = cn_str

    deployment = MagicMock()
    deployment.received_certificate_chain = [leaf]
    deployment.leaf_certificate_signed_certificate_timestamps_count = 0
    deployment.verified_chain_has_legacy_symantec_anchor = None
    deployment.ocsp_response = ocsp_response

    path_result = MagicMock()
    path_result.was_validation_successful = chain_valid
    deployment.path_validation_results = [path_result]

    return deployment


def _make_scan_results(
    *,
    cert_deployments: list | None = None,
    ssl2_accepted: int = 0,
    ssl3_accepted: int = 0,
    tls10_accepted: int = 0,
    tls11_accepted: int = 0,
    tls12_accepted: int = 0,
    tls13_accepted: int = 0,
    weak_cipher_names: list[str] | None = None,
    heartbleed: bool = False,
    robot_vulnerable: bool = False,
    compression: bool = False,
) -> MagicMock:
    from sslyze import ScanCommandAttemptStatusEnum, RobotScanResultEnum

    results = MagicMock()

    def make_cipher_attempt(count: int, cipher_names: list[str] | None = None) -> MagicMock:
        attempt = MagicMock()
        attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
        suites = []
        names = cipher_names or [f"TLS_AES_256_GCM_SHA384"] * count
        for name in names[:count] if not cipher_names else names:
            suite = MagicMock()
            suite.cipher_suite.name = name
            suites.append(suite)
        attempt.result.accepted_cipher_suites = suites
        return attempt

    if cert_deployments is not None:
        cert_attempt = MagicMock()
        cert_attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
        cert_attempt.result.certificate_deployments = cert_deployments
        results.certificate_info = cert_attempt
    else:
        cert_attempt = MagicMock()
        cert_attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
        cert_attempt.result.certificate_deployments = [_mock_cert()]
        results.certificate_info = cert_attempt

    results.ssl_2_0_cipher_suites = make_cipher_attempt(ssl2_accepted)
    results.ssl_3_0_cipher_suites = make_cipher_attempt(ssl3_accepted)
    results.tls_1_0_cipher_suites = make_cipher_attempt(tls10_accepted)
    results.tls_1_1_cipher_suites = make_cipher_attempt(tls11_accepted)

    tls12_names = weak_cipher_names if weak_cipher_names else None
    tls12_count = len(weak_cipher_names) if weak_cipher_names else tls12_accepted
    results.tls_1_2_cipher_suites = make_cipher_attempt(tls12_count, tls12_names)

    results.tls_1_3_cipher_suites = make_cipher_attempt(tls13_accepted)

    hb_attempt = MagicMock()
    hb_attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
    hb_attempt.result.is_vulnerable_to_heartbleed = heartbleed
    results.heartbleed = hb_attempt

    robot_attempt = MagicMock()
    robot_attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
    robot_attempt.result.robot_result = (
        RobotScanResultEnum.VULNERABLE_STRONG_ORACLE
        if robot_vulnerable
        else RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE
    )
    results.robot = robot_attempt

    comp_attempt = MagicMock()
    comp_attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
    comp_attempt.result.supports_compression = compression
    results.tls_compression = comp_attempt

    return results


def _run_scan_with_mock(scan_results: MagicMock) -> list:
    """Patch SSLyze Scanner and run SSLScanner.scan(), returning findings."""
    import asyncio
    from sslyze import ServerScanStatusEnum

    server_result = MagicMock()
    server_result.scan_status = ServerScanStatusEnum.COMPLETED
    server_result.scan_result = scan_results

    with patch("whiterabbit.scanner.ssl_scanner.Scanner") as MockScanner:
        instance = MockScanner.return_value
        instance.get_results.return_value = [server_result]

        scanner = SSLScanner()
        result = asyncio.run(scanner.scan("example.com", ScanConfig()))
        return result.findings


class TestSSLScannerCertificate:
    def test_valid_cert_no_findings(self) -> None:
        results = _make_scan_results(tls13_accepted=3, tls12_accepted=2)
        findings = _run_scan_with_mock(results)
        cert_findings = [f for f in findings if "ertificat" in f.title or "expired" in f.title.lower()]
        assert len(cert_findings) == 0

    def test_expired_cert(self) -> None:
        deploy = _mock_cert(expired=True)
        results = _make_scan_results(cert_deployments=[deploy], tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        expired = [f for f in findings if "expired" in f.title.lower() or "Expired" in f.title]
        assert len(expired) == 1
        assert expired[0].severity == Severity.CRITICAL

    def test_self_signed_cert(self) -> None:
        deploy = _mock_cert(self_signed=True)
        results = _make_scan_results(cert_deployments=[deploy], tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        self_signed = [f for f in findings if "self-signed" in f.title.lower()]
        assert len(self_signed) == 1
        assert self_signed[0].severity == Severity.CRITICAL

    def test_cert_expiring_soon(self) -> None:
        deploy = _mock_cert(days_left=15)
        results = _make_scan_results(cert_deployments=[deploy], tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        expiring = [f for f in findings if "expires in" in f.title.lower()]
        assert len(expiring) == 1
        assert expiring[0].severity == Severity.MEDIUM

    def test_weak_rsa_key(self) -> None:
        deploy = _mock_cert(key_size=1024)
        results = _make_scan_results(cert_deployments=[deploy], tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        weak_key = [f for f in findings if "1024 bits" in f.title]
        assert len(weak_key) == 1
        assert weak_key[0].severity == Severity.HIGH

    def test_hostname_mismatch(self) -> None:
        deploy = _mock_cert(san_names=["other.com", "*.other.com"])
        results = _make_scan_results(cert_deployments=[deploy], tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        mismatch = [f for f in findings if "mismatch" in f.title.lower()]
        assert len(mismatch) == 1
        assert mismatch[0].severity == Severity.CRITICAL

    def test_incomplete_chain(self) -> None:
        deploy = _mock_cert(chain_valid=False)
        results = _make_scan_results(cert_deployments=[deploy], tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        chain = [f for f in findings if "chain" in f.title.lower()]
        assert len(chain) == 1
        assert chain[0].severity == Severity.MEDIUM


class TestSSLScannerProtocols:
    def test_ssl2_critical(self) -> None:
        results = _make_scan_results(ssl2_accepted=3, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        ssl2 = [f for f in findings if "SSLv2" in f.title]
        assert len(ssl2) == 1
        assert ssl2[0].severity == Severity.CRITICAL

    def test_ssl3_critical(self) -> None:
        results = _make_scan_results(ssl3_accepted=3, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        ssl3 = [f for f in findings if "SSLv3" in f.title]
        assert len(ssl3) == 1
        assert ssl3[0].severity == Severity.CRITICAL

    def test_tls10_high(self) -> None:
        results = _make_scan_results(tls10_accepted=3, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        tls10 = [f for f in findings if "TLS 1.0" in f.title]
        assert len(tls10) == 1
        assert tls10[0].severity == Severity.HIGH

    def test_tls11_high(self) -> None:
        results = _make_scan_results(tls11_accepted=3, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        tls11 = [f for f in findings if "TLS 1.1" in f.title]
        assert len(tls11) == 1
        assert tls11[0].severity == Severity.HIGH

    def test_no_tls13(self) -> None:
        results = _make_scan_results(tls13_accepted=0, tls12_accepted=3)
        findings = _run_scan_with_mock(results)
        no_tls13 = [f for f in findings if "TLS 1.3 not supported" in f.title]
        assert len(no_tls13) == 1
        assert no_tls13[0].severity == Severity.MEDIUM


class TestSSLScannerVulnerabilities:
    def test_heartbleed(self) -> None:
        results = _make_scan_results(heartbleed=True, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        hb = [f for f in findings if "Heartbleed" in f.title]
        assert len(hb) == 1
        assert hb[0].severity == Severity.CRITICAL
        assert hb[0].cve == "CVE-2014-0160"

    def test_robot(self) -> None:
        results = _make_scan_results(robot_vulnerable=True, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        robot = [f for f in findings if "ROBOT" in f.title]
        assert len(robot) == 1
        assert robot[0].severity == Severity.HIGH

    def test_compression_crime(self) -> None:
        results = _make_scan_results(compression=True, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        comp = [f for f in findings if "compression" in f.title.lower()]
        assert len(comp) == 1
        assert comp[0].severity == Severity.HIGH

    def test_weak_ciphers(self) -> None:
        results = _make_scan_results(
            weak_cipher_names=["TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
            tls13_accepted=3,
        )
        findings = _run_scan_with_mock(results)
        weak = [f for f in findings if "Weak cipher" in f.title]
        assert len(weak) == 2
        assert all(f.severity == Severity.HIGH for f in weak)


class TestSSLScannerCleanSite:
    def test_clean_site_no_findings(self) -> None:
        results = _make_scan_results(tls12_accepted=3, tls13_accepted=3)
        findings = _run_scan_with_mock(results)
        non_ocsp = [f for f in findings if "OCSP" not in f.title]
        assert len(non_ocsp) == 0


class TestSSLScannerErrors:
    def test_connection_failure(self) -> None:
        import asyncio
        from sslyze import ServerScanStatusEnum

        server_result = MagicMock()
        server_result.scan_status = ServerScanStatusEnum.ERROR_NO_CONNECTIVITY

        with (
            patch("whiterabbit.scanner.ssl_scanner.ServerNetworkLocation"),
            patch("whiterabbit.scanner.ssl_scanner.Scanner") as MockScanner,
        ):
            instance = MockScanner.return_value
            instance.get_results.return_value = [server_result]

            scanner = SSLScanner()
            result = asyncio.run(scanner.scan("nope.invalid", ScanConfig()))
            assert result.error is not None
            assert "Could not connect" in result.error

    def test_exception_during_scan(self) -> None:
        import asyncio

        with patch("whiterabbit.scanner.ssl_scanner.Scanner") as MockScanner:
            MockScanner.side_effect = RuntimeError("SSLyze crashed")

            scanner = SSLScanner()
            result = asyncio.run(scanner.scan("example.com", ScanConfig()))
            assert result.error is not None
            assert "SSLyze crashed" in result.error
