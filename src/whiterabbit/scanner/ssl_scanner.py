"""SSL/TLS scanner powered by SSLyze."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

from sslyze import (  # type: ignore[attr-defined]
    CipherSuitesScanResult,
    HeartbleedScanResult,
    RobotScanResult,
    RobotScanResultEnum,
    ScanCommand,
    ScanCommandAttemptStatusEnum,
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ServerScanStatusEnum,
)

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.scanner.base import BaseScanner

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}


def _parse_target(target: str) -> tuple[str, int]:
    if "://" not in target:
        target = f"https://{target}"
    parsed = urlparse(target)
    hostname = parsed.hostname or parsed.path.split("/")[0].split(":")[0]
    port = parsed.port or 443
    return hostname, port


class SSLScanner(BaseScanner):
    name = "ssl"
    display_name = "SSL/TLS Scanner"
    description = "Checks SSL/TLS configuration using SSLyze"

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        hostname, port = _parse_target(target)
        started = datetime.now(UTC)
        findings: list[Finding] = []

        try:
            location = ServerNetworkLocation(hostname=hostname, port=port)
            request = ServerScanRequest(
                server_location=location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.TLS_COMPRESSION,
                },
            )

            scanner = Scanner()
            scanner.queue_scans([request])

            for server_result in scanner.get_results():
                if (
                    server_result.scan_status
                    == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY
                ):
                    return ScanResult(
                        target=target,
                        scanner_name=self.name,
                        started_at=started,
                        finished_at=datetime.now(UTC),
                        error=f"Could not connect to {hostname}:{port}",
                    )

                results = server_result.scan_result
                findings.extend(self._check_certificate(results, hostname))
                findings.extend(self._check_protocols(results))
                findings.extend(self._check_ciphers(results))
                findings.extend(self._check_heartbleed(results))
                findings.extend(self._check_robot(results))
                findings.extend(self._check_compression(results))

        except Exception as exc:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc),
            )

        return ScanResult(
            target=target,
            scanner_name=self.name,
            started_at=started,
            finished_at=datetime.now(UTC),
            findings=findings,
        )

    def _check_certificate(self, results: object, hostname: str) -> list[Finding]:
        findings: list[Finding] = []
        cert_attempt = results.certificate_info  # type: ignore[attr-defined]
        if cert_attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return findings

        cert_result = cert_attempt.result
        for deployment in cert_result.certificate_deployments:
            leaf = deployment.received_certificate_chain[0]
            now = datetime.now(UTC)

            if leaf.not_valid_after_utc < now:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title=f"Certificate expired on {leaf.not_valid_after_utc.date()}",
                        description="The SSL certificate has expired and browsers will show security warnings.",
                        remediation="Renew the SSL certificate immediately.",
                        category="ssl",
                        scanner=self.name,
                        cwe="CWE-298",
                    )
                )

            days_left = (leaf.not_valid_after_utc - now).days
            if 0 < days_left <= 30:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"Certificate expires in {days_left} days",
                        description=f"The certificate expires on {leaf.not_valid_after_utc.date()}, which is less than 30 days away.",
                        remediation="Renew the certificate before it expires. Consider setting up auto-renewal with Let's Encrypt.",
                        category="ssl",
                        scanner=self.name,
                    )
                )

            if leaf.issuer == leaf.subject:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title="Certificate is self-signed",
                        description="The certificate is self-signed and will not be trusted by browsers.",
                        remediation="Obtain a certificate from a trusted Certificate Authority. Let's Encrypt provides free certificates.",
                        category="ssl",
                        scanner=self.name,
                        cwe="CWE-295",
                    )
                )

            san_names: list[str] = []
            try:
                from cryptography.x509 import ExtensionNotFound
                from cryptography.x509.oid import ExtensionOID

                san_ext = leaf.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                from cryptography.x509 import DNSName

                san_names = san_ext.value.get_values_for_type(DNSName)
            except (ExtensionNotFound, Exception):
                cn = leaf.subject.rfc4514_string()
                if "CN=" in cn:
                    san_names = [cn.split("CN=")[1].split(",")[0]]

            hostname_lower = hostname.lower()
            if san_names and not any(
                _hostname_matches(hostname_lower, name.lower()) for name in san_names
            ):
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title="Certificate hostname mismatch",
                        description=f"Certificate is issued for {', '.join(san_names)} but scanning {hostname}.",
                        remediation="Obtain a certificate that includes the correct hostname in its Subject Alternative Names.",
                        category="ssl",
                        scanner=self.name,
                        cwe="CWE-295",
                    )
                )

            key = leaf.public_key()
            from cryptography.hazmat.primitives.asymmetric import rsa

            if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"RSA key is {key.key_size} bits (minimum 2048)",
                        description=f"The RSA key is only {key.key_size} bits, which is considered weak.",
                        remediation="Generate a new certificate with at least a 2048-bit RSA key, or use ECDSA.",
                        category="ssl",
                        scanner=self.name,
                        cwe="CWE-326",
                    )
                )

            if not deployment.leaf_certificate_signed_certificate_timestamps_count:
                pass

            if not any(
                path.was_validation_successful
                for path in deployment.path_validation_results
            ) and not any(
                f.title.startswith("Certificate is self-signed") for f in findings
            ):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="Incomplete certificate chain",
                        description="The server's certificate chain could not be validated against any trust store.",
                        remediation="Ensure the server sends the full certificate chain including intermediate certificates.",
                        category="ssl",
                        scanner=self.name,
                        cwe="CWE-295",
                    )
                )

            if deployment.verified_chain_has_legacy_symantec_anchor is not None:
                pass

            if (
                hasattr(deployment, "ocsp_response_is_trusted")
                and deployment.ocsp_response is None
            ):
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        title="OCSP stapling not enabled",
                        description="The server does not staple OCSP responses, which can slow certificate validation.",
                        remediation="Enable OCSP stapling in your server configuration. For Nginx: `ssl_stapling on; ssl_stapling_verify on;`",
                        category="ssl",
                        scanner=self.name,
                    )
                )

        return findings

    def _check_protocols(self, results: object) -> list[Finding]:
        findings: list[Finding] = []
        protocol_checks = [
            (
                "ssl_2_0_cipher_suites",
                "SSLv2",
                Severity.CRITICAL,
                "SSLv2 is enabled — vulnerable to DROWN attack",
                "Disable SSLv2 immediately. It has been deprecated since 2011.",
                "CWE-326",
                "CVE-2016-0800",
            ),
            (
                "ssl_3_0_cipher_suites",
                "SSLv3",
                Severity.CRITICAL,
                "SSLv3 is enabled — vulnerable to POODLE attack",
                "Disable SSLv3 immediately. Use TLS 1.2 or higher.",
                "CWE-326",
                "CVE-2014-3566",
            ),
            (
                "tls_1_0_cipher_suites",
                "TLS 1.0",
                Severity.HIGH,
                "TLS 1.0 is deprecated (RFC 8996)",
                "Disable TLS 1.0. For Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
                "CWE-326",
                None,
            ),
            (
                "tls_1_1_cipher_suites",
                "TLS 1.1",
                Severity.HIGH,
                "TLS 1.1 is deprecated (RFC 8996)",
                "Disable TLS 1.1. For Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
                "CWE-326",
                None,
            ),
        ]

        for attr, protocol, severity, title, remediation, cwe, cve in protocol_checks:
            attempt = getattr(results, attr, None)
            if (
                attempt is None
                or attempt.status != ScanCommandAttemptStatusEnum.COMPLETED
            ):
                continue
            cipher_result: CipherSuitesScanResult = attempt.result
            if cipher_result.accepted_cipher_suites:
                findings.append(
                    Finding(
                        severity=severity,
                        title=title,
                        description=f"{protocol} is enabled with {len(cipher_result.accepted_cipher_suites)} accepted cipher suite(s). This protocol has known vulnerabilities.",
                        remediation=remediation,
                        category="ssl",
                        scanner=self.name,
                        cwe=cwe,
                        cve=cve,
                    )
                )

        tls13_attempt = getattr(results, "tls_1_3_cipher_suites", None)
        if (
            tls13_attempt
            and tls13_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED
        ):
            tls13_result: CipherSuitesScanResult = tls13_attempt.result
            if not tls13_result.accepted_cipher_suites:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="TLS 1.3 not supported",
                        description="The server does not support TLS 1.3, the latest and most secure TLS version.",
                        remediation="Enable TLS 1.3 in your server configuration. For Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`",
                        category="ssl",
                        scanner=self.name,
                    )
                )

        return findings

    def _check_ciphers(self, results: object) -> list[Finding]:
        findings: list[Finding] = []
        cipher_attrs = [
            "tls_1_0_cipher_suites",
            "tls_1_1_cipher_suites",
            "tls_1_2_cipher_suites",
        ]

        for attr in cipher_attrs:
            attempt = getattr(results, attr, None)
            if (
                attempt is None
                or attempt.status != ScanCommandAttemptStatusEnum.COMPLETED
            ):
                continue
            cipher_result: CipherSuitesScanResult = attempt.result
            for accepted in cipher_result.accepted_cipher_suites:
                cipher_name = accepted.cipher_suite.name
                if any(weak in cipher_name.upper() for weak in WEAK_CIPHERS):
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=f"Weak cipher suite: {cipher_name}",
                            description=f"The server accepts the weak cipher suite {cipher_name}.",
                            remediation="Disable weak cipher suites in your server configuration. Only allow modern ciphers with AEAD.",
                            category="ssl",
                            scanner=self.name,
                            cwe="CWE-326",
                        )
                    )

        return findings

    def _check_heartbleed(self, results: object) -> list[Finding]:
        attempt = getattr(results, "heartbleed", None)
        if attempt is None or attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return []
        hb_result: HeartbleedScanResult = attempt.result
        if hb_result.is_vulnerable_to_heartbleed:
            return [
                Finding(
                    severity=Severity.CRITICAL,
                    title="Server is vulnerable to Heartbleed (CVE-2014-0160)",
                    description="The server is vulnerable to the Heartbleed bug, which allows attackers to read server memory.",
                    remediation="Update OpenSSL to a patched version immediately and reissue all certificates.",
                    category="ssl",
                    scanner=self.name,
                    cwe="CWE-119",
                    cve="CVE-2014-0160",
                    references=["https://heartbleed.com/"],
                )
            ]
        return []

    def _check_robot(self, results: object) -> list[Finding]:
        attempt = getattr(results, "robot", None)
        if attempt is None or attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return []
        robot_result: RobotScanResult = attempt.result
        if robot_result.robot_result in (
            RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
            RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
        ):
            return [
                Finding(
                    severity=Severity.HIGH,
                    title="Server is vulnerable to ROBOT attack",
                    description="The server is vulnerable to the Return Of Bleichenbacher's Oracle Threat (ROBOT) attack.",
                    remediation="Disable RSA key exchange cipher suites or update your TLS library.",
                    category="ssl",
                    scanner=self.name,
                    cwe="CWE-203",
                    references=["https://robotattack.org/"],
                )
            ]
        return []

    def _check_compression(self, results: object) -> list[Finding]:
        attempt = getattr(results, "tls_compression", None)
        if attempt is None or attempt.status != ScanCommandAttemptStatusEnum.COMPLETED:
            return []
        if attempt.result.supports_compression:
            return [
                Finding(
                    severity=Severity.HIGH,
                    title="TLS compression enabled — vulnerable to CRIME attack",
                    description="TLS compression is enabled, which makes the server vulnerable to the CRIME attack.",
                    remediation="Disable TLS compression in your server configuration.",
                    category="ssl",
                    scanner=self.name,
                    cwe="CWE-310",
                    cve="CVE-2012-4929",
                )
            ]
        return []


def _hostname_matches(hostname: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and "." in hostname[: -len(suffix) + 1]
    return hostname == pattern
