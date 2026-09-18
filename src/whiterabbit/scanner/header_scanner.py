"""HTTP security headers scanner."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.scanner.base import BaseScanner


def _normalize_target(target: str) -> str:
    if "://" not in target:
        return f"https://{target}"
    return target


class HeaderScanner(BaseScanner):
    name = "headers"
    display_name = "HTTP Headers Scanner"
    description = "Checks HTTP security headers, cookies, and HTTPS redirect"

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        url = _normalize_target(target)
        started = datetime.now(UTC)
        findings: list[Finding] = []

        try:
            # verify=False: intentional — a security scanner must connect to misconfigured hosts
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(config.timeout),
                verify=False,
            ) as client:
                response = await client.get(url)
                headers = response.headers

                findings.extend(_check_hsts(headers))
                findings.extend(_check_csp(headers))
                findings.extend(_check_x_content_type_options(headers))
                findings.extend(_check_x_frame_options(headers))
                findings.extend(_check_referrer_policy(headers))
                findings.extend(_check_permissions_policy(headers))
                findings.extend(_check_server_header(headers))
                findings.extend(_check_x_powered_by(headers))
                findings.extend(_check_coop(headers))
                findings.extend(_check_corp(headers))
                findings.extend(_check_cors(headers))
                findings.extend(_check_cookies(response))
                findings.extend(await _check_https_redirect(target, client))

        except httpx.TimeoutException:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Request timed out after {config.timeout}s",
            )
        except httpx.ConnectError:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=f"Could not connect to {target}",
            )
        except Exception as exc:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(UTC),
                error=str(exc) or f"{type(exc).__name__} (no details)",
            )

        return ScanResult(
            target=target,
            scanner_name=self.name,
            started_at=started,
            finished_at=datetime.now(UTC),
            findings=findings,
        )


def _check_hsts(headers: httpx.Headers) -> list[Finding]:
    findings: list[Finding] = []
    hsts = headers.get("strict-transport-security")
    if not hsts:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="HSTS header not set",
                description="The Strict-Transport-Security header is missing. The site is vulnerable to protocol downgrade attacks and cookie hijacking.",
                remediation="Add the header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
                category="headers",
                scanner="headers",
                cwe="CWE-523",
            )
        )
    else:
        if "max-age=" in hsts.lower():
            try:
                max_age = int(hsts.lower().split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title=f"HSTS max-age is {max_age}s (recommend 31536000)",
                            description=f"The HSTS max-age is set to {max_age} seconds, which is less than the recommended one year (31536000).",
                            remediation="Increase max-age to at least 31536000 (one year): `Strict-Transport-Security: max-age=31536000; includeSubDomains`",
                            category="headers",
                            scanner="headers",
                            cwe="CWE-523",
                        )
                    )
            except (ValueError, IndexError):
                pass
    return findings


def _check_csp(headers: httpx.Headers) -> list[Finding]:
    findings: list[Finding] = []
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="No Content-Security-Policy header",
                description="The CSP header is missing. The site is vulnerable to XSS via inline scripts and unauthorized resource loading.",
                remediation="Add a Content-Security-Policy header. Start with: `Content-Security-Policy: default-src 'self'` and refine.",
                category="headers",
                scanner="headers",
                cwe="CWE-693",
            )
        )
    else:
        csp_lower = csp.lower()
        for directive in ("'unsafe-inline'", "'unsafe-eval'"):
            if directive in csp_lower:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"CSP allows {directive}",
                        description=f"The Content-Security-Policy contains {directive}, which weakens XSS protection.",
                        remediation=f"Remove {directive} from your CSP. Use nonces or hashes for inline scripts instead.",
                        category="headers",
                        scanner="headers",
                        cwe="CWE-693",
                    )
                )
    return findings


def _check_x_content_type_options(headers: httpx.Headers) -> list[Finding]:
    val = headers.get("x-content-type-options")
    if not val or val.lower().strip() != "nosniff":
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Missing X-Content-Type-Options: nosniff",
                description="Without nosniff, browsers may MIME-sniff responses, potentially treating non-executable content as executable.",
                remediation="Add the header: `X-Content-Type-Options: nosniff`",
                category="headers",
                scanner="headers",
                cwe="CWE-693",
            )
        ]
    return []


def _check_x_frame_options(headers: httpx.Headers) -> list[Finding]:
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="Missing clickjacking protection",
                description="Neither X-Frame-Options nor CSP frame-ancestors is set. The site may be vulnerable to clickjacking attacks.",
                remediation="Add `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`.",
                category="headers",
                scanner="headers",
                cwe="CWE-1021",
            )
        ]
    return []


def _check_referrer_policy(headers: httpx.Headers) -> list[Finding]:
    if not headers.get("referrer-policy"):
        return [
            Finding(
                severity=Severity.LOW,
                title="No Referrer-Policy header",
                description="Without a Referrer-Policy, the full URL may leak to third parties via the Referer header.",
                remediation="Add: `Referrer-Policy: strict-origin-when-cross-origin`",
                category="headers",
                scanner="headers",
            )
        ]
    return []


def _check_permissions_policy(headers: httpx.Headers) -> list[Finding]:
    if not headers.get("permissions-policy"):
        return [
            Finding(
                severity=Severity.LOW,
                title="No Permissions-Policy header",
                description="Without a Permissions-Policy, browser features like camera, microphone, and geolocation are not explicitly restricted.",
                remediation="Add: `Permissions-Policy: camera=(), microphone=(), geolocation=()`",
                category="headers",
                scanner="headers",
            )
        ]
    return []


def _check_server_header(headers: httpx.Headers) -> list[Finding]:
    server = headers.get("server")
    if server and any(c.isdigit() for c in server):
        return [
            Finding(
                severity=Severity.LOW,
                title=f"Server header reveals: {server}",
                description=f"The Server header exposes software and version information ({server}), aiding attackers in fingerprinting.",
                remediation="Remove or obscure the Server header. For Nginx: `server_tokens off;`",
                category="headers",
                scanner="headers",
                cwe="CWE-200",
            )
        ]
    return []


def _check_x_powered_by(headers: httpx.Headers) -> list[Finding]:
    powered_by = headers.get("x-powered-by")
    if powered_by:
        return [
            Finding(
                severity=Severity.LOW,
                title=f"X-Powered-By reveals: {powered_by}",
                description=f"The X-Powered-By header exposes technology information ({powered_by}), aiding attackers.",
                remediation="Remove the X-Powered-By header from server responses.",
                category="headers",
                scanner="headers",
                cwe="CWE-200",
            )
        ]
    return []


def _check_coop(headers: httpx.Headers) -> list[Finding]:
    if not headers.get("cross-origin-opener-policy"):
        return [
            Finding(
                severity=Severity.LOW,
                title="No Cross-Origin-Opener-Policy header",
                description="Without COOP, the page may be vulnerable to cross-origin attacks via window references.",
                remediation="Add: `Cross-Origin-Opener-Policy: same-origin`",
                category="headers",
                scanner="headers",
            )
        ]
    return []


def _check_corp(headers: httpx.Headers) -> list[Finding]:
    if not headers.get("cross-origin-resource-policy"):
        return [
            Finding(
                severity=Severity.LOW,
                title="No Cross-Origin-Resource-Policy header",
                description="Without CORP, resources may be loaded by cross-origin documents.",
                remediation="Add: `Cross-Origin-Resource-Policy: same-origin`",
                category="headers",
                scanner="headers",
            )
        ]
    return []


def _check_cors(headers: httpx.Headers) -> list[Finding]:
    acao = headers.get("access-control-allow-origin")
    if acao and acao.strip() == "*":
        return [
            Finding(
                severity=Severity.MEDIUM,
                title="CORS allows any origin",
                description="Access-Control-Allow-Origin is set to *, allowing any website to make cross-origin requests.",
                remediation="Restrict CORS to trusted origins instead of using a wildcard.",
                category="headers",
                scanner="headers",
                cwe="CWE-942",
            )
        ]
    return []


def _check_cookies(response: httpx.Response) -> list[Finding]:
    findings: list[Finding] = []
    cookies = response.headers.get_list("set-cookie")
    for cookie_str in cookies:
        name = cookie_str.split("=")[0].strip()
        lower = cookie_str.lower()

        if "secure" not in lower:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f'Cookie "{name}" missing Secure flag',
                    description=f'The cookie "{name}" does not have the Secure flag, meaning it can be sent over unencrypted HTTP.',
                    remediation=f'Add the Secure flag to the "{name}" cookie.',
                    category="cookies",
                    scanner="headers",
                    cwe="CWE-614",
                )
            )

        if "httponly" not in lower:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f'Cookie "{name}" missing HttpOnly flag',
                    description=f'The cookie "{name}" does not have the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS theft.',
                    remediation=f'Add the HttpOnly flag to the "{name}" cookie.',
                    category="cookies",
                    scanner="headers",
                    cwe="CWE-1004",
                )
            )

        if "samesite" not in lower:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f'Cookie "{name}" missing SameSite attribute',
                    description=f'The cookie "{name}" does not have the SameSite attribute, which helps prevent CSRF attacks.',
                    remediation=f'Add `SameSite=Lax` or `SameSite=Strict` to the "{name}" cookie.',
                    category="cookies",
                    scanner="headers",
                    cwe="CWE-1275",
                )
            )

    return findings


async def _check_https_redirect(
    target: str, client: httpx.AsyncClient
) -> list[Finding]:
    parsed = urlparse(_normalize_target(target))
    hostname = parsed.hostname or target
    http_url = f"http://{hostname}"

    try:
        response = await client.get(http_url, follow_redirects=False)
        location = response.headers.get("location", "")
        if response.status_code not in (301, 302, 307, 308) or not location.startswith(
            "https://"
        ):
            return [
                Finding(
                    severity=Severity.HIGH,
                    title="HTTP to HTTPS redirect missing",
                    description=f"Requesting {http_url} does not redirect to HTTPS. Users may access the site over an insecure connection.",
                    remediation="Configure your server to redirect all HTTP requests to HTTPS with a 301 redirect.",
                    category="headers",
                    scanner="headers",
                    cwe="CWE-319",
                )
            ]
    except httpx.ConnectError:
        pass
    except Exception:
        pass

    return []
