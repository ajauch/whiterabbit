# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in WhiteRabbit, please report it
responsibly. **Do not open a public GitHub issue.**

Instead, use [GitHub's private vulnerability reporting](https://github.com/ajauch/whiterabbit/security/advisories/new)
to submit your report. You can also email security concerns to
info@fictivize.com.

Please include:

- A description of the vulnerability
- Steps to reproduce
- The impact you believe it has
- Any suggested fix (optional)

You should receive an acknowledgment within 48 hours. We will work with you to
understand the issue and coordinate a fix before any public disclosure.

## Scope

WhiteRabbit is a security scanner that intentionally sends HTTP requests and
invokes external tools against user-specified targets. Vulnerabilities in
*WhiteRabbit itself* (e.g., command injection via crafted target input, unsafe
deserialization of scan results, dependency vulnerabilities) are in scope.

Findings that a scan *produces* about a target are not vulnerabilities in
WhiteRabbit.
