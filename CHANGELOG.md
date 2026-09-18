# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Verify TLS certificates when downloading the retire.js vulnerability database,
  while allowing scans of targets with misconfigured TLS.

## [0.1.0] - 2026-09-17

### Added

- CLI with `scan`, `list-scanners`, and `check-deps` commands
- SSL/TLS scanner (SSLyze) -- certificate validation, protocol support, cipher suites, Heartbleed, ROBOT
- HTTP header scanner -- HSTS, CSP, cookie flags, CORS, HTTPS redirect, and 15+ other checks
- Nuclei scanner -- misconfiguration, exposure, and technology detection via community templates
- Retire.js scanner -- known-vulnerable JavaScript libraries against the retire.js database
- testssl.sh scanner -- deep TLS/SSL analysis (BEAST, POODLE, DROWN, FREAK, Logjam, SWEET32, Ticketbleed)
- Concurrent scanner execution via `asyncio.TaskGroup` with per-scanner timeouts
- Letter grading (A+ through F) based on finding severity waterfall
- Terminal, JSON, and HTML report output formats
- Quick-scan mode (`--quick`) for headers + SSL only
- CI pipeline with ruff, mypy, and pytest across Python 3.11-3.13 on Ubuntu and Windows

[0.1.0]: https://github.com/ajauch/whiterabbit/releases/tag/v0.1.0
