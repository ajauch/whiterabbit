# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Repository scanning via `whiterabbit scanrepo` — scan GitHub repos or local
  directories for security vulnerabilities.
- Dependency CVE scanner (`cve`) — parses `requirements.txt`, `pyproject.toml`,
  `package.json`, and `package-lock.json`, then queries the OSV.dev API for
  known vulnerabilities. Pure Python, no external dependencies.
- OWASP SAST scanner (`owasp`) — static analysis for OWASP Top 10
  vulnerabilities using Semgrep's `p/owasp-top-ten` ruleset.
- `list-repo-scanners` and `check-repo-deps` CLI commands.
- Automatic git clone with temp directory cleanup for remote repo URLs.
- `--branch`, `--depth`, and `--keep-clone` options for `scanrepo`.
- Recursive manifest discovery — finds dependency files in subdirectories,
  skipping `node_modules`, `.git`, `__pycache__`, `.venv`, and `vendor`.
- Scan results appended to `RepoScanResults.csv` (separate from web scan CSV).

### Fixed

- Verify TLS certificates when downloading the retire.js vulnerability database,
  while allowing scans of targets with misconfigured TLS.
- Identify retire.js database download failures separately from target connection
  errors, preserving the failure details and reporting the database timeout.

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
