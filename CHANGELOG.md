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
- Slopsquat scanner (`slopsquat`) — detects hallucinated or non-existent
  packages in dependency manifests by checking PyPI and npm registries.
  Flags non-existent packages (HIGH) and recently created packages less
  than 7 days old (LOW). Pure Python, no external dependencies.
- Multi-signal threat scoring for slopsquat scanner — replaces binary
  exists/not-exists detection with scoring across 8 signals (description,
  author, source repo, license, release count, creation date, download
  count, classifiers). Catches slopsquatted packages that were registered
  with malicious intent, not just missing ones.
- Malware scanner (`malware`) — flags dependencies that appear in the
  DataDog malicious-software-packages-dataset or have OSSF `MAL-`
  advisories via OSV.dev. Checks PyPI and npm packages; fetches both
  sources fresh at scan time. Pure Python, no external dependencies.
- Dependency pinning scanner (`pinning`) — detects unpinned or loosely pinned
  dependencies in `requirements.txt`, `pyproject.toml`, and `package.json`.
  Flags bare names and `*`/`latest` (HIGH), loose constraints like `>=`, `^`,
  `~` (LOW), and missing lockfiles for npm projects (MEDIUM). Pure Python,
  no external dependencies.
- Log leak scanner (`logleak`) — detects logging statements that may expose
  sensitive data such as passwords, API keys, tokens, PII, and full request
  bodies. Uses string-literal stripping to distinguish variable references from
  literal message text, minimizing false positives. Supports Python, JS/TS,
  Java, Go, Ruby, and PHP. CWE-532. Pure Python, no external dependencies.
- Shared manifest parsing module (`repo_scanner/manifest.py`) — extracted
  from the CVE scanner for reuse across dependency-aware scanners.
- Recursive manifest discovery — finds dependency files in subdirectories,
  skipping `node_modules`, `.git`, `__pycache__`, `.venv`, and `vendor`.
- Scan results appended to `RepoScanResults.csv` (separate from web scan CSV).
- Branch protection policy documented in README — CI, review, signing, and
  force-push rules.

### Changed

- Downgraded loose dependency constraints (`>=`, `^`, `~`) from MEDIUM to
  LOW severity in the pinning scanner. These are common in healthy projects
  and rarely represent a real supply-chain risk.

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
