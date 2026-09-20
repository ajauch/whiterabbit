# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install (editable, with dev deps)
pip install -e ".[dev]"

# Run the web scanner
whiterabbit scan <target>              # all scanners, terminal output
whiterabbit scan <target> --quick      # headers + SSL only
python -m whiterabbit scan <target>    # alternative entry point

# Run the repo scanner
whiterabbit scanrepo <repo-url>        # scan a GitHub repo (clones, scans, cleans up)
whiterabbit scanrepo ./local-dir       # scan a local directory
whiterabbit scanrepo <url> --branch dev --scanners cve  # specific branch + scanner
whiterabbit list-repo-scanners         # show available repo scanners
whiterabbit check-repo-deps            # check repo scanner dependencies

# Tests
pytest tests/ -v                       # all tests
pytest tests/ -v -m "not integration"  # skip tests that hit external services
pytest tests/scanners/test_ssl_scanner.py -v             # single file
pytest tests/scanners/test_ssl_scanner.py::TestClass::test_name -v  # single test

# Lint & format
ruff check src/ tests/
ruff format src/ tests/
mypy src/
```

## Architecture

WhiteRabbit is a local web security scanner. Src layout: `src/whiterabbit/`.

**Scan pipeline:** CLI (`cli.py`) builds a `ScanConfig` and selects scanners, then `ScanRunner` (`runner.py`) runs them concurrently via `asyncio.TaskGroup` with per-scanner timeouts. Each scanner returns a `ScanResult` (findings list + optional error). The runner aggregates findings, computes a letter grade, and returns a `ScanReport`. The CLI formats output (terminal/json/html), appends a row to `ScanResults.csv`, and logs to `whiterabbit.log`.

**Scanner contract:** Scanners subclass `BaseScanner` (`scanner/base.py`). They must implement `async scan(target, config) -> ScanResult`, never raise (catch exceptions and return `ScanResult` with `error` set), and include remediation text on every `Finding`. External binary dependencies go in `required_binaries`; the base class checks PATH availability. Scanners are explicitly registered in the `SCANNER_REGISTRY` dict in `scanner/__init__.py` — no auto-discovery.

**Scanners:** `ssl` (SSLyze library), `headers` (httpx), `nuclei` (subprocess, requires `nuclei` binary), `retirejs` (pure Python, downloads vuln DB), `testssl` (subprocess via Git Bash on Windows, requires `testssl.sh`). The testssl scanner overrides `is_available()`/`check_dependencies()` instead of using `required_binaries`.

**Data models** (`report/models.py`): Pydantic v2. `Severity` enum (critical/high/medium/low/info), `Finding`, `ScanResult`, `ScanReport`.

**Grading** (`report/grader.py`): Waterfall — any critical→F, high→D, medium→C, low→B, info-only→A, none→A+.

**HTML reports** use a Jinja2 template at `templates/report.html`.

**Repo scan pipeline:** CLI `scanrepo` command auto-detects local directories vs git URLs. For URLs, it clones via `clone_repo()` (async context manager with temp dir cleanup). `RepoScanRunner` (`repo_runner.py`) orchestrates repo scanners concurrently — same TaskGroup/timeout/progress pattern as `ScanRunner`. Reuses all existing data models and formatters.

**Repo scanner contract:** Repo scanners subclass `BaseRepoScanner` (`repo_scanner/base.py`). Same contract as `BaseScanner` but `scan()` takes `repo_path` (local dir) + `RepoScanConfig`. Registered in `REPO_SCANNER_REGISTRY` in `repo_scanner/__init__.py`.

**Repo scanners:** `cve` (pure Python, parses dependency manifests and queries OSV.dev API), `owasp` (Semgrep subprocess, requires `semgrep` binary), `trivy` (subprocess, requires `trivy` binary — dependency CVEs across 15+ ecosystems, IaC misconfigs, license compliance), `secret` (subprocess, requires `trufflehog` binary — secret/credential detection with verification), `bandit` (subprocess, requires `bandit` binary — Python-specific security linting), `slopsquat` (pure Python — detects hallucinated/non-existent packages by checking PyPI and npm registries, flags recently created packages), `pinning` (pure Python — flags unpinned/loosely-pinned dependencies and missing lockfiles as supply-chain risks), `logleak` (pure Python — detects logging statements that expose sensitive data like passwords, tokens, API keys, and request bodies; uses string-literal stripping to avoid false positives; supports Python/JS/TS/Java/Go/Ruby/PHP).

## Testing patterns

Tests mock external dependencies (SSLyze, httpx, subprocess) — scanner tests never hit the network. Async tests use `pytest-asyncio` with `asyncio_mode = "auto"`. Shared fixtures in `tests/conftest.py` provide `sample_config`, `sample_finding`, `sample_findings`, `sample_scan_result`, and `sample_report`.

