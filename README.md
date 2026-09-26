<p align="center">
  <img src="assets/brand/wordmark.svg" alt="WhiteRabbit" width="480">
</p>

<p align="center">
  <a href="https://github.com/ajauch/whiterabbit/actions/workflows/ci.yml">
    <img src="https://github.com/ajauch/whiterabbit/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
</p>

**Grade the security posture of a web application — deployed or in source — in one command.**

Agent-written code ships fast, but it ships with a predictable set of security
gaps: missing headers, outdated JavaScript libraries, TLS misconfigurations,
exposed admin panels, vulnerable dependencies, OWASP Top 10 code flaws.
WhiteRabbit runs best-in-class scanners against a live target *or* a source
repository and distills the results into a single letter grade (A+ through F)
with actionable remediation for every finding.

```bash
# Scan a live web target
whiterabbit scan example.com

# Scan a GitHub repo for dependency CVEs and OWASP issues
whiterabbit scanrepo https://github.com/owner/repo
```

## Why this exists

Automated code generation is accelerating how fast applications get deployed.
The security fundamentals — transport encryption, header hardening, dependency
hygiene — are exactly the things that slip through when speed is the priority.
WhiteRabbit exists to catch those gaps post-deployment, before an attacker does.

WhiteRabbit was itself built with Claude Code — the `CLAUDE.md` in this repo is
the real file used during development, not a demo. A scanner for agent-written
code that was agent-written is the honest version of eating your own dogfood.

## Installation

```bash
pip install -e ".[dev]"
```

### External dependencies

Most scanners are pure Python. Several require external binaries:

| Binary | Required by | Install |
|--------|-------------|---------|
| [Nuclei](https://github.com/projectdiscovery/nuclei#install-nuclei) | `nuclei` web scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [testssl.sh](https://github.com/drwetter/testssl.sh#install) | `testssl` web scanner | Clone the repo or install via package manager |
| [Semgrep](https://semgrep.dev/docs/getting-started/) | `owasp` repo scanner | `pip install semgrep` or `brew install semgrep` |
| [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) | `trivy` repo scanner | `brew install trivy` or [GitHub releases](https://github.com/aquasecurity/trivy/releases) |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog#installation) | `secret` repo scanner | `brew install trufflehog` or `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| [Bandit](https://bandit.readthedocs.io/) | `bandit` repo scanner | `pip install bandit` |

**testssl.sh on Windows:** WhiteRabbit invokes testssl.sh through Git Bash. It
searches PATH first, then falls back to the path in the `WHITERABBIT_TESTSSL_PATH`
environment variable (default: `C:/Tools/testssl/testssl.sh`). Set this variable
if your testssl.sh lives elsewhere:

```bash
set WHITERABBIT_TESTSSL_PATH=D:/path/to/testssl.sh
```

## Usage

### Web scanning

```bash
# Scan a target (runs all available scanners)
whiterabbit scan example.com

# Quick scan (SSL + headers only)
whiterabbit scan example.com --quick

# Fast scan (skip slow scanners like testssl)
whiterabbit scan example.com --fast

# Run specific scanners
whiterabbit scan example.com --scanners ssl,headers

# Output to HTML report
whiterabbit scan example.com -o report.html

# Output as JSON
whiterabbit scan example.com --format json

# JSON to file
whiterabbit scan example.com --format json -o report.json

# Verbose output
whiterabbit scan example.com -v

# Custom timeout (per scanner, in seconds)
whiterabbit scan example.com --timeout 60

# List available scanners
whiterabbit list-scanners

# Check scanner dependencies
whiterabbit check-deps
```

### Repository scanning

```bash
# Scan a GitHub repo (clones, scans, cleans up)
whiterabbit scanrepo https://github.com/owner/repo

# Scan a local directory
whiterabbit scanrepo ./my-project

# Specific branch
whiterabbit scanrepo https://github.com/owner/repo --branch dev

# Run only the CVE scanner
whiterabbit scanrepo ./my-project --scanners cve

# Full clone (default is shallow, depth=1)
whiterabbit scanrepo https://github.com/owner/repo --depth 0

# Keep the cloned repo after scanning
whiterabbit scanrepo https://github.com/owner/repo --keep-clone

# Output to HTML or JSON
whiterabbit scanrepo ./my-project -o report.html
whiterabbit scanrepo ./my-project --format json -o report.json

# List available repo scanners
whiterabbit list-repo-scanners

# Check repo scanner dependencies
whiterabbit check-repo-deps
```

## Grading

| Grade | Criteria |
|-------|----------|
| A+ | No findings |
| A | Info-only findings |
| B | Low severity, no medium+ |
| C | Medium findings, no high+ |
| D | High findings, no critical |
| F | Any critical finding |

## Available scanners

### Web scanners (`whiterabbit scan`)

| Scanner | What it checks | Dependencies |
|---------|---------------|--------------|
| `ssl` | Certificate validation, protocol support, cipher suites, Heartbleed, ROBOT | None (SSLyze, pure Python) |
| `headers` | HSTS, CSP, cookie flags, CORS, HTTPS redirect, and 15+ other HTTP headers | None (httpx, pure Python) |
| `nuclei` | Misconfiguration, exposure, and technology detection via community templates | [Nuclei](https://github.com/projectdiscovery/nuclei#install-nuclei) |
| `retirejs` | Known-vulnerable JavaScript libraries against the retire.js database | None (pure Python) |
| `testssl` | Deep TLS/SSL analysis: BEAST, POODLE, DROWN, FREAK, Logjam, SWEET32, Ticketbleed | [testssl.sh](https://github.com/drwetter/testssl.sh#install) |

### Repo scanners (`whiterabbit scanrepo`)

| Scanner | What it checks | Dependencies |
|---------|---------------|--------------|
| `cve` | Known vulnerabilities in project dependencies via the [OSV.dev](https://osv.dev/) API. Parses `requirements.txt`, `pyproject.toml`, `package.json`, and `package-lock.json`. | None (pure Python) |
| `owasp` | OWASP Top 10 code vulnerabilities via static analysis with the [Semgrep](https://semgrep.dev/) `p/owasp-top-ten` ruleset | [Semgrep](https://semgrep.dev/docs/getting-started/) |
| `trivy` | Dependency CVEs across 15+ ecosystems, IaC misconfigurations, and license compliance | [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) |
| `secret` | Committed secrets and credentials detection with verification | [TruffleHog](https://github.com/trufflesecurity/trufflehog#installation) |
| `bandit` | Python-specific security linting (hardcoded passwords, unsafe deserialization, weak crypto, etc.) | [Bandit](https://bandit.readthedocs.io/) |
| `slopsquat` | Detects hallucinated and slopsquatted packages in dependency manifests. Checks PyPI and npm registries and scores existing packages against 8 threat signals (description, author, source repo, license, release count, age, downloads, classifiers). Non-existent packages are CRITICAL; existing packages are scored from MEDIUM to CRITICAL based on signal count. | None (pure Python) |
| `pinning` | Detects unpinned or loosely pinned dependencies that create supply-chain risk. Flags bare names and `*`/`latest` (HIGH), loose constraints like `>=`, `^`, `~` (LOW), and missing lockfiles (MEDIUM). Parses `requirements.txt`, `pyproject.toml`, and `package.json`. | None (pure Python) |
| `logleak` | Detects logging statements that may expose sensitive data — passwords, API keys, tokens, PII, and full request bodies. Distinguishes variable references from string literals to minimize false positives. Supports Python, JS/TS, Java, Go, Ruby, and PHP. CWE-532. | None (pure Python) |
| `malware` | Flags dependencies that appear in the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) or have OSSF `MAL-` advisories via [OSV.dev](https://osv.dev/). Checks PyPI and npm packages; fetches both sources fresh at scan time. | None (pure Python) |

## Architecture

Both pipelines share the same pattern: scanners run concurrently via
`asyncio.TaskGroup` with per-scanner timeouts. Every scanner is contractually
forbidden from raising — it catches its own exceptions and returns a `ScanResult`
with `error` set. This means a single broken or timed-out scanner never takes
down the run or corrupts other results.

```
CLI (cli.py)
 ├─ scan command
 │   └─ ScanRunner (runner.py)
 │       └─ asyncio.TaskGroup
 │           ├─ SSLScanner        → ScanResult
 │           ├─ HeaderScanner     → ScanResult
 │           ├─ NucleiScanner     → ScanResult
 │           ├─ RetireJSScanner   → ScanResult
 │           └─ TestSSLScanner    → ScanResult
 │
 └─ scanrepo command
     ├─ clone_repo() (temp dir, auto-cleanup)
     └─ RepoScanRunner (repo_runner.py)
         └─ asyncio.TaskGroup
             ├─ CVEScanner        → ScanResult
             ├─ OWASPScanner      → ScanResult
             ├─ TrivyScanner      → ScanResult
             ├─ SecretScanner     → ScanResult
             ├─ BanditScanner     → ScanResult
             ├─ SlopsquatScanner  → ScanResult
             ├─ MalwareScanner   → ScanResult
             ├─ PinningScanner    → ScanResult
             └─ LogLeakScanner    → ScanResult
                     │
                     ▼
             ScanReport (aggregated findings + letter grade)
```

Each scanner is a single class implementing `async scan(target, config) -> ScanResult`.
Repo scanners follow the same contract but take a local directory path instead
of a URL, and use `RepoScanConfig` instead of `ScanConfig`.

If a scanner is requested but fails the availability check (e.g. binary not on
PATH), the report records it in a `scanners_unavailable` list with the reason.
This appears in JSON, HTML, and terminal output so pipeline consumers can
distinguish "scanner found nothing" from "scanner was never attempted."

For remote repos, `scanrepo` clones into a temporary directory (shallow by
default) and cleans up automatically after the scan completes.

### Nuclei template selection

Nuclei is restricted by tag selection, not by a "passive-only" flag. The
`DEFAULT_TAGS` are `exposure`, `misconfig`, and `tech`. The `EXCLUDED_TAGS`
block: `fuzz`, `exploit`, `intrusive`, `dos`, `brute`, `sqli`, `xss`, `rce`,
`auth-bypass`.

This is policy, not a guarantee — a community template tagged `exposure` that
behaves intrusively would still run. Review your template set if this matters
for your environment.

### TLS certificate verification

The header scanner and retire.js scanner disable TLS certificate verification
(`verify=False`) on target-probing requests. This is intentional:
a security scanner that refuses to connect to misconfigured hosts
cannot assess misconfigured hosts.

The retire.js scanner uses a separate client with TLS certificate verification
enabled to download its vulnerability database from GitHub
(`raw.githubusercontent.com`).

## Responsible use

**Web scanning** sends real HTTP requests and invokes external tools against the
target. Only scan targets you own or have explicit permission to test.
Unauthorized scanning may violate laws and terms of service.

**Repository scanning** is static analysis — it reads local files and
queries public vulnerability databases (OSV.dev, PyPI, npm registry). No
traffic is sent to the scanned application itself. You still need appropriate
access rights to the source code.

## Branch protection

The `master` branch enforces the following rules:

| Control | Status |
|---------|--------|
| CI must pass (tests, lint, type check) | Runs on every push and PR; not yet a required status check |
| Pull request review | Required — 1 approving review, stale reviews dismissed on new pushes |
| Signed commits | Not required |
| Force pushes | Blocked |
| Admin bypass | Admins can bypass the above rules |

CI runs across a 2×3 matrix (Ubuntu + Windows, Python 3.11–3.13) and gates on
`pytest` (≥80 % coverage), `ruff check`, `ruff format`, and `mypy`.

## Adding a scanner

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding new web
scanners or repo scanners.

## License

MIT
