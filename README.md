# WhiteRabbit

[![CI](https://github.com/ajauch/whiterabbit/actions/workflows/ci.yml/badge.svg)](https://github.com/ajauch/whiterabbit/actions/workflows/ci.yml)

**Grade the security posture of a deployed web application — in one command.**

Agent-written code ships fast, but it ships with a predictable set of security
gaps: missing headers, outdated JavaScript libraries, TLS misconfigurations,
exposed admin panels. WhiteRabbit runs best-in-class scanners against a live
target and distills the results into a single letter grade (A+ through F) with
actionable remediation for every finding.

```bash
whiterabbit scan example.com
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

Most scanners are pure Python. Two require external binaries:

| Binary | Required by | Install |
|--------|-------------|---------|
| [Nuclei](https://github.com/projectdiscovery/nuclei#install-nuclei) | `nuclei` scanner | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [testssl.sh](https://github.com/drwetter/testssl.sh#install) | `testssl` scanner | Clone the repo or install via package manager |

**testssl.sh on Windows:** WhiteRabbit invokes testssl.sh through Git Bash. It
searches PATH first, then falls back to the path in the `WHITERABBIT_TESTSSL_PATH`
environment variable (default: `C:/Tools/testssl/testssl.sh`). Set this variable
if your testssl.sh lives elsewhere:

```bash
set WHITERABBIT_TESTSSL_PATH=D:/path/to/testssl.sh
```

## Usage

```bash
# Scan a target (runs all available scanners)
whiterabbit scan example.com

# Quick scan (SSL + headers only)
whiterabbit scan example.com --quick

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

| Scanner | What it checks | Dependencies |
|---------|---------------|--------------|
| `ssl` | Certificate validation, protocol support, cipher suites, Heartbleed, ROBOT | None (SSLyze, pure Python) |
| `headers` | HSTS, CSP, cookie flags, CORS, HTTPS redirect, and 15+ other HTTP headers | None (httpx, pure Python) |
| `nuclei` | Misconfiguration, exposure, and technology detection via community templates | [Nuclei](https://github.com/projectdiscovery/nuclei#install-nuclei) |
| `retirejs` | Known-vulnerable JavaScript libraries against the retire.js database | None (pure Python) |
| `testssl` | Deep TLS/SSL analysis: BEAST, POODLE, DROWN, FREAK, Logjam, SWEET32, Ticketbleed | [testssl.sh](https://github.com/drwetter/testssl.sh#install) |

## Architecture

Scanners run concurrently via `asyncio.TaskGroup` with per-scanner timeouts.
Every scanner is contractually forbidden from raising — it catches its own
exceptions and returns a `ScanResult` with `error` set. This means a single
broken or timed-out scanner never takes down the run or corrupts other results.

```
CLI (cli.py)
 └─ ScanRunner (runner.py)
     └─ asyncio.TaskGroup
         ├─ SSLScanner        → ScanResult
         ├─ HeaderScanner     → ScanResult
         ├─ NucleiScanner     → ScanResult
         ├─ RetireJSScanner   → ScanResult
         └─ TestSSLScanner    → ScanResult
                 │
                 ▼
         ScanReport (aggregated findings + letter grade)
```

This pattern — concurrent fan-out with fault isolation per task — is the most
reusable idea in the codebase. Each scanner is a single class implementing
`async scan(target, config) -> ScanResult`.

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
(`verify=False`) on outbound requests. This is intentional for target-probing
requests: a security scanner that refuses to connect to misconfigured hosts
cannot assess misconfigured hosts.

The retire.js scanner also uses the same unverified client to download its
vulnerability database from GitHub (`raw.githubusercontent.com`). Ideally the
DB fetch would use a verified connection; this is a known tradeoff documented
in the source.

## Responsible use

Only scan targets you own or have explicit permission to test. WhiteRabbit
sends real HTTP requests and invokes external tools against the target — it is
not a static analyzer. Unauthorized scanning may violate laws and terms of
service.

## Adding a scanner

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding new scanners.

## License

MIT
