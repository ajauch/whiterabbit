# WhiteRabbit — Implementation Plan

A local, open-source web security scanner that aggregates best-in-class open-source tools behind a unified CLI and reporting interface.

---

## Phase 1: Foundation & Core Architecture

**Goal:** Establish the project skeleton, plugin architecture, data models, and CLI — with no scanners yet. Everything after this phase is "just adding scanners."

### 1.1 Project Setup

- Initialize the repository with `pyproject.toml` (PEP 621, using Hatch or Poetry as build backend)
- Python 3.11+ required (for `asyncio.TaskGroup`, `tomllib`, modern typing)
- Directory structure:

```
whiterabbit/
├── pyproject.toml
├── LICENSE                     # MIT
├── README.md
├── src/
│   └── whiterabbit/
│       ├── __init__.py
│       ├── __main__.py         # python -m whiterabbit
│       ├── cli.py              # Typer CLI
│       ├── config.py           # Scan profiles & settings
│       ├── runner.py           # Async orchestrator
│       ├── scanner/
│       │   ├── __init__.py
│       │   └── base.py         # BaseScanner ABC
│       └── report/
│           ├── __init__.py
│           ├── models.py       # Pydantic Finding/ScanResult
│           ├── grader.py       # A-F letter grade
│           └── formatters/
│               ├── __init__.py
│               ├── terminal.py # Rich console output
│               ├── json.py     # JSON report
│               └── html.py     # Self-contained HTML report
├── tests/
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_runner.py
│   └── scanners/
│       └── ...
└── templates/
    └── report.html             # Jinja2 HTML report template
```

- Add `ruff` for linting/formatting, `mypy` for type checking, `pytest` + `pytest-asyncio` for tests
- Add a `Makefile` or `justfile` with targets: `lint`, `typecheck`, `test`, `build`

### 1.2 Data Models (`report/models.py`)

Define Pydantic v2 models that every scanner must produce:

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Finding:
    severity: Severity
    title: str                    # e.g. "Missing Content-Security-Policy header"
    description: str              # Human-readable explanation
    remediation: str              # What to do about it
    category: str                 # e.g. "headers", "ssl", "vuln"
    scanner: str                  # Which scanner found it
    cwe: str | None               # CWE-693, etc.
    cve: str | None               # CVE-2024-XXXX, etc.
    references: list[str]         # URLs to learn more
    raw: dict | None              # Scanner-specific raw data

class ScanResult:
    target: str                   # The scanned URL/host
    scanner_name: str
    started_at: datetime
    finished_at: datetime
    findings: list[Finding]
    error: str | None             # If the scanner failed

class ScanReport:
    target: str
    scan_date: datetime
    duration_seconds: float
    grade: str                    # A+ through F
    summary: dict[Severity, int]  # Count by severity
    results: list[ScanResult]     # Per-scanner results
    whiterabbit_version: str
```

### 1.3 Scanner Plugin Interface (`scanner/base.py`)

```python
class BaseScanner(ABC):
    name: str                      # Machine name, e.g. "ssl"
    display_name: str              # Human name, e.g. "SSL/TLS Scanner"
    description: str               # One-line description
    required_binaries: list[str]   # External tools this scanner needs (empty for pure-Python)

    @abstractmethod
    async def scan(self, target: str, config: ScanConfig) -> ScanResult: ...

    def is_available(self) -> bool:
        """Check if all required_binaries are on PATH."""

    def check_dependencies(self) -> list[str]:
        """Return list of missing dependencies with install instructions."""
```

- Scanners are discovered via a registry dict in `scanner/__init__.py` — no magic autodiscovery
- Each scanner is responsible for catching its own exceptions and returning a `ScanResult` with an `error` field rather than crashing the whole run

### 1.4 Async Runner (`runner.py`)

```python
class ScanRunner:
    async def run(self, target: str, scanners: list[BaseScanner], config: ScanConfig) -> ScanReport:
        """Run all selected scanners concurrently, collect results, compute grade."""
```

- Uses `asyncio.TaskGroup` (Python 3.11+) to run scanners concurrently
- Each scanner gets a configurable timeout (default 5 minutes)
- Progress reporting via callbacks (Rich live display in the terminal)
- If a scanner fails or times out, log the error and continue with the rest

### 1.5 CLI (`cli.py`)

Built with **Typer** + **Rich** for a modern terminal experience.

```
whiterabbit scan <target> [OPTIONS]

Arguments:
  target              URL or hostname to scan (e.g. example.com, https://example.com)

Options:
  --quick             Headers + SSL only (~10 seconds)
  --full              All available scanners (~10+ minutes)
  --scanners TEXT     Comma-separated list of scanners to run (e.g. ssl,headers)
  --output PATH       Write report to file (.json or .html)
  --format TEXT       Output format: terminal (default), json, html
  --timeout INT       Per-scanner timeout in seconds (default 300)
  --no-color          Disable colored output
  --verbose / -v      Show detailed scanner output
  --list-scanners     List all available scanners and exit

whiterabbit check-deps
  Check which scanner dependencies are installed and show install instructions for missing ones.
```

### 1.6 Grading System (`report/grader.py`)

Simple, transparent grading based on finding counts by severity:

| Grade | Criteria |
|-------|----------|
| A+    | 0 findings of any severity |
| A     | Info-only findings |
| B     | Low findings, no medium+ |
| C     | Medium findings, no high+ |
| D     | High findings, no critical |
| F     | Any critical finding |

The grade is computed from the aggregate findings across all scanners. The grading logic is in one function, easy to tune later.

### 1.7 Deliverables for Phase 1

- [x] Project skeleton with pyproject.toml, CI config, linting
- [x] Pydantic data models with full test coverage
- [x] BaseScanner ABC with dependency checking
- [x] Async runner with timeout and error handling
- [x] CLI with all flags (scanners will just be empty at this point)
- [x] Terminal formatter with Rich (colored severity, summary table)
- [x] JSON formatter
- [x] Grading system
- [x] `check-deps` command

**Phase 1 complete.** All 28 core tests passing. CLI produces empty A+ report with no scanners.

---

## Phase 2: SSL/TLS Scanner (SSLyze)

**Goal:** First real scanner. Validates the plugin architecture works end-to-end.

### 2.1 Integration Approach

SSLyze is a pure Python library (`pip install sslyze`). No subprocess calls needed.

```python
from sslyze import Scanner, ServerScanRequest, ScanCommand
```

### 2.2 What It Checks

| Check | Severity | Finding |
|-------|----------|---------|
| Expired certificate | Critical | Certificate expired on {date} |
| Self-signed certificate | Critical | Certificate is self-signed |
| Certificate hostname mismatch | Critical | Cert issued for {names}, scanning {target} |
| SSLv2 / SSLv3 enabled | Critical | {protocol} is enabled — vulnerable to DROWN/POODLE |
| TLS 1.0 / 1.1 enabled | High | {protocol} is deprecated (RFC 8996) |
| TLS 1.3 not supported | Medium | TLS 1.3 not supported |
| Weak cipher suites (RC4, DES, 3DES, NULL, EXPORT) | High | Weak cipher suite: {name} |
| No OCSP stapling | Low | OCSP stapling not enabled |
| Short RSA key (<2048 bits) | High | RSA key is {n} bits (minimum 2048) |
| Heartbleed vulnerable | Critical | Server is vulnerable to Heartbleed (CVE-2014-0160) |
| ROBOT vulnerable | High | Server is vulnerable to ROBOT attack |
| Certificate chain incomplete | Medium | Incomplete certificate chain |
| Certificate expires soon (<30 days) | Medium | Certificate expires in {n} days |

### 2.3 Implementation

- `scanner/ssl_scanner.py` — ~150–200 lines
- Map SSLyze's `ScanCommand` results to `Finding` objects
- Include remediation text for each finding type (e.g., "Disable TLS 1.0 in your server configuration. For Nginx: `ssl_protocols TLSv1.2 TLSv1.3;`")
- Handle connection failures gracefully (host not reachable, no TLS at all)

### 2.4 Tests

- Unit tests with mocked SSLyze results for each finding type
- One integration test against a known public endpoint (e.g., `badssl.com` subdomains: `expired.badssl.com`, `self-signed.badssl.com`, `rc4.badssl.com`)
- Mark integration tests with `@pytest.mark.integration` so they can be skipped in CI

### 2.5 Deliverables for Phase 2

- [x] SSL scanner implementation
- [x] Full unit tests with mocked SSLyze responses (24 tests)
- [ ] Integration tests against badssl.com
- [x] Remediation text for each finding
- [x] End-to-end test: `whiterabbit scan example.com --scanners ssl`

---

## Phase 3: HTTP Security Headers Scanner

**Goal:** Second scanner, fast and high-value. Most sites have header issues.

### 3.1 Integration Approach

Use **humble** (pure Python, actively maintained) or implement custom checks with `httpx`. Given humble's comprehensive coverage (50+ header checks), we'll evaluate it first. If its API isn't cleanly importable, we fall back to a custom implementation using `httpx` — the checks are straightforward HTTP GET + header inspection.

### 3.2 What It Checks

| Check | Severity | Finding |
|-------|----------|---------|
| Missing `Strict-Transport-Security` | High | HSTS header not set — site vulnerable to protocol downgrade |
| HSTS `max-age` too short (<1 year) | Medium | HSTS max-age is {n}s (recommend 31536000) |
| Missing `Content-Security-Policy` | High | No CSP header — site vulnerable to XSS via inline scripts |
| CSP contains `unsafe-inline` or `unsafe-eval` | Medium | CSP allows {directive} — weakens XSS protection |
| Missing `X-Content-Type-Options` | Medium | Missing nosniff — browser may MIME-sniff responses |
| Missing `X-Frame-Options` | Medium | Missing clickjacking protection (or use CSP frame-ancestors) |
| Missing `Referrer-Policy` | Low | No Referrer-Policy — full URL may leak to third parties |
| Missing `Permissions-Policy` | Low | No Permissions-Policy — browser features not restricted |
| `Server` header exposes version | Low | Server header reveals: {value} |
| `X-Powered-By` header present | Low | X-Powered-By reveals: {value} |
| Cookies missing `Secure` flag | High | Cookie "{name}" missing Secure flag |
| Cookies missing `HttpOnly` flag | Medium | Cookie "{name}" missing HttpOnly flag |
| Cookies missing `SameSite` attribute | Medium | Cookie "{name}" missing SameSite attribute |
| CORS wildcard (`Access-Control-Allow-Origin: *`) | Medium | CORS allows any origin |
| HTTP → HTTPS redirect missing | High | Site accessible over plain HTTP without redirect |
| Missing `X-Content-Type-Options: nosniff` | Medium | Missing nosniff header |
| `Cross-Origin-Opener-Policy` missing | Low | No COOP header set |
| `Cross-Origin-Resource-Policy` missing | Low | No CORP header set |

### 3.3 Implementation

- `scanner/header_scanner.py` — ~200–300 lines
- Uses `httpx.AsyncClient` to make requests (follows redirects, checks both HTTP and HTTPS)
- Each check is a small function: `check_hsts(headers) -> list[Finding]`
- Easy to add new header checks without touching other code

### 3.4 Tests

- Unit tests with fixture headers (good site, bad site, partial headers)
- Integration test against a known site
- Test redirect behavior (HTTP → HTTPS)
- Test cookie flag extraction

### 3.5 Deliverables for Phase 3

- [x] Header scanner implementation with all checks above
- [x] Cookie security checks
- [x] CORS misconfiguration checks
- [x] HTTP-to-HTTPS redirect check
- [x] Full unit and integration tests (40 tests)
- [x] End-to-end: `whiterabbit scan example.com --scanners headers`

---

## Phase 4: HTML Report & Polish

**Goal:** Make the output beautiful and useful. A security report people actually want to read.

### 4.1 HTML Report

- Self-contained single HTML file (inline CSS/JS, no external dependencies)
- Jinja2 template in `templates/report.html`
- Sections:
  - **Executive Summary:** Letter grade, scan date, target, finding count by severity
  - **Findings Table:** Sortable by severity, filterable by category
  - **Finding Detail Cards:** Title, severity badge, description, remediation steps, references
  - **Scanner Details:** Which scanners ran, duration, errors if any
- Light and dark theme support via `prefers-color-scheme`
- Print-friendly CSS (`@media print`)

### 4.2 Terminal Output Polish

- Rich panel with grade and summary on scan completion
- Progress spinner per scanner while running
- Color-coded findings table
- `--verbose` flag shows raw scanner data

### 4.3 Documentation

- README with installation instructions, usage examples, screenshots
- `--help` text for every command and option
- `CONTRIBUTING.md` with instructions for adding a new scanner

### 4.4 Deliverables for Phase 4

- [x] HTML report template with Jinja2 (sortable table, category filters, scanner details, dark mode, print CSS)
- [x] Rich terminal progress display (per-scanner live status)
- [x] README with usage examples
- [x] CONTRIBUTING.md (how to add a scanner)
- [x] End-to-end test: full scan with HTML report output (12 tests)

---

## Phase 5: Nuclei Integration (Passive Templates Only)

**Goal:** Add misconfiguration and exposure detection via Nuclei's community templates — **passive/recon templates only**. No exploit payloads, no active fuzzing, no credential brute-forcing.

### 5.1 Design Constraint: Passive Only

All scanning must be non-invasive — indistinguishable from normal browser traffic to WAFs and IDS/IPS. This means:

- **Allowed:** HTTP GET/HEAD requests, technology fingerprinting, exposed file detection, response analysis
- **Blocked:** Exploit payloads, injection tests, brute-force, authentication bypass attempts

Nuclei templates are filtered at invocation to enforce this.

### 5.2 Integration Approach

Nuclei is a Go binary — no Python API. Integration via subprocess + JSON output parsing.

```bash
nuclei -u https://example.com -jsonl -silent -tags exposure,misconfig,tech -exclude-tags fuzz,exploit,intrusive,dos,brute
```

### 5.3 Implementation

- `scanner/nuclei_scanner.py`
- Check that `nuclei` is on PATH; provide install instructions if missing
- Run with `-jsonl` flag, parse each line as a JSON finding
- **Hardcode exclusion of dangerous template tags** (`fuzz`, `exploit`, `intrusive`, `dos`, `brute`, `sqli`, `xss`, `rce`, `auth-bypass`) — not configurable by the user to prevent accidental active scanning
- Allow configuration of passive template categories only (e.g., `--nuclei-tags exposure,misconfig,tech`)
- Map Nuclei's severity levels and template metadata to `Finding` objects
- Template auto-update: run `nuclei -update-templates` on first use or when stale

### 5.4 Checks Covered (Passive Only)

- Exposed sensitive files (`.env`, `.git/config`, `backup.sql`, `.DS_Store`)
- Exposed admin panels and debug endpoints (detection only, no login attempts)
- Technology fingerprinting (CMS, framework, server detection from response headers/body)
- Cloud misconfigurations detectable via HTTP (open S3 bucket listing, Azure blob enumeration)
- WAF detection (identifies which WAF is in front of the target)
- Security.txt and robots.txt analysis
- Default pages and installation artifacts

### 5.5 Deliverables for Phase 5

- [x] Nuclei scanner wrapper with hardcoded passive-only filtering
- [x] JSON output parsing and Finding mapping
- [x] Dependency check with install instructions
- [x] Template update mechanism
- [x] Configuration for passive template categories/tags
- [x] Tests with mocked Nuclei output (21 tests)
- [x] Validation that excluded tags cannot be overridden

---

## Phase 6: JavaScript Library Scanner (retire.js)

**Goal:** Detect known-vulnerable JavaScript libraries served by the target. This is **passive** — it fetches the page and its scripts the same way a browser does, then checks library versions against a vulnerability database.

### 6.1 Integration Approach

retire.js is an npm package. Integration via subprocess + JSON output parsing.

```bash
retire --js --outputformat json --outputpath /dev/stdout --inputurl https://example.com
```

Alternatively, use retire.js's vulnerability database (a JSON file) directly from Python — download the repo's `jsrepository.json`, fetch the target's JS resources with httpx, and match signatures/versions in pure Python (avoids the Node.js dependency).

### 6.2 Why This Is Safe

retire.js only performs standard HTTP GET requests to fetch JavaScript files — exactly what a browser does when visiting the page. No payloads, no fuzzing, no injection. Indistinguishable from a normal page visit.

### 6.3 What It Checks

| Check | Severity | Finding |
|-------|----------|---------|
| jQuery with known XSS CVE | High–Critical | jQuery {version} has known vulnerability {CVE} |
| Outdated Angular.js | High | AngularJS {version} is EOL with known vulnerabilities |
| Vulnerable Bootstrap | Medium | Bootstrap {version} has XSS vulnerability {CVE} |
| Any library in retire.js DB | Varies | {library} {version} — {vulnerability description} |

Maps to **OWASP A06: Vulnerable and Outdated Components**.

### 6.4 Implementation

- `scanner/retirejs_scanner.py` — ~150–200 lines
- **Option A (preferred):** Pure Python — download `jsrepository.json` from the retire.js GitHub repo, fetch target's HTML + linked JS files with httpx, match version signatures against the database. No Node.js dependency.
- **Option B:** Subprocess wrapper around the `retire` CLI (requires Node.js + npm install)
- Extract `<script src="...">` tags and inline scripts from the target page
- Match library fingerprints (filename patterns, file content hashes, version comments)
- Report CVEs, severity, and remediation (upgrade to version X)

### 6.5 Deliverables for Phase 6

- [x] retire.js scanner implementation (pure Python)
- [x] Vulnerability database download/caching mechanism
- [x] JS resource extraction from target HTML
- [x] Finding mapping with CVE references
- [x] Tests with mocked HTTP responses and known-vulnerable library fixtures (20 tests)
- [x] Database staleness check (warn if vuln DB older than 25 days)

---

## Phase 7: Deep TLS Analysis (testssl.sh)

**Goal:** Complement SSLyze (Phase 2) with testssl.sh's broader and deeper TLS/SSL checks. This is **passive** — it only performs TLS handshakes and analyzes server responses, identical to what any connecting client does.

### 7.1 Integration Approach

testssl.sh is a bash script — integration via subprocess + JSON output parsing.

```bash
testssl --jsonfile /dev/stdout --quiet --color 0 https://example.com
```

### 7.2 Why This Is Safe

testssl.sh performs TLS handshakes — the same thing every browser and client does when connecting. No application-layer payloads, no exploitation, no port scanning. It is invisible to WAFs (which operate at HTTP layer) and looks like normal TLS negotiation to IDS/IPS.

### 7.3 Checks (Beyond What SSLyze Already Covers)

| Check | Severity | Finding |
|-------|----------|---------|
| BEAST vulnerability | High | Server vulnerable to BEAST (CBC in TLS 1.0) |
| POODLE (TLS) | High | Server vulnerable to POODLE on TLS |
| Lucky13 | Medium | Server may be vulnerable to Lucky13 timing attack |
| DROWN | Critical | Server vulnerable to DROWN (SSLv2 cross-protocol) |
| FREAK | High | Server vulnerable to FREAK (export cipher downgrade) |
| Logjam | High | Server vulnerable to Logjam (weak DH parameters) |
| SWEET32 | Medium | Server vulnerable to SWEET32 (64-bit block ciphers) |
| Ticketbleed | High | Server vulnerable to Ticketbleed |
| Missing OCSP stapling | Low | OCSP stapling not enabled |
| Certificate transparency | Info | No SCT (Signed Certificate Timestamp) found |
| Cipher order preference | Low | Server does not enforce cipher order |
| Session resumption issues | Info | Session resumption not supported |
| Forward secrecy support | Medium | No forward secrecy ciphers available |

### 7.4 Implementation

- `scanner/testssl_scanner.py` — ~200–250 lines
- Check that `testssl.sh` is on PATH (or bundled); provide install instructions if missing
- Run with `--jsonfile` flag, parse JSON output
- **Deduplicate against SSLyze findings** — skip findings already reported by the SSL scanner to avoid noisy duplicate reports
- Map testssl.sh severity ratings and CVE references to `Finding` objects
- Include remediation text with server-specific config examples (Nginx, Apache, IIS)

### 7.5 Deliverables for Phase 7

- [x] testssl.sh scanner wrapper
- [x] JSON output parsing and Finding mapping
- [x] Deduplication logic against SSLyze SSL scanner findings
- [x] Dependency check with install instructions
- [x] Tests with mocked testssl.sh JSON output (22 tests)
- [x] Remediation text for each finding type

---

## Future Phases (Not Planned in Detail)

These are ideas for after the core scanner is solid:

- **DNS Security:** DNSSEC validation, CAA records, SPF/DKIM/DMARC for mail domains (passive — DNS lookups only)
- **Subdomain Discovery:** Integrate `subfinder` or `amass` for recon (passive — DNS/CT log enumeration, no brute-forcing)
- **Mozilla Observatory Integration:** Complement the header scanner with Observatory's scoring and SRI checks
- **Comparison Reports:** Re-scan and diff against a previous report to show improvement
- **CI/CD Integration:** Exit code based on grade threshold (`whiterabbit scan example.com --fail-below B`)
- **Configuration File:** `.whiterabbit.toml` for per-project scan settings
- **Scanner Auto-Install:** Offer to install missing binaries (Nuclei, testssl.sh) via package managers

> **Design principle:** All scanners must be **passive and non-invasive**. WhiteRabbit only sends traffic that is indistinguishable from normal browser/client behavior (HTTP GETs, TLS handshakes, DNS lookups). No exploit payloads, no active fuzzing, no port scanning, no brute-forcing. This ensures scans do not trigger WAFs, IDS/IPS, or rate limiters on the target.

---

## Tech Stack Summary

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Python 3.11+ | Best scanner ecosystem, native imports for SSLyze and retire.js vuln DB |
| CLI | Typer | Modern, type-hint-based, auto-generated help |
| Terminal UI | Rich | Progress bars, tables, colored output, panels |
| Data models | Pydantic v2 | Validation, serialization, JSON schema generation |
| HTTP client | httpx | Async support, HTTP/2, modern API |
| Templates | Jinja2 | HTML report generation |
| Testing | pytest + pytest-asyncio | Async test support, fixtures, markers |
| Linting | Ruff | Fast, replaces flake8 + isort + black |
| Type checking | mypy | Catch type errors before runtime |
| Build | Hatch | Modern Python packaging |

---

## Implementation Order & Estimated Effort

| Phase | Description | Depends On | Effort |
|-------|-------------|------------|--------|
| 1 | Foundation & Core Architecture | — | 2–3 days |
| 2 | SSL/TLS Scanner (SSLyze) | Phase 1 | 1–2 days |
| 3 | HTTP Headers Scanner | Phase 1 | 1–2 days |
| 4 | HTML Report & Polish | Phase 2, 3 | 1–2 days |
| 5 | Nuclei (passive recon only) | Phase 1 | 1–2 days |
| 6 | retire.js (JS vulnerability detection) | Phase 1 | 1–2 days |
| 7 | testssl.sh (deep TLS analysis) | Phase 2 | 1 day |

**Phases 2 and 3 can be done in parallel** since both only depend on Phase 1. **Phases 5, 6, and 7 can also be done in parallel** (7 depends on Phase 2 for deduplication logic, but 5 and 6 are independent).

**Minimum viable product: Phases 1–4** (~6–9 days). This gives you SSL + header scanning, terminal + JSON + HTML output, and a polished CLI. Enough to be genuinely useful.

> **All phases are passive.** Every scanner only sends traffic indistinguishable from normal browsing — HTTP GETs and TLS handshakes. No phase will trigger WAFs, IDS/IPS, or rate limiters.
