# WhiteRabbit

A local, open-source web security scanner that aggregates best-in-class tools behind a unified CLI and reporting interface.

## Features

- **SSL/TLS scanning** — certificate validation, protocol checks, cipher suites, Heartbleed, ROBOT (powered by SSLyze)
- **Deep TLS analysis** — BEAST, POODLE, DROWN, FREAK, Logjam, SWEET32, Ticketbleed detection (powered by testssl.sh)
- **HTTP security headers** — HSTS, CSP, cookie flags, CORS, HTTPS redirect, and 15+ other checks
- **Nuclei passive scanning** — misconfiguration, exposure, and technology detection using Nuclei community templates (passive only)
- **JavaScript library scanning** — detects known-vulnerable JS libraries using the retire.js vulnerability database (pure Python)
- **Unified reporting** — terminal, JSON, and HTML output with severity grading (A+ through F)
- **Async scanning** — all scanners run concurrently for fast results
- **Extensible** — add new scanners by implementing a single class

## Installation

```bash
pip install -e ".[dev]"
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

## Available Scanners

| Scanner | Description | Dependencies |
|---------|-------------|--------------|
| `ssl` | SSL/TLS configuration via SSLyze | None (pure Python) |
| `headers` | HTTP security headers, cookies, CORS | None (pure Python) |
| `nuclei` | Misconfiguration and exposure detection (passive only) | [Nuclei](https://github.com/projectdiscovery/nuclei#install-nuclei) |
| `retirejs` | Known-vulnerable JavaScript library detection | None (pure Python) |
| `testssl` | Deep TLS/SSL analysis (complements SSLyze) | [testssl.sh](https://github.com/drwetter/testssl.sh#install) |

## Adding a Scanner

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on adding new scanners.

## License

MIT
