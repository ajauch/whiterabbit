# Contributing to WhiteRabbit

## Adding a New Scanner

WhiteRabbit is designed to make adding scanners straightforward. Here's how:

### 1. Create the scanner file

Create `src/whiterabbit/scanner/your_scanner.py`:

```python
from __future__ import annotations
from datetime import datetime, timezone
from whiterabbit.config import ScanConfig
from whiterabbit.report.models import Finding, ScanResult, Severity
from whiterabbit.scanner.base import BaseScanner

class YourScanner(BaseScanner):
    name = "your_scanner"              # Machine name, used in --scanners flag
    display_name = "Your Scanner"      # Human-readable name
    description = "What it checks"     # One-line description
    required_binaries = []             # e.g. ["nmap"] if it needs an external binary

    async def scan(self, target: str, config: ScanConfig) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []

        try:
            # Your scanning logic here
            # Append Finding objects to findings list
            pass
        except Exception as exc:
            return ScanResult(
                target=target,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                error=str(exc),
            )

        return ScanResult(
            target=target,
            scanner_name=self.name,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
        )
```

### 2. Register it

Add your scanner to `src/whiterabbit/scanner/__init__.py`:

```python
from whiterabbit.scanner.your_scanner import YourScanner

SCANNER_REGISTRY: dict[str, type[BaseScanner]] = {
    # ... existing scanners ...
    "your_scanner": YourScanner,
}
```

### 3. Write tests

Create `tests/scanners/test_your_scanner.py` with:
- Unit tests using mocked responses for each finding type
- At least one end-to-end test (can be marked `@pytest.mark.integration`)

### Key rules

- **Never crash the runner.** Catch all exceptions and return a `ScanResult` with an `error` field.
- **Include remediation text** for every finding — tell the user what to do, not just what's wrong.
- **Set CWE/CVE** when applicable.
- **Use `config.timeout`** — the runner enforces it, but be a good citizen.
- **External binaries** go in `required_binaries` so `check-deps` reports them.

## Development Setup

```bash
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
```

Skip integration tests (those that hit external services):
```bash
pytest tests/ -v -m "not integration"
```

## Linting

```bash
ruff check src/ tests/
ruff format src/ tests/
```
