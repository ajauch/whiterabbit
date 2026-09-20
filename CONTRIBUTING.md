# Contributing to WhiteRabbit

Thanks for your interest in contributing! This guide covers the general
workflow and the scanner-specific process.

## Getting started

1. Fork the repo and clone your fork
2. Create a branch from `master`:
   ```bash
   git checkout -b my-feature
   ```
3. Install in development mode:
   ```bash
   pip install -e ".[dev]"
   ```
4. Install the pre-commit hooks:
   ```bash
   pre-commit install
   ```

This ensures every commit is automatically checked for lint, formatting, type
errors, and test failures — the same checks CI runs.

## Making changes

- Keep PRs focused — one bug fix or feature per PR.
- Follow the existing code style. Ruff enforces it automatically.
- Add tests for new functionality.
- Update `CHANGELOG.md` under an `[Unreleased]` section.

## Running the checks

The pre-commit hooks run these automatically on every commit. To run them
manually:

```bash
pytest tests/ -v -m "not integration"
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
```

To auto-format:

```bash
ruff format src/ tests/
```

## Submitting a pull request

1. Push your branch to your fork
2. Open a PR against `master`
3. Fill out the PR template
4. Make sure CI passes

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/ajauch/whiterabbit/issues/new/choose)
on GitHub. For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

---

## Adding a new web scanner

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

---

## Adding a new repo scanner

Repo scanners follow the same pattern as web scanners but operate on a local
directory (a cloned repo or existing project) instead of a live URL.

### 1. Create the scanner file

Create `src/whiterabbit/repo_scanner/your_scanner.py`:

```python
from __future__ import annotations
from datetime import datetime, timezone
from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.base import BaseRepoScanner
from whiterabbit.report.models import Finding, ScanResult, Severity

class YourScanner(BaseRepoScanner):
    name = "your_scanner"              # Machine name, used in --scanners flag
    display_name = "Your Scanner"      # Human-readable name
    description = "What it checks"     # One-line description
    required_binaries = []             # e.g. ["semgrep"] if it needs an external binary

    async def scan(self, repo_path: str, config: RepoScanConfig) -> ScanResult:
        started = datetime.now(timezone.utc)
        findings: list[Finding] = []

        try:
            # Your scanning logic here — repo_path is a local directory
            pass
        except Exception as exc:
            return ScanResult(
                target=repo_path,
                scanner_name=self.name,
                started_at=started,
                finished_at=datetime.now(timezone.utc),
                error=str(exc),
            )

        return ScanResult(
            target=repo_path,
            scanner_name=self.name,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            findings=findings,
        )
```

### 2. Register it

Add your scanner to `src/whiterabbit/repo_scanner/__init__.py`:

```python
from whiterabbit.repo_scanner.your_scanner import YourScanner

REPO_SCANNER_REGISTRY: dict[str, type[BaseRepoScanner]] = {
    # ... existing scanners ...
    "your_scanner": YourScanner,
}
```

### 3. Write tests

Create `tests/repo_scanners/test_your_scanner.py` with:
- Unit tests using mocked responses (no network calls, no real subprocess)
- At least one end-to-end test (can be marked `@pytest.mark.integration`)

### 4. Provide public test repos

If your scanner targets a specific language or ecosystem, your PR must include
**at least three public repositories** that can be used as real-world test
targets. These should be:

- **Large enough** to exercise the scanner meaningfully (not toy projects)
- **Permissively licensed** (MIT, Apache 2.0, etc.) so anyone can clone them
- **Likely to contain findings** — the point is to verify the scanner produces
  useful output, not to scan pristine code

List them in your PR description with a short note on why each is a good target.
For example, a C# scanner PR might reference `dotnet/aspnetcore`,
`bitwarden/server`, and `jellyfin/jellyfin`.

### Key rules

Same as web scanners, plus:
- **`scan()` receives a local path**, not a URL. The clone/cleanup lifecycle is handled by the CLI.
- **Use `RepoScanConfig`** instead of `ScanConfig` — it includes repo-specific options like `branch` and `depth`.
