## What

<!-- One-sentence summary of the change -->

## Why

<!-- What problem does this solve or what feature does it add? Link to an issue if applicable. -->

## How to test

- [ ] `pytest tests/ -v -m "not integration"` passes
- [ ] `ruff check src/ tests/` passes
- [ ] `mypy src/` passes
- [ ] <!-- Any manual verification steps -->

## Checklist

- [ ] I've read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] New/changed scanner catches all exceptions and returns `ScanResult` with `error` set
- [ ] Findings include remediation text
- [ ] Tests added for new functionality
