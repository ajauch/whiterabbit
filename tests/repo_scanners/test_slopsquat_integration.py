"""Integration tests for the slopsquat scanner using the trendmicro/slopsquatting dataset.

Downloads the public JSONL dataset of AI-hallucinated Python package names and
verifies that our scanner correctly flags them against the live PyPI registry.

Dataset: https://github.com/trendmicro/slopsquatting
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from whiterabbit.config import RepoScanConfig
from whiterabbit.repo_scanner.slopsquat_scanner import SlopsquatScanner
from whiterabbit.report.models import Severity

DATASET_URL = (
    "https://raw.githubusercontent.com/trendmicro/slopsquatting"
    "/main/slopsquatting.jsonl"
)

# Some hallucinated names may have been registered since the dataset was
# published, so we assert a detection *rate* rather than 100%.
MIN_DETECTION_RATE = 0.75


def _fetch_dataset() -> list[dict]:
    """Download and parse the trendmicro slopsquatting JSONL dataset."""
    resp = httpx.get(DATASET_URL, timeout=30, follow_redirects=True)
    resp.raise_for_status()
    return [json.loads(line) for line in resp.text.splitlines() if line.strip()]


def _extract_hallucinated_names(dataset: list[dict]) -> set[str]:
    """Extract all unique hallucinated package names from the dataset."""
    names: set[str] = set()
    for entry in dataset:
        for name in entry.get("modulenotfound", []):
            if name and isinstance(name, str):
                names.add(name)
    return names


def _extract_all_names(dataset: list[dict]) -> tuple[set[str], set[str]]:
    """Extract (hallucinated, real) package name sets from the dataset."""
    hallucinated: set[str] = set()
    real: set[str] = set()
    for entry in dataset:
        all_modules = set(entry.get("modules", []))
        not_found = set(entry.get("modulenotfound", []))
        hallucinated.update(not_found)
        real.update(all_modules - not_found)
    real -= hallucinated
    return hallucinated, real


@pytest.mark.integration
class TestSlopsquatTrendmicroDataset:
    """Validate our scanner against the trendmicro hallucinated-package dataset."""

    def test_detects_hallucinated_packages(self, tmp_path: Path) -> None:
        """Scanner should flag most known-hallucinated packages as non-existent."""
        dataset = _fetch_dataset()
        hallucinated = _extract_hallucinated_names(dataset)
        assert len(hallucinated) > 0, "Dataset returned no hallucinated names"

        (tmp_path / "requirements.txt").write_text(
            "\n".join(sorted(hallucinated)) + "\n"
        )

        scanner = SlopsquatScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None

        flagged_names = {
            f.raw["package"] for f in result.findings if f.severity == Severity.HIGH
        }

        detection_rate = len(flagged_names) / len(hallucinated)
        print(
            f"\nSlopsquat detection: {len(flagged_names)}/{len(hallucinated)} "
            f"({detection_rate:.0%}) hallucinated packages flagged"
        )
        if flagged_names != hallucinated:
            missed = sorted(hallucinated - flagged_names)
            print(f"Missed (may have been registered): {missed}")

        assert detection_rate >= MIN_DETECTION_RATE, (
            f"Detection rate {detection_rate:.0%} is below "
            f"threshold {MIN_DETECTION_RATE:.0%}"
        )

    def test_does_not_flag_real_packages(self, tmp_path: Path) -> None:
        """Scanner should not flag legitimate packages from the dataset."""
        dataset = _fetch_dataset()
        _hallucinated, real = _extract_all_names(dataset)

        # Use a sample of real packages to keep the test fast
        real_sample = sorted(real)[:20]
        assert len(real_sample) > 0, "Dataset returned no real package names"

        (tmp_path / "requirements.txt").write_text("\n".join(real_sample) + "\n")

        scanner = SlopsquatScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None

        false_positives = [f for f in result.findings if f.severity == Severity.HIGH]
        if false_positives:
            fp_names = [f.raw["package"] for f in false_positives]
            print(f"\nFalse positives: {fp_names}")

        assert len(false_positives) == 0, (
            f"Real packages falsely flagged: "
            f"{[f.raw['package'] for f in false_positives]}"
        )

    def test_mixed_manifest_separation(self, tmp_path: Path) -> None:
        """Scanner should flag hallucinated names and pass real ones in one manifest."""
        dataset = _fetch_dataset()
        hallucinated, real = _extract_all_names(dataset)

        hallucinated_sample = sorted(hallucinated)
        real_sample = sorted(real)[:20]
        all_names = hallucinated_sample + real_sample

        (tmp_path / "requirements.txt").write_text("\n".join(all_names) + "\n")

        scanner = SlopsquatScanner()
        config = RepoScanConfig()
        result = asyncio.run(scanner.scan(str(tmp_path), config))

        assert result.error is None

        flagged_names = {
            f.raw["package"] for f in result.findings if f.severity == Severity.HIGH
        }

        correctly_flagged = flagged_names & set(hallucinated_sample)
        false_positives = flagged_names & set(real_sample)

        print(
            f"\nMixed test: {len(correctly_flagged)}/{len(hallucinated_sample)} "
            f"hallucinated flagged, {len(false_positives)} false positives"
        )

        assert len(false_positives) == 0, (
            f"Real packages falsely flagged: {sorted(false_positives)}"
        )
        assert len(correctly_flagged) >= len(hallucinated_sample) * MIN_DETECTION_RATE
