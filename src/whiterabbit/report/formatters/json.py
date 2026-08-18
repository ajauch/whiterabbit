"""JSON report formatter."""

from __future__ import annotations

import json

from whiterabbit.report.models import ScanReport


def format_json(report: ScanReport) -> str:
    return report.model_dump_json(indent=2)


def write_json(report: ScanReport, path: str) -> None:
    data = json.loads(format_json(report))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
