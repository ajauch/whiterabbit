"""HTML report formatter using Jinja2 templates."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from whiterabbit.report.models import ScanReport, Severity

TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent / "templates"


def _severity_class(severity: Severity) -> str:
    return f"severity-{severity.value}"


def format_html(report: ScanReport) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    env.filters["severity_class"] = _severity_class
    template = env.get_template("report.html")
    return template.render(report=report, Severity=Severity)


def write_html(report: ScanReport, path: str) -> None:
    html = format_html(report)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
