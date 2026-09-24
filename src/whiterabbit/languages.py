"""Detect programming languages in a repository by file extension."""

from __future__ import annotations

from pathlib import Path

EXTENSION_MAP: dict[str, str] = {
    ".py": "Python",
    ".pyi": "Python",
    ".pyx": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cxx": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".hxx": "C++",
    ".cs": "C#",
    ".fs": "F#",
    ".fsx": "F#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C",
    ".dart": "Dart",
    ".lua": "Lua",
    ".r": "R",
    ".R": "R",
    ".jl": "Julia",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".hrl": "Erlang",
    ".hs": "Haskell",
    ".clj": "Clojure",
    ".cljs": "Clojure",
    ".pl": "Perl",
    ".pm": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".psm1": "PowerShell",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "Sass",
    ".less": "Less",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".sql": "SQL",
    ".tf": "HCL",
    ".hcl": "HCL",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".json": "JSON",
    ".xml": "XML",
    ".toml": "TOML",
    ".ini": "INI",
    ".cfg": "INI",
    ".md": "Markdown",
    ".rst": "reStructuredText",
    ".proto": "Protocol Buffers",
    ".graphql": "GraphQL",
    ".gql": "GraphQL",
    ".sol": "Solidity",
    ".zig": "Zig",
    ".nim": "Nim",
    ".v": "V",
    ".groovy": "Groovy",
    ".gradle": "Groovy",
    ".cmake": "CMake",
    ".mk": "Makefile",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".tox",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
    "target",
    "vendor",
    ".next",
    ".nuxt",
}


def detect_languages(repo_path: str | Path) -> dict[str, int]:
    """Walk a repository and return {language: byte_count}, sorted by bytes descending."""
    counts: dict[str, int] = {}
    root = Path(repo_path)

    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        lang = EXTENSION_MAP.get(path.suffix.lower()) or EXTENSION_MAP.get(path.suffix)
        if lang is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        counts[lang] = counts.get(lang, 0) + size

    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
