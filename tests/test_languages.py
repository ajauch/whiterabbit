"""Tests for the language detection module."""

from __future__ import annotations

from pathlib import Path

from whiterabbit.languages import detect_languages


class TestDetectLanguages:
    def test_detects_by_extension(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("print('hello')\n")
        (tmp_path / "app.rs").write_text("fn main() {}\n")
        (tmp_path / "util.go").write_text("package main\n")

        result = detect_languages(tmp_path)

        assert "Python" in result
        assert "Rust" in result
        assert "Go" in result

    def test_sorted_by_bytes_descending(self, tmp_path: Path) -> None:
        (tmp_path / "big.py").write_text("x" * 1000)
        (tmp_path / "small.js").write_text("x" * 100)

        result = detect_languages(tmp_path)
        langs = list(result.keys())

        assert langs[0] == "Python"
        assert langs[1] == "JavaScript"

    def test_skips_git_and_node_modules(self, tmp_path: Path) -> None:
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config.py").write_text("x" * 100)

        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "dep.js").write_text("x" * 100)

        (tmp_path / "real.py").write_text("x" * 50)

        result = detect_languages(tmp_path)

        assert result == {"Python": 50}

    def test_empty_repo(self, tmp_path: Path) -> None:
        result = detect_languages(tmp_path)
        assert result == {}

    def test_unknown_extensions_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "data.xyz").write_text("stuff")
        (tmp_path / "binary.bin").write_bytes(b"\x00" * 100)

        result = detect_languages(tmp_path)
        assert result == {}

    def test_counts_bytes_correctly(self, tmp_path: Path) -> None:
        content = "hello world"
        (tmp_path / "a.py").write_text(content)
        (tmp_path / "b.py").write_text(content)

        result = detect_languages(tmp_path)
        expected = (tmp_path / "a.py").stat().st_size + (
            tmp_path / "b.py"
        ).stat().st_size
        assert result["Python"] == expected
