"""Tests for shared manifest parsing module."""

from __future__ import annotations

import json
from pathlib import Path

from whiterabbit.repo_scanner.manifest import extract_package_names


class TestExtractPackageNames:
    def test_pinned_requirements(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
        result = extract_package_names(str(tmp_path))
        assert "PyPI" in result
        assert "requests" in result["PyPI"]
        assert "flask" in result["PyPI"]

    def test_unpinned_requirements(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests>=2.0\nflask\n")
        result = extract_package_names(str(tmp_path))
        assert "PyPI" in result
        assert "requests" in result["PyPI"]
        assert "flask" in result["PyPI"]

    def test_mixed_requirements(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "requests==2.31.0\nflask>=3.0\ndjango\n"
        )
        result = extract_package_names(str(tmp_path))
        assert result["PyPI"] == {"requests", "flask", "django"}

    def test_requirements_ignores_comments_and_flags(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text(
            "# comment\n-r other.txt\nrequests>=2.0\n"
        )
        result = extract_package_names(str(tmp_path))
        assert result["PyPI"] == {"requests"}

    def test_pyproject_all_deps(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            "[project]\ndependencies = [\n"
            '  "requests==2.31.0",\n'
            '  "flask>=3.0",\n'
            '  "django",\n'
            "]\n"
        )
        result = extract_package_names(str(tmp_path))
        assert "PyPI" in result
        assert "requests" in result["PyPI"]
        assert "flask" in result["PyPI"]
        assert "django" in result["PyPI"]

    def test_package_json(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "dependencies": {"express": "^4.18.2"},
                    "devDependencies": {"jest": "~29.7.0"},
                }
            )
        )
        result = extract_package_names(str(tmp_path))
        assert "npm" in result
        assert "express" in result["npm"]
        assert "jest" in result["npm"]

    def test_skips_lockfiles(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "myapp"},
                        "node_modules/lodash": {"version": "4.17.21"},
                    },
                }
            )
        )
        result = extract_package_names(str(tmp_path))
        assert result == {}

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "evil-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            json.dumps({"dependencies": {"hidden": "^1.0.0"}})
        )
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"express": "^4.18.2"}})
        )
        result = extract_package_names(str(tmp_path))
        assert "express" in result["npm"]
        assert "hidden" not in result.get("npm", set())

    def test_deduplication_across_manifests(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "requirements.txt").write_text("requests>=2.0\nflask\n")
        result = extract_package_names(str(tmp_path))
        assert result["PyPI"] == {"requests", "flask"}

    def test_no_manifests(self, tmp_path: Path) -> None:
        result = extract_package_names(str(tmp_path))
        assert result == {}

    def test_empty_manifests(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("")
        (tmp_path / "package.json").write_text(json.dumps({"name": "test"}))
        result = extract_package_names(str(tmp_path))
        assert result == {}

    def test_mixed_ecosystems(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask>=3.0\n")
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"react": "^18.0.0"}})
        )
        result = extract_package_names(str(tmp_path))
        assert "PyPI" in result
        assert "npm" in result
        assert "flask" in result["PyPI"]
        assert "react" in result["npm"]

    def test_scoped_npm_package(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": {"@types/node": "^20.0.0"}})
        )
        result = extract_package_names(str(tmp_path))
        assert "@types/node" in result["npm"]

    def test_subdirectory_manifests(self, tmp_path: Path) -> None:
        backend = tmp_path / "backend"
        backend.mkdir()
        (backend / "requirements.txt").write_text("django>=4.2\n")
        frontend = tmp_path / "frontend"
        frontend.mkdir()
        (frontend / "package.json").write_text(
            json.dumps({"dependencies": {"react": "^18.0.0"}})
        )
        result = extract_package_names(str(tmp_path))
        assert "django" in result["PyPI"]
        assert "react" in result["npm"]
