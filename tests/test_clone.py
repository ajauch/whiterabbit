"""Tests for the repo cloning helper."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from whiterabbit.repo_scanner.clone import clone_repo

_EXEC_PATH = "whiterabbit.repo_scanner.clone.asyncio.create_subprocess_exec"
_RMTREE_PATH = "whiterabbit.repo_scanner.clone.shutil.rmtree"


def _make_proc_mock(returncode: int = 0, stderr: bytes = b"") -> AsyncMock:
    proc = AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(b"", stderr))
    return proc


class TestCloneRepo:
    def test_successful_clone(self) -> None:
        proc = _make_proc_mock()
        with patch(_EXEC_PATH, return_value=proc) as mock_exec:

            async def _run() -> Path:
                async with clone_repo("https://github.com/user/repo") as repo_dir:
                    assert repo_dir.name == "repo"
                    return repo_dir

            asyncio.run(_run())
            mock_exec.assert_called_once()
            cmd = mock_exec.call_args[0]
            assert "git" in cmd
            assert "clone" in cmd
            assert "--depth" in cmd
            assert "1" in cmd

    def test_clone_with_branch(self) -> None:
        proc = _make_proc_mock()
        with patch(_EXEC_PATH, return_value=proc) as mock_exec:

            async def _run() -> None:
                async with clone_repo("https://github.com/user/repo", branch="develop"):
                    pass

            asyncio.run(_run())
            cmd = mock_exec.call_args[0]
            assert "--branch" in cmd
            assert "develop" in cmd

    def test_clone_full_depth(self) -> None:
        proc = _make_proc_mock()
        with patch(_EXEC_PATH, return_value=proc) as mock_exec:

            async def _run() -> None:
                async with clone_repo("https://github.com/user/repo", depth=None):
                    pass

            asyncio.run(_run())
            cmd = mock_exec.call_args[0]
            assert "--depth" not in cmd

    def test_clone_failure_raises(self) -> None:
        proc = _make_proc_mock(returncode=128, stderr=b"fatal: repo not found")
        with patch(_EXEC_PATH, return_value=proc):

            async def _run() -> None:
                async with clone_repo("https://github.com/user/nonexistent"):
                    pass

            with pytest.raises(RuntimeError, match="git clone failed"):
                asyncio.run(_run())

    def test_cleanup_on_success(self) -> None:
        proc = _make_proc_mock()
        with (
            patch(_EXEC_PATH, return_value=proc),
            patch(_RMTREE_PATH) as mock_rmtree,
        ):

            async def _run() -> None:
                async with clone_repo("https://github.com/user/repo"):
                    pass

            asyncio.run(_run())
            mock_rmtree.assert_called_once()

    def test_keep_clone_skips_cleanup(self) -> None:
        proc = _make_proc_mock()
        with (
            patch(_EXEC_PATH, return_value=proc),
            patch(_RMTREE_PATH) as mock_rmtree,
        ):

            async def _run() -> None:
                async with clone_repo("https://github.com/user/repo", keep=True):
                    pass

            asyncio.run(_run())
            mock_rmtree.assert_not_called()

    def test_cleanup_on_error(self) -> None:
        proc = _make_proc_mock(returncode=128, stderr=b"fatal: error")
        with (
            patch(_EXEC_PATH, return_value=proc),
            patch(_RMTREE_PATH) as mock_rmtree,
        ):

            async def _run() -> None:
                async with clone_repo("https://github.com/user/repo"):
                    pass

            with pytest.raises(RuntimeError):
                asyncio.run(_run())
            mock_rmtree.assert_called_once()
