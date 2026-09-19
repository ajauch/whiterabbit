"""Git clone helper with automatic temp directory cleanup."""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path


@asynccontextmanager
async def clone_repo(
    url: str,
    branch: str | None = None,
    depth: int | None = 1,
    keep: bool = False,
) -> AsyncIterator[Path]:
    """Clone a repo into a temp dir, yield the path, clean up on exit."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="whiterabbit_repo_"))
    repo_dir = tmp_dir / "repo"
    try:
        cmd: list[str] = ["git", "clone"]
        if depth and depth > 0:
            cmd.extend(["--depth", str(depth)])
        if branch:
            cmd.extend(["--branch", branch])
        cmd.extend([url, str(repo_dir)])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            error_msg = stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"git clone failed (exit {proc.returncode}): {error_msg}"
            )

        yield repo_dir
    finally:
        if not keep and tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
