"""Resolve external binaries, including those installed via pip."""

from __future__ import annotations

import os
import shutil
import sys
import sysconfig
from pathlib import Path


def _python_scripts_dirs() -> list[Path]:
    dirs: list[Path] = []
    scheme = "nt_user" if sys.platform == "win32" else "posix_user"
    for key in (scheme, None):
        try:
            raw = (
                sysconfig.get_path("scripts", key)
                if key
                else sysconfig.get_path("scripts")
            )
        except KeyError:
            continue
        if raw:
            dirs.append(Path(raw))
    return dirs


def resolve_binary(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    suffix = ".exe" if sys.platform == "win32" else ""
    for scripts_dir in _python_scripts_dirs():
        candidate = scripts_dir / (name + suffix)
        if candidate.is_file():
            return str(candidate)
    return None


def subprocess_env() -> dict[str, str]:
    """Return an env dict with Python scripts dirs prepended to PATH."""
    env = os.environ.copy()
    extra = [str(d) for d in _python_scripts_dirs() if d.is_dir()]
    if extra:
        sep = os.pathsep
        env["PATH"] = sep.join(extra) + sep + env.get("PATH", "")
    return env
