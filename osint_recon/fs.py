"""Filesystem helpers - secure directory and file creation.

All osint-recon report/cache output must be private by default. These helpers
enforce that regardless of the host umask.
"""

from __future__ import annotations

import stat
from pathlib import Path


def secure_dir(path: Path, mode: int = 0o700) -> Path:
    """Create directory and enforce mode, even if it already existed."""
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def secure_file(path: Path, mode: int = 0o600) -> Path:
    """Ensure parent is private, then enforce mode on the file."""
    secure_dir(path.parent)
    if path.exists():
        path.chmod(mode)
    return path


def mode_ok(path: Path, expected: int) -> bool:
    """True if the file/dir has exactly the expected octal mode."""
    try:
        return stat.S_IMODE(path.stat().st_mode) == expected
    except OSError:
        return False
