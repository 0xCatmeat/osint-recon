from __future__ import annotations

import stat
from pathlib import Path


def secure_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    return path


def secure_file(path: Path, mode: int = 0o600) -> Path:
    secure_dir(path.parent)
    if path.exists():
        path.chmod(mode)
    return path


def mode_ok(path: Path, expected: int) -> bool:
    try:
        return stat.S_IMODE(path.stat().st_mode) == expected
    except OSError:
        return False
