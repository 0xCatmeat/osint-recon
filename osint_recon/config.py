"""Configuration loading and provider enablement.

Reads a simple ``KEY=VALUE`` env file (default ``~/OSINT/config/apis.env``). A provider
is considered enabled only when all of its required keys are present; keyless providers
declare no required keys and are always enabled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ENV_PATH = Path.home() / "OSINT" / "config" / "apis.env"


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip().strip('"').strip("'")
        if val:
            values[key.strip()] = val
    return values


@dataclass
class Config:
    env_path: Path
    values: dict[str, str]

    @classmethod
    def load(cls, env_path: Path | str | None = None) -> "Config":
        path = Path(env_path) if env_path else DEFAULT_ENV_PATH
        return cls(env_path=path, values=_parse_env_file(path))

    def get(self, key: str) -> str | None:
        """File value wins, then process environment, else None."""
        return self.values.get(key) or os.environ.get(key) or None

    def has(self, key: str) -> bool:
        return self.get(key) is not None
