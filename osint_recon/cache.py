from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from osint_recon.fs import secure_dir, secure_file

DEFAULT_CACHE_PATH = Path.home() / "OSINT" / ".cache" / "osint-recon.sqlite"

# provider -> (max_calls, window_seconds)
RATE_LIMITS: dict[str, tuple[int, float]] = {
    "virustotal": (4, 60.0),
    "abuseipdb": (1000, 86_400.0),
    "netlas": (50, 86_400.0),
    "shodan": (1, 1.0),
    "urlscan": (60, 3_600.0),
    "etherscan": (5, 1.0),
    "rdap": (10, 1.0),
    "crtsh": (1, 2.0),
}


@dataclass(frozen=True)
class CacheEntry:
    value: Any
    stored_at: float
    ttl: float


class Store:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_CACHE_PATH
        secure_dir(self.path.parent)
        self.db = sqlite3.connect(str(self.path))
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS cache "
            "(provider TEXT, key TEXT, value TEXT, stored_at REAL, ttl REAL, "
            "PRIMARY KEY (provider, key))"
        )
        self.db.execute("CREATE TABLE IF NOT EXISTS calls (provider TEXT, ts REAL)")
        self.db.commit()
        secure_file(self.path)

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get_entry(
        self,
        provider: str,
        key: str,
        *,
        bypass_cache: bool = False,
        max_age: float | None = None,
    ) -> CacheEntry | None:
        if bypass_cache:
            return None
        row = self.db.execute(
            "SELECT value, stored_at, ttl FROM cache WHERE provider=? AND key=?",
            (provider, key),
        ).fetchone()
        if row is None:
            return None
        value, stored_at, ttl = row
        if max_age is not None and time.time() - stored_at > max_age:
            return None
        if ttl and time.time() - stored_at > ttl:
            return None
        return CacheEntry(value=json.loads(value), stored_at=stored_at, ttl=ttl)

    def get(self, provider: str, key: str) -> Any | None:
        entry = self.get_entry(provider, key)
        return entry.value if entry else None

    def put(self, provider: str, key: str, value: Any, ttl: float = 86_400.0) -> float:
        stored_at = time.time()
        self.db.execute(
            "INSERT OR REPLACE INTO cache VALUES (?,?,?,?,?)",
            (provider, key, json.dumps(value), stored_at, ttl),
        )
        self.db.commit()
        return stored_at

    def throttle(self, provider: str) -> None:
        limit = RATE_LIMITS.get(provider)
        if not limit:
            return
        max_calls, window = limit
        now = time.time()
        self.db.execute("DELETE FROM calls WHERE ts < ?", (now - window,))
        recent = self.db.execute(
            "SELECT COUNT(*) FROM calls WHERE provider=? AND ts >= ?",
            (provider, now - window),
        ).fetchone()[0]
        if recent >= max_calls:
            oldest = self.db.execute(
                "SELECT MIN(ts) FROM calls WHERE provider=? AND ts >= ?",
                (provider, now - window),
            ).fetchone()[0]
            sleep_for = max(0.0, (oldest + window) - now)
            if sleep_for:
                time.sleep(sleep_for)
        self.db.execute("INSERT INTO calls VALUES (?,?)", (provider, time.time()))
        self.db.commit()
