"""Provider base class, HTTP helper, and query machinery."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from osint_recon.config import Config
from osint_recon.schema import Finding

USER_AGENT = "osint-recon/0.1 (OSINT toolkit)"


@dataclass
class Health:
    provider: str
    ok: bool
    detail: str
    enabled: bool = True


@dataclass
class Fetched:
    provider: str
    source_url: str
    raw_bytes: bytes
    findings: list[Finding]
    cache_hit: bool = False
    fetched_at: str = ""
    cached_at: str = ""
    ttl_seconds: float = 0.0


def epoch_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Provider:
    """Base for all providers.

    Subclasses set ``name`` / ``requires`` / ``supported_artifacts`` and implement
    ``health`` plus (for queryable providers) ``source_url`` / ``fetch`` / ``parse``.
    """

    name: str = "base"
    requires: tuple[str, ...] = ()  # env keys required to enable; empty == keyless
    supported_artifacts: tuple[str, ...] = ()  # artifact types query() handles
    cache_ttl_seconds: float = 86_400.0

    def __init__(self, config: Config) -> None:
        self.config = config

    def enabled(self) -> bool:
        return all(self.config.has(key) for key in self.requires)

    def supports(self, artifact_type: str) -> bool:
        return self.enabled() and artifact_type in self.supported_artifacts

    def health(self) -> Health:
        raise NotImplementedError

    def _disabled(self) -> Health:
        missing = ", ".join(key for key in self.requires if not self.config.has(key))
        return Health(self.name, ok=False, detail=f"disabled (set {missing})", enabled=False)

    def source_url(self, artifact: str, artifact_type: str) -> str:
        """Canonical, secret-free URL for this lookup (for provenance/sources)."""
        raise NotImplementedError

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        """Perform the HTTP request (adds auth) and return the response."""
        raise NotImplementedError

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        """Pure: map a parsed response into Findings."""
        raise NotImplementedError

    def query(
        self,
        artifact: str,
        artifact_type: str,
        store: Any = None,
        *,
        offline: bool = False,
        bypass_cache: bool = False,
        max_age: float | None = None,
    ) -> Fetched:
        src = self.source_url(artifact, artifact_type)
        cache_key = f"{artifact_type}:{src}"
        entry = (
            store.get_entry(self.name, cache_key, bypass_cache=bypass_cache, max_age=max_age)
            if store is not None
            else None
        )
        cache_hit = entry is not None
        raw_text = entry.value if entry is not None else None
        cached_at = epoch_iso(entry.stored_at) if entry is not None else ""
        ttl_seconds = float(entry.ttl) if entry is not None else 0.0
        fetched_at = cached_at
        if raw_text is None:  # cache miss
            if offline:
                raise RuntimeError("offline: no cached data available")
            if store is not None:
                store.throttle(self.name)
            resp = self.fetch(artifact, artifact_type)
            if resp.status_code == 404:  # provider has no data; not an error, not cached
                return Fetched(
                    self.name,
                    src,
                    resp.content,
                    [],
                    cache_hit=False,
                    fetched_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                )
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")
            raw_text = resp.text
            if store is not None:
                stored_at = store.put(self.name, cache_key, raw_text, ttl=self.cache_ttl_seconds)
                fetched_at = epoch_iso(stored_at)
                ttl_seconds = self.cache_ttl_seconds
            else:
                fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw_bytes = raw_text.encode("utf-8")
        try:
            raw = json.loads(raw_bytes)
        except ValueError:
            raw = {}
        findings = self.parse(raw, artifact, artifact_type)
        for finding in findings:
            finding.source_url = src
        return Fetched(
            self.name,
            src,
            raw_bytes,
            findings,
            cache_hit=cache_hit,
            fetched_at=fetched_at,
            cached_at=cached_at,
            ttl_seconds=ttl_seconds,
        )

    def _finding(
        self,
        artifact: str,
        artifact_type: str,
        finding: str,
        *,
        selector: str = "",
        confidence: str = "medium",
        risk_level: str = "info",
        tlp: str = "amber",
    ) -> Finding:
        return Finding(
            target=artifact,
            artifact_type=artifact_type,
            source_tool=self.name,
            finding=finding,
            selector=selector,
            confidence=confidence,
            risk_level=risk_level,
            tlp=tlp,
        )

    @staticmethod
    def client(timeout: float = 20.0) -> httpx.Client:
        return httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
