from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from osint_recon.config import Config
from osint_recon.schema import Finding, utcnow_iso

USER_AGENT = "osint-recon/0.1 (OSINT toolkit)"
BIN_DIR = Path.home() / "OSINT" / "bin"
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _version_line(text: str) -> str:
    lines = [_ANSI_RE.sub("", line).strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    if not lines:
        return "ok"
    return next((line for line in reversed(lines) if "version" in line.lower()), lines[-1])


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


def jsonl_to_array(stdout: bytes) -> bytes:
    # Several local tools emit one JSON object per line. That is not valid JSON on
    # its own, and the cache and parse path expect a single document, so join it up.
    entries: list[Any] = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return json.dumps(entries).encode("utf-8")


class Provider:
    name: str = "base"
    requires: tuple[str, ...] = ()
    supported_artifacts: tuple[str, ...] = ()
    cache_ttl_seconds: float = 86_400.0
    active: bool = False

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
        raise NotImplementedError

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        raise NotImplementedError

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        raise NotImplementedError

    def _run_cached(
        self,
        store: Any,
        *,
        cache_key: str,
        source_url: str,
        do_fetch: Callable[[], httpx.Response],
        do_parse: Callable[[Any], list[Finding]],
        ttl: float,
        offline: bool = False,
        bypass_cache: bool = False,
        max_age: float | None = None,
    ) -> Fetched:
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
        if raw_text is None:
            if offline:
                raise RuntimeError("offline: no cached data available")
            if store is not None:
                store.throttle(self.name)
            resp = do_fetch()
            if resp.status_code == 404:
                # No record for this artifact. Not an error, and not worth caching.
                return Fetched(
                    self.name,
                    source_url,
                    resp.content,
                    [],
                    cache_hit=False,
                    fetched_at=utcnow_iso(),
                )
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}")
            raw_text = resp.text
            if store is not None:
                stored_at = store.put(self.name, cache_key, raw_text, ttl=ttl)
                fetched_at = epoch_iso(stored_at)
                ttl_seconds = ttl
            else:
                fetched_at = utcnow_iso()
        raw_bytes = raw_text.encode("utf-8")
        try:
            raw = json.loads(raw_bytes)
        except ValueError:
            raw = {}
        findings = do_parse(raw)
        for finding in findings:
            finding.source_url = source_url
        return Fetched(
            self.name,
            source_url,
            raw_bytes,
            findings,
            cache_hit=cache_hit,
            fetched_at=fetched_at,
            cached_at=cached_at,
            ttl_seconds=ttl_seconds,
        )

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
        return self._run_cached(
            store,
            cache_key=f"{artifact_type}:{src}",
            source_url=src,
            do_fetch=lambda: self.fetch(artifact, artifact_type),
            do_parse=lambda raw: self.parse(raw, artifact, artifact_type),
            ttl=self.cache_ttl_seconds,
            offline=offline,
            bypass_cache=bypass_cache,
            max_age=max_age,
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


class LocalBinaryProvider(Provider):
    binary_name: str = ""
    version_args: tuple[str, ...] = ("-version",)
    run_timeout: float = 60.0

    def _binary(self) -> Path:
        return BIN_DIR / self.binary_name

    def enabled(self) -> bool:
        binary = self._binary()
        return binary.is_file() and bool(binary.stat().st_mode & 0o100)

    def health(self) -> Health:
        binary = self._binary()
        if not binary.is_file():
            return Health(self.name, ok=False, detail=f"binary not found: {binary}", enabled=False)
        if not binary.stat().st_mode & 0o100:
            return Health(
                self.name, ok=False, detail=f"binary not executable: {binary}", enabled=False
            )
        try:
            result = subprocess.run(
                [str(binary), *self.version_args],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return Health(self.name, ok=False, detail=f"version check failed: {exc}", enabled=False)
        if result.returncode != 0:
            return Health(
                self.name,
                ok=False,
                detail=f"binary exited {result.returncode}: {result.stderr.strip()}",
                enabled=False,
            )
        version = _version_line(f"{result.stdout}\n{result.stderr}")
        return Health(self.name, ok=True, detail=f"keyless; {version}")

    def _argv(self, artifact: str, artifact_type: str) -> list[str]:
        raise NotImplementedError

    def _stdin(self, artifact: str, artifact_type: str) -> bytes | None:
        return None

    def _body(self, stdout: bytes) -> bytes:
        return stdout

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        binary = self._binary()
        try:
            result = subprocess.run(
                [str(binary), *self._argv(artifact, artifact_type)],
                input=self._stdin(artifact, artifact_type),
                capture_output=True,
                timeout=self.run_timeout,
            )
        except FileNotFoundError:
            raise RuntimeError(f"binary not found: {binary}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"{self.name} timed out for {artifact}")
        # Some tools exit nonzero on partial errors but still print usable output.
        if result.returncode != 0 and not result.stdout.strip():
            stderr = result.stderr.decode(errors="replace").strip()
            raise RuntimeError(f"{self.name} exited {result.returncode}: {stderr}")
        return httpx.Response(
            200,
            content=self._body(result.stdout),
            request=httpx.Request("GET", self.source_url(artifact, artifact_type)),
        )
