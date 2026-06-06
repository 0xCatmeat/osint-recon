"""Subfinder - passive subdomain enumeration via local binary (keyless)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


class SubfinderProvider(Provider):
    name = "subfinder"
    requires = ()  # keyless - uses local binary
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 604_800.0  # 7 days - subdomains change slowly

    def _binary(self) -> Path:
        return Path.home() / "OSINT" / "bin" / "subfinder"

    def health(self) -> Health:
        binary = self._binary()
        if not binary.exists():
            return Health(self.name, ok=False, detail=f"binary not found: {binary}", enabled=False)
        if not binary.is_file() or not (binary.stat().st_mode & 0o100):
            return Health(
                self.name, ok=False, detail=f"binary not executable: {binary}", enabled=False
            )
        try:
            result = subprocess.run(
                [str(binary), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            return Health(self.name, ok=False, detail=f"binary not found: {binary}", enabled=False)
        except subprocess.TimeoutExpired:
            return Health(self.name, ok=False, detail="binary --version timed out", enabled=False)
        if result.returncode == 0:
            version_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "ok"
            return Health(self.name, ok=True, detail=f"keyless; {version_line}")
        return Health(
            self.name,
            ok=False,
            detail=f"binary exited {result.returncode}: {result.stderr.strip()}",
            enabled=False,
        )

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"subfinder -d {artifact} (local binary)"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        binary = self._binary()
        cmd = [str(binary), "-d", artifact, "-silent", "-oJ", "-nC"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            raise RuntimeError(f"binary not found: {binary}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"subfinder timed out for {artifact}")
        if result.returncode != 0:
            raise RuntimeError(f"subfinder exited {result.returncode}: {result.stderr.strip()}")
        # Wrap stdout in a synthetic httpx.Response so base-class caching works.
        body = result.stdout.encode("utf-8") if result.stdout else b"[]"
        resp = httpx.Response(
            200,
            content=body,
            request=httpx.Request("GET", self.source_url(artifact, artifact_type)),
        )
        return resp

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, list):
            return []
        seen: set[str] = set()
        findings: list[Finding] = []
        count = 0
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            host = (entry.get("host") or "").strip().lower()
            source = (entry.get("source") or "").strip()
            if not host or host in seen:
                continue
            seen.add(host)
            count += 1
            source_label = f" (via {source})" if source else ""
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"Subdomain{source_label}: {host}",
                    selector=host,
                    confidence="medium",
                )
            )
        if count > 0:
            findings.insert(
                0,
                self._finding(
                    artifact,
                    artifact_type,
                    f"{count} subdomain(s) found by subfinder",
                    selector="subfinder_summary",
                    confidence="high",
                ),
            )
        return findings
