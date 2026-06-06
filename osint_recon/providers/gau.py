"""gau - historical URL discovery from Wayback Machine, urlscan, OTX (keyless)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding

_BINARY = Path.home() / "OSINT" / "bin" / "gau"
_MAX_URLS = 100


class GauProvider(Provider):
    name = "gau"
    requires = ()  # keyless
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 604_800.0

    def health(self) -> Health:
        if not _BINARY.exists():
            return Health(self.name, ok=False, detail="binary not found", enabled=True)
        if not _BINARY.stat().st_mode & 0o100:
            return Health(self.name, ok=False, detail="binary not executable", enabled=True)
        try:
            result = subprocess.run(
                [str(_BINARY), "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return Health(self.name, ok=False, detail=f"version check failed: {exc}")
        if result.returncode != 0:
            return Health(
                self.name,
                ok=False,
                detail=f"exit {result.returncode}: {(result.stderr or result.stdout).strip()[:100]}",
            )
        out = result.stdout.strip() or result.stderr.strip()
        if not out:
            return Health(self.name, ok=False, detail="no version output")
        version = out.splitlines()[-1]
        return Health(self.name, ok=True, detail=version)

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"gau {artifact} (local binary)"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        try:
            proc = subprocess.run(
                [str(_BINARY), artifact, "--json", "--subs", "--retries", "2"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            proc = subprocess.CompletedProcess(args=[], returncode=-1, stdout="", stderr="timeout")
        except OSError as exc:
            proc = subprocess.CompletedProcess(args=[], returncode=-1, stdout="", stderr=str(exc))

        if proc.returncode != 0 and not proc.stdout.strip():
            raise RuntimeError(
                f"gau failed: {proc.stderr.strip() or 'exit ' + str(proc.returncode)}"
            )

        urls: list[str] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                urls.append(line)

        results: dict[str, Any] = {"urls": urls[:_MAX_URLS], "total": len(urls)}
        body = json.dumps(results).encode("utf-8")
        resp = httpx.Response(
            200,
            content=body,
            request=httpx.Request("GET", self.source_url(artifact, artifact_type)),
        )
        return resp  # type: ignore[return-value]

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        findings: list[Finding] = []
        if not isinstance(raw, dict):
            return findings

        urls = raw.get("urls", [])
        total = raw.get("total", len(urls))
        if not urls:
            return findings

        findings.append(
            self._finding(
                artifact,
                artifact_type,
                f"{total} historical URL(s) discovered (showing up to {_MAX_URLS})",
                selector="gau_summary",
                confidence="high",
            )
        )

        seen: set[str] = set()
        for url in urls:
            if not isinstance(url, str) or not url.startswith("http"):
                continue
            if url in seen:
                continue
            seen.add(url)
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"Historical URL: {url}",
                    selector=url[:120],
                    confidence="medium",
                )
            )

        return findings
