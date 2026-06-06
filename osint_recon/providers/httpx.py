"""httpx - ProjectDiscovery's HTTP probing tool (local binary, keyless)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


class HttpxProvider(Provider):
    name = "httpx"
    requires = ()  # keyless
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 86_400.0  # 24h

    def _binary(self) -> Path:
        return Path.home() / "OSINT" / "bin" / "httpx"

    def health(self) -> Health:
        bin_path = self._binary()
        if not bin_path.exists():
            return Health(self.name, ok=False, detail=f"binary not found at {bin_path}")
        try:
            result = subprocess.run(
                [str(bin_path), "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0] if result.stdout.strip() else "ok"
                return Health(self.name, ok=True, detail=f"binary present ({version})")
            return Health(
                self.name,
                ok=False,
                detail=f"binary exited {result.returncode}: {result.stderr.strip()}",
            )
        except FileNotFoundError:
            return Health(self.name, ok=False, detail=f"binary not found at {bin_path}")
        except subprocess.TimeoutExpired:
            return Health(self.name, ok=False, detail="version check timed out")
        except Exception as exc:
            return Health(self.name, ok=False, detail=f"health check failed: {exc}")

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"httpx -l {artifact} (local binary)"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:  # type: ignore[override]
        """Run httpx binary with the domain as stdin input, capture JSONL.

        httpx produces JSONL (one JSON object per line), which is not valid JSON.
        We parse it here and emit a proper JSON array so the base class query()
        can cache and re-parse it correctly.
        """
        bin_path = self._binary()
        cmd = [
            str(bin_path),
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-cdn",
        ]
        try:
            result = subprocess.run(
                cmd,
                input=artifact.encode("utf-8"),
                capture_output=True,
                timeout=30,
            )
        except FileNotFoundError:
            raise RuntimeError(f"httpx binary not found at {bin_path}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"httpx timed out for {artifact}")

        if result.returncode != 0:
            raise RuntimeError(
                f"httpx exited {result.returncode}: {result.stderr.decode(errors='replace').strip()}"
            )

        entries: list[dict[str, Any]] = []
        raw_text = result.stdout.decode("utf-8", errors="replace")
        for line in raw_text.splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        body = json.dumps(entries).encode("utf-8")
        resp = httpx.Response(
            200,
            content=body,
            request=httpx.Request("GET", self.source_url(artifact, artifact_type)),
        )
        return resp  # type: ignore[return-value]

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        findings: list[Finding] = []

        # fetch() serializes JSONL as a proper JSON array, so raw should be a list.
        entries: list[dict[str, Any]] = (
            [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []
        )
        if not entries:
            return findings

        total = len(entries)
        live = sum(1 for e in entries if e.get("status_code") and e.get("status_code") != 0)
        findings.append(
            self._finding(
                artifact,
                artifact_type,
                f"httpx: {total} probed, {live} live",
                selector="httpx_summary",
                confidence="high",
            )
        )

        for entry in entries:
            url = entry.get("url") or entry.get("host") or ""
            status = entry.get("status_code")
            title = entry.get("title") or ""
            tech = entry.get("tech") or []
            cdn = entry.get("cdn") or ""

            if not url:
                continue

            parts = [url]
            if status:
                parts.append(f"[{status}]")
            if title:
                parts.append(title)

            label = " ".join(parts)
            finding = self._finding(
                artifact,
                artifact_type,
                label,
                selector=url,
                confidence="high",
            )
            if tech:
                finding.finding += f" -- tech: {', '.join(tech)}"
            if cdn:
                finding.finding += f" (CDN: {cdn})"
            findings.append(finding)

        return findings
