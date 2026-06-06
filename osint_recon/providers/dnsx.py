"""dnsx - DNS resolution via local binary (keyless)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


class DnsxProvider(Provider):
    name = "dnsx"
    requires = ()  # keyless - uses local binary
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 86_400.0  # 24h

    def _binary(self) -> Path:
        return Path.home() / "OSINT" / "bin" / "dnsx"

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
        return f"dnsx -d {artifact} (local binary)"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        binary = self._binary()
        cmd = [
            str(binary),
            "-d",
            artifact,
            "-silent",
            "-json",
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-ns",
            "-txt",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            raise RuntimeError(f"binary not found: {binary}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"dnsx timed out for {artifact}")
        if result.returncode != 0:
            raise RuntimeError(f"dnsx exited {result.returncode}: {result.stderr.strip()}")
        # Wrap stdout in a synthetic httpx.Response so base-class caching works.
        body = result.stdout.encode("utf-8") if result.stdout else b"[]"
        resp = httpx.Response(
            200,
            content=body,
            request=httpx.Request("GET", self.source_url(artifact, artifact_type)),
        )
        return resp

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        # dnsx can return one object instead of a list.
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            return []
        findings: list[Finding] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue

            host = (entry.get("host") or "").strip()

            for ip in entry.get("a") or []:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"A: {host} -> {ip}",
                        selector="a",
                        confidence="high",
                    )
                )

            for ip in entry.get("aaaa") or []:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"AAAA: {host} -> {ip}",
                        selector="aaaa",
                        confidence="high",
                    )
                )

            for cname in entry.get("cname") or []:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"CNAME: {host} -> {cname}",
                        selector="cname",
                        confidence="high",
                    )
                )

            for mx in entry.get("mx") or []:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"MX: {host} -> {mx}",
                        selector="mx",
                        confidence="high",
                    )
                )

            for ns in entry.get("ns") or []:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"NS: {host} -> {ns}",
                        selector="ns",
                        confidence="high",
                    )
                )

            for txt in entry.get("txt") or []:
                txt_display = txt if len(txt) <= 120 else txt[:117] + "..."
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"TXT: {host} -> {txt_display}",
                        selector="txt",
                        confidence="high",
                    )
                )

        if findings:
            findings.insert(
                0,
                self._finding(
                    artifact,
                    artifact_type,
                    f"{len(findings)} DNS record(s) found by dnsx",
                    selector="dnsx_summary",
                    confidence="high",
                ),
            )
        return findings
