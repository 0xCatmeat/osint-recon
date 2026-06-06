"""tlsx - ProjectDiscovery's TLS fingerprinting tool (local binary, keyless)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


class TlsxProvider(Provider):
    name = "tlsx"
    requires = ()  # keyless
    supported_artifacts = ("ip", "domain")
    cache_ttl_seconds = 604_800.0  # 7 days -- certs change slowly

    def _binary(self) -> Path:
        return Path.home() / "OSINT" / "bin" / "tlsx"

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
        return f"tlsx -host {artifact} -port 443 (local binary)"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:  # type: ignore[override]
        """Run tlsx binary against the target, capture JSON, wrap in synthetic response."""
        bin_path = self._binary()
        cmd = [
            str(bin_path),
            "-host",
            artifact,
            "-port",
            "443",
            "-silent",
            "-json",
            "-san",
            "-cn",
            "-expired",
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=15,
            )
        except FileNotFoundError:
            raise RuntimeError(f"tlsx binary not found at {bin_path}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"tlsx timed out for {artifact}")

        if result.returncode != 0:
            raise RuntimeError(
                f"tlsx exited {result.returncode}: {result.stderr.decode(errors='replace').strip()}"
            )

        body = result.stdout
        resp = httpx.Response(
            200,
            content=body,
            request=httpx.Request("GET", self.source_url(artifact, artifact_type)),
        )
        return resp

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(raw, dict):
            return findings

        # Skip empty or error responses
        if not raw or raw.get("error"):
            return findings

        host = raw.get("host") or ""
        subject_cn = raw.get("subject_cn") or ""
        subject_an = raw.get("subject_an") or []
        issuer_cn = raw.get("issuer_cn") or ""
        not_before = raw.get("not_before") or ""
        not_after = raw.get("not_after") or ""
        expired = raw.get("expired", False)

        parts = []
        if subject_cn:
            parts.append(f"CN={subject_cn}")
        if issuer_cn:
            parts.append(f"issuer={issuer_cn}")
        if not_after:
            parts.append(f"expires={not_after}")
        if expired:
            parts.append("EXPIRED")

        if parts:
            label = "TLS cert: " + ", ".join(parts)
            risk = "high" if expired else "info"
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    label,
                    selector=f"{host}:443",
                    confidence="high",
                    risk_level=risk,
                )
            )

        if isinstance(subject_an, list):
            for san in subject_an:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"TLS SAN: {san}",
                        selector=san,
                        confidence="high",
                    )
                )

        if not_before and not_after and not any(f.selector == "cert_lifetime" for f in findings):
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"Cert valid: {not_before} to {not_after}",
                    selector="cert_lifetime",
                    confidence="high",
                )
            )

        return findings
