"""crt.sh - Certificate Transparency log search for subdomains/certs (keyless)."""

from __future__ import annotations

from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding

_MAX_SUBDOMAINS = 50


class CrtshProvider(Provider):
    name = "crtsh"
    requires = ()  # keyless
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 604_800.0

    def health(self) -> Health:
        try:
            with self.client(timeout=30.0) as client:
                resp = client.get("https://crt.sh/", params={"q": "example.com", "output": "json"})
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        ok = resp.status_code == 200
        return Health(
            self.name,
            ok=ok,
            detail="keyless; crt.sh reachable" if ok else f"HTTP {resp.status_code}",
        )

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"https://crt.sh/?q={artifact}&output=json"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        with self.client(timeout=30.0) as client:
            return client.get("https://crt.sh/", params={"q": artifact, "output": "json"})

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, list):
            return []
        names: set[str] = set()
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            for line in (entry.get("name_value") or "").splitlines():
                name = line.strip().lstrip("*.").lower()
                if name and "@" not in name:
                    names.add(name)
        subs = sorted(n for n in names if n != artifact)
        findings = [
            self._finding(
                artifact,
                artifact_type,
                f"{len(subs)} unique subdomain(s) in CT logs (showing up to {_MAX_SUBDOMAINS})",
                selector="ct_summary",
                confidence="high",
            )
        ]
        for sub in subs[:_MAX_SUBDOMAINS]:
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"Subdomain (CT): {sub}",
                    selector=sub,
                    confidence="high",
                )
            )
        return findings
