"""VirusTotal - reputation for domains, IPs, URLs, and hashes (free public API v3)."""

from __future__ import annotations

import base64
from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


class VirusTotalProvider(Provider):
    name = "virustotal"
    requires = ("VIRUSTOTAL_API_KEY",)
    supported_artifacts = ("domain", "ip", "url", "hash")

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.config.get("VIRUSTOTAL_API_KEY") or ""}

    def health(self) -> Health:
        if not self.enabled():
            return self._disabled()
        key = self.config.get("VIRUSTOTAL_API_KEY")
        try:
            with self.client() as client:
                resp = client.get(
                    f"https://www.virustotal.com/api/v3/users/{key}",
                    headers={"x-apikey": key},
                )
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        if resp.status_code != 200:
            return Health(self.name, ok=False, detail=f"HTTP {resp.status_code}")
        quota = (
            resp.json()
            .get("data", {})
            .get("attributes", {})
            .get("quotas", {})
            .get("api_requests_daily", {})
        )
        used, allowed = quota.get("used"), quota.get("allowed")
        detail = f"daily {used}/{allowed}" if used is not None and allowed else "key valid"
        return Health(self.name, ok=True, detail=detail)

    def _path(self, artifact: str, artifact_type: str) -> str:
        if artifact_type == "domain":
            return f"domains/{artifact}"
        if artifact_type == "ip":
            return f"ip_addresses/{artifact}"
        if artifact_type == "hash":
            return f"files/{artifact}"
        if artifact_type == "url":
            uid = base64.urlsafe_b64encode(artifact.encode()).decode().rstrip("=")
            return f"urls/{uid}"
        return ""

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"https://www.virustotal.com/api/v3/{self._path(artifact, artifact_type)}"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        with self.client() as client:
            return client.get(self.source_url(artifact, artifact_type), headers=self._headers())

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        attrs = raw.get("data", {}).get("attributes", {}) if isinstance(raw, dict) else {}
        if not attrs:
            return []
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        risk = "high" if mal else "medium" if susp else "info"
        findings = [
            self._finding(
                artifact,
                artifact_type,
                f"VT analysis: malicious={mal} suspicious={susp} harmless={harmless} undetected={undetected}",
                selector="last_analysis_stats",
                risk_level=risk,
                confidence="high" if (mal or susp) else "medium",
            )
        ]
        reputation = attrs.get("reputation")
        if isinstance(reputation, int):
            findings.append(
                self._finding(
                    artifact, artifact_type, f"VT reputation: {reputation}", selector="reputation"
                )
            )
        owner = attrs.get("as_owner")
        if owner:
            findings.append(
                self._finding(artifact, artifact_type, f"AS owner: {owner}", selector="as_owner")
            )
        return findings
