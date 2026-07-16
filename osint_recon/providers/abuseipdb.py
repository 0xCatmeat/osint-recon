from __future__ import annotations

from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    requires = ("ABUSEIPDB_API_KEY",)
    supported_artifacts = ("ip",)

    def _headers(self) -> dict[str, str]:
        return {"Key": self.config.get("ABUSEIPDB_API_KEY") or "", "Accept": "application/json"}

    def health(self) -> Health:
        if not self.enabled():
            return self._disabled()
        try:
            with self.client() as client:
                resp = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers=self._headers(),
                    params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
                )
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        if resp.status_code != 200:
            return Health(self.name, ok=False, detail=f"HTTP {resp.status_code}")
        remaining = resp.headers.get("X-RateLimit-Remaining")
        detail = f"key valid; {remaining} checks left today" if remaining else "key valid"
        return Health(self.name, ok=True, detail=detail)

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"https://api.abuseipdb.com/api/v2/check?ipAddress={artifact}"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        with self.client() as client:
            return client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=self._headers(),
                params={"ipAddress": artifact, "maxAgeInDays": "90"},
            )

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        data = raw.get("data", {}) if isinstance(raw, dict) else {}
        if not data:
            return []
        score = data.get("abuseConfidenceScore", 0) or 0
        reports = data.get("totalReports", 0)
        risk = "high" if score >= 50 else "medium" if score >= 10 else "info"
        detail = f"AbuseIPDB score={score}% reports={reports}"
        extra = ", ".join(
            value
            for value in (
                data.get("isp", ""),
                data.get("countryCode", ""),
                data.get("usageType", ""),
            )
            if value
        )
        if extra:
            detail += f" ({extra})"
        return [
            self._finding(
                artifact,
                artifact_type,
                detail,
                selector="abuseConfidenceScore",
                risk_level=risk,
                confidence="high" if score else "medium",
            )
        ]
