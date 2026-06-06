"""RDAP - structured domain/IP registration data (keyless; replaces port-43 WHOIS)."""

from __future__ import annotations

from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


def _vcard_name(entity: dict) -> str:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return entity.get("handle", "") or ""


class RdapProvider(Provider):
    name = "rdap"
    requires = ()  # keyless
    supported_artifacts = ("domain", "ip")
    cache_ttl_seconds = 604_800.0

    def health(self) -> Health:
        try:
            with self.client() as client:
                resp = client.get("https://rdap.org/domain/example.com")
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        ok = resp.status_code == 200
        return Health(
            self.name,
            ok=ok,
            detail="keyless; rdap.org reachable" if ok else f"HTTP {resp.status_code}",
        )

    def source_url(self, artifact: str, artifact_type: str) -> str:
        kind = "ip" if artifact_type == "ip" else "domain"
        return f"https://rdap.org/{kind}/{artifact}"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        with self.client() as client:
            return client.get(self.source_url(artifact, artifact_type))

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []

        for event in raw.get("events", []) or []:
            action = (event.get("eventAction") or "").lower()
            date = event.get("eventDate")
            if action in ("registration", "expiration", "last changed") and date:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"{action}: {date}",
                        selector=action.replace(" ", "_"),
                        confidence="high",
                    )
                )

        for entity in raw.get("entities", []) or []:
            roles = [r.lower() for r in entity.get("roles", []) or []]
            label = _vcard_name(entity)
            if "registrar" in roles and label:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"Registrar: {label}",
                        selector="registrar",
                        confidence="high",
                    )
                )
            if "abuse" in roles and label:
                findings.append(
                    self._finding(
                        artifact, artifact_type, f"Abuse contact: {label}", selector="abuse_contact"
                    )
                )

        nameservers = [
            n.get("ldhName") for n in raw.get("nameservers", []) or [] if n.get("ldhName")
        ]
        if nameservers:
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    "Nameservers: " + ", ".join(nameservers),
                    selector="nameservers",
                    confidence="high",
                )
            )

        if artifact_type == "ip":
            name = raw.get("name")
            country = raw.get("country")
            start, end = raw.get("startAddress"), raw.get("endAddress")
            if name:
                label = f"Network: {name}" + (f" ({country})" if country else "")
                findings.append(
                    self._finding(
                        artifact, artifact_type, label, selector="network", confidence="high"
                    )
                )
            if start and end:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"Range: {start} - {end}",
                        selector="range",
                        confidence="high",
                    )
                )

        status = raw.get("status")
        if status:
            findings.append(
                self._finding(
                    artifact, artifact_type, "Status: " + ", ".join(status), selector="status"
                )
            )
        return findings
