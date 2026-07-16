from __future__ import annotations

from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding

_API_BASE = "https://app.netlas.io/api"
_MAX_SERVICES = 25


class NetlasProvider(Provider):
    name = "netlas"
    requires = ("NETLAS_API_KEY",)
    supported_artifacts = ("ip", "domain")

    def _headers(self) -> dict[str, str]:
        key = self.config.get("NETLAS_API_KEY") or ""
        return {"Authorization": f"Bearer {key}"}

    def health(self) -> Health:
        if not self.enabled():
            return self._disabled()
        key = self.config.get("NETLAS_API_KEY")
        try:
            with self.client() as client:
                resp = client.get(
                    f"{_API_BASE}/host/",
                    headers={"Authorization": f"Bearer {key}"},
                )
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        if resp.status_code in (401, 403):
            return Health(self.name, ok=False, detail=f"auth failed (HTTP {resp.status_code})")
        if resp.status_code != 200:
            return Health(self.name, ok=False, detail=f"HTTP {resp.status_code}")
        return Health(self.name, ok=True, detail="key valid")

    def source_url(self, artifact: str, artifact_type: str) -> str:
        if artifact_type == "ip":
            return f"{_API_BASE}/host/{artifact}"
        return f"{_API_BASE}/domain/whois/{artifact}"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        with self.client() as client:
            if artifact_type == "ip":
                return client.get(
                    f"{_API_BASE}/host/{artifact}",
                    headers=self._headers(),
                )
            return client.get(
                f"{_API_BASE}/domain/whois/{artifact}",
                headers=self._headers(),
            )

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        findings: list[Finding] = []

        if artifact_type == "ip":
            findings.extend(self._parse_host(raw, artifact))
        elif artifact_type == "domain":
            findings.extend(self._parse_whois(raw, artifact))

        return findings

    def _parse_host(self, raw: dict, artifact: str) -> list[Finding]:
        findings: list[Finding] = []

        ip = raw.get("ip") or artifact
        hostname = raw.get("hostname") or raw.get("ptr") or ""
        isp = raw.get("isp") or ""
        as_info = raw.get("asn") or raw.get("as_info") or {}
        as_number = ""
        as_name = ""
        if isinstance(as_info, dict):
            as_number = str(as_info.get("asn") or as_info.get("number") or "")
            as_name = as_info.get("name") or as_info.get("org") or ""
        country = raw.get("geo") or raw.get("location") or {}
        country_code = ""
        if isinstance(country, dict):
            country_code = country.get("country") or country.get("country_code") or ""

        summary_parts: list[str] = [f"IP: {ip}"]
        if hostname:
            summary_parts.append(f"hostname: {hostname}")
        if isp:
            summary_parts.append(f"ISP: {isp}")
        if as_number:
            as_label = f"AS{as_number}"
            if as_name:
                as_label += f" ({as_name})"
            summary_parts.append(as_label)
        if country_code:
            summary_parts.append(f"country: {country_code}")

        if len(summary_parts) > 1:
            findings.append(
                self._finding(
                    artifact,
                    "ip",
                    " | ".join(summary_parts),
                    selector="host_summary",
                    confidence="high",
                )
            )

        ports = raw.get("ports") or raw.get("port") or []
        if isinstance(ports, int):
            ports = [ports]
        if ports:
            findings.append(
                self._finding(
                    artifact,
                    "ip",
                    f"Open ports: {', '.join(str(p) for p in sorted(ports))}",
                    selector="ports",
                    confidence="high",
                )
            )

        services = raw.get("data") or raw.get("services") or []
        for svc in services[:_MAX_SERVICES]:
            if not isinstance(svc, dict):
                continue
            port = svc.get("port") or svc.get("port_number") or ""
            proto = svc.get("transport") or svc.get("protocol") or "tcp"
            product = svc.get("product") or svc.get("service", {}).get("name", "")
            version = svc.get("version") or ""
            label = f"{proto}/{port}"
            if product:
                label += f" {product}"
                if version:
                    label += f" {version}"
            findings.append(
                self._finding(
                    artifact,
                    "ip",
                    label.strip(),
                    selector=f"{artifact}:{port}",
                )
            )

        dns = raw.get("dns") or {}
        dns_names: list[str] = []
        if isinstance(dns, dict):
            dns_names = dns.get("names") or dns.get("hostnames") or []
        if dns_names:
            findings.append(
                self._finding(
                    artifact,
                    "ip",
                    "DNS/cert names: " + ", ".join(dns_names[:50]),
                    selector="dns_names",
                )
            )

        hostnames = raw.get("hostnames") or []
        if hostnames and not dns_names:
            findings.append(
                self._finding(
                    artifact,
                    "ip",
                    "Hostnames: " + ", ".join(hostnames[:50]),
                    selector="hostnames",
                )
            )

        tags = raw.get("tags") or raw.get("labels") or []
        if tags:
            findings.append(
                self._finding(
                    artifact,
                    "ip",
                    "Tags: " + ", ".join(tags[:30]),
                    selector="tags",
                )
            )

        last_updated = raw.get("last_updated") or raw.get("last_update") or ""
        if last_updated:
            findings.append(
                self._finding(
                    artifact,
                    "ip",
                    f"Last seen: {last_updated}",
                    selector="last_seen",
                )
            )

        return findings

    def _parse_whois(self, raw: dict, artifact: str) -> list[Finding]:
        findings: list[Finding] = []

        registrar = raw.get("registrar") or {}
        registrar_name = ""
        if isinstance(registrar, dict):
            registrar_name = registrar.get("name") or registrar.get("registrar_name") or ""
        if not registrar_name:
            registrar_name = raw.get("registrar_name") or raw.get("registrar") or ""
        if isinstance(registrar_name, str) and registrar_name:
            findings.append(
                self._finding(
                    artifact,
                    "domain",
                    f"Registrar: {registrar_name}",
                    selector="registrar",
                    confidence="high",
                )
            )

        created = raw.get("created") or raw.get("creation_date") or ""
        expires = raw.get("expires") or raw.get("expiration_date") or ""
        if created:
            label = f"Registered: {created}"
            if expires:
                label += f" | Expires: {expires}"
            findings.append(
                self._finding(
                    artifact,
                    "domain",
                    label,
                    selector="registration",
                    confidence="high",
                )
            )

        nameservers = raw.get("nameservers") or raw.get("name_servers") or []
        if nameservers:
            findings.append(
                self._finding(
                    artifact,
                    "domain",
                    "Nameservers: " + ", ".join(nameservers[:20]),
                    selector="nameservers",
                    confidence="high",
                )
            )

        contacts = raw.get("contacts") or raw.get("registrant_contacts") or {}
        if isinstance(contacts, dict):
            registrant = contacts.get("registrant") or contacts.get("owner") or {}
            if isinstance(registrant, dict):
                org = registrant.get("organization") or registrant.get("org") or ""
                if org:
                    findings.append(
                        self._finding(
                            artifact,
                            "domain",
                            f"Registrant org: {org}",
                            selector="registrant_org",
                        )
                    )

        status = raw.get("status") or raw.get("domain_status") or []
        if status:
            if isinstance(status, list):
                status_str = ", ".join(status)
            else:
                status_str = str(status)
            findings.append(
                self._finding(
                    artifact,
                    "domain",
                    f"Domain status: {status_str}",
                    selector="status",
                )
            )

        updated = raw.get("updated") or raw.get("updated_date") or ""
        if updated:
            findings.append(
                self._finding(
                    artifact,
                    "domain",
                    f"WHOIS last updated: {updated}",
                    selector="whois_updated",
                )
            )

        return findings
