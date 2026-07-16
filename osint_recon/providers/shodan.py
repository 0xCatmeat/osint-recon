from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from osint_recon.providers.base import Fetched, Health, Provider
from osint_recon.schema import Finding

_MAX_SERVICES = 25


class ShodanProvider(Provider):
    name = "shodan"
    requires = ("SHODAN_API_KEY",)
    # Only host lookups run by default. Search stays opt-in because it costs query credits.
    supported_artifacts = ("ip",)

    def health(self) -> Health:
        if not self.enabled():
            return self._disabled()
        key = self.config.get("SHODAN_API_KEY")
        try:
            with self.client() as client:
                resp = client.get("https://api.shodan.io/api-info", params={"key": key})
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        if resp.status_code != 200:
            return Health(self.name, ok=False, detail=f"HTTP {resp.status_code}")
        data = resp.json()
        return Health(
            self.name,
            ok=True,
            detail=(
                f"plan={data.get('plan', '?')} "
                f"query_credits={data.get('query_credits', '?')} "
                f"scan_credits={data.get('scan_credits', '?')}"
            ),
        )

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"https://api.shodan.io/shodan/host/{artifact}"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        with self.client() as client:
            return client.get(
                f"https://api.shodan.io/shodan/host/{artifact}",
                params={"key": self.config.get("SHODAN_API_KEY"), "minify": "false"},
            )

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, dict) or raw.get("error"):
            return []
        findings: list[Finding] = []
        ports = raw.get("ports", []) or []
        org = raw.get("org") or raw.get("isp") or ""
        if ports:
            label = f"Open ports: {', '.join(str(p) for p in sorted(ports))}"
            if org:
                label += f" - {org}"
            findings.append(
                self._finding(artifact, artifact_type, label, selector="ports", confidence="high")
            )
        hostnames = raw.get("hostnames", []) or []
        if hostnames:
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    "Hostnames: " + ", ".join(hostnames),
                    selector="hostnames",
                )
            )
        for service in (raw.get("data", []) or [])[:_MAX_SERVICES]:
            if not isinstance(service, dict):
                continue
            port = service.get("port")
            transport = service.get("transport", "tcp")
            product = service.get("product") or service.get("_shodan", {}).get("module", "")
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"{transport}/{port} {product}".strip(),
                    selector=f"{artifact}:{port}",
                )
            )
        vulns = raw.get("vulns")
        if vulns:
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    "CVEs reported: " + ", ".join(sorted(vulns)),
                    selector="vulns",
                    risk_level="medium",
                )
            )
        return findings

    def search(self, query: str, store: Any = None) -> Fetched:
        return self._run_cached(
            store,
            cache_key=f"search:{quote(query)}",
            source_url=f"https://api.shodan.io/shodan/host/search?query={quote(query)}",
            do_fetch=lambda: self._search_fetch(query),
            do_parse=lambda raw: self._parse_search(raw, query),
            ttl=self.cache_ttl_seconds,
        )

    def _search_fetch(self, query: str) -> httpx.Response:
        with self.client() as client:
            return client.get(
                "https://api.shodan.io/shodan/host/search",
                params={
                    "key": self.config.get("SHODAN_API_KEY"),
                    "query": query,
                    "minify": "false",
                },
            )

    def _parse_search(self, raw: Any, query: str) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        total = raw.get("total", 0)
        matches = raw.get("matches", []) or []
        if not matches:
            return []

        findings = [
            self._finding(
                query,
                "shodan_search",
                f"Shodan search: {total} total results, {len(matches)} shown (query: {query})",
                selector="search_summary",
                confidence="high",
            )
        ]

        for match in matches[:50]:
            ip = match.get("ip_str", "?")
            port = match.get("port", "?")
            transport = match.get("transport", "tcp")
            product = match.get("product") or ""
            org = match.get("org", "")
            hostnames = match.get("hostnames", []) or []
            label = f"{ip}:{port}/{transport}"
            if product:
                label += f" {product}"
            if org:
                label += f" ({org})"
            if hostnames:
                label += f" [{', '.join(hostnames[:3])}]"
            findings.append(
                self._finding(
                    query,
                    "shodan_search",
                    label,
                    selector=f"{ip}:{port}",
                    confidence="high",
                )
            )

        return findings
