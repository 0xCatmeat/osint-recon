"""Shodan - passive exposure via host lookup (free; host lookups cost no query credits)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from osint_recon.providers.base import Health, Provider, Fetched
from osint_recon.schema import Finding

_MAX_SERVICES = 25


class ShodanProvider(Provider):
    name = "shodan"
    requires = ("SHODAN_API_KEY",)
    # Host lookups are free; search stays opt-in because it costs credits.
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
        """Run a Shodan search query. Costs 1 query credit when filters are used.

        This is separate from the normal ``enrich`` flow. It is only called when
        ``--shodan-search QUERY`` is passed on the CLI.
        """
        src = f"https://api.shodan.io/shodan/host/search?query={quote(query)}"
        cache_key = f"search:{quote(query)}"

        entry = store.get_entry(self.name, cache_key) if store is not None else None
        cache_hit = entry is not None
        raw_text = entry.value if entry is not None else None
        cached_at = ""
        fetched_at = ""
        ttl_seconds = 0.0
        if entry is not None:
            cached_at = datetime.fromtimestamp(entry.stored_at, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            ttl_seconds = float(entry.ttl)

        if raw_text is None:
            if store is not None:
                store.throttle(self.name)
            with self.client() as client:
                resp = client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={
                        "key": self.config.get("SHODAN_API_KEY"),
                        "query": query,
                        "minify": "false",
                    },
                )
            if resp.status_code != 200:
                raise RuntimeError(f"Shodan search HTTP {resp.status_code}")
            raw_text = resp.text
            if store is not None:
                stored_at = store.put(self.name, cache_key, raw_text, ttl=86_400.0)
                fetched_at = datetime.fromtimestamp(stored_at, timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                ttl_seconds = 86_400.0
            else:
                fetched_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        raw_bytes = raw_text.encode("utf-8")
        raw = __import__("json").loads(raw_bytes) if raw_bytes else {}
        findings = self._parse_search(raw, query)
        for f in findings:
            f.source_url = src

        return Fetched(
            self.name,
            src,
            raw_bytes,
            findings,
            cache_hit=cache_hit,
            fetched_at=fetched_at,
            cached_at=cached_at,
            ttl_seconds=ttl_seconds,
        )

    def _parse_search(self, raw: Any, query: str) -> list[Finding]:
        """Parse Shodan search results into Findings."""
        findings: list[Finding] = []
        if not isinstance(raw, dict):
            return findings

        total = raw.get("total", 0)
        matches = raw.get("matches", []) or []
        if not matches:
            return findings

        findings.append(
            self._finding(
                query,
                "shodan_search",
                f"Shodan search: {total} total results, {len(matches)} shown (query: {query})",
                selector="search_summary",
                confidence="high",
            )
        )

        for match in matches[:50]:  # cap at 50 findings per search
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
