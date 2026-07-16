from __future__ import annotations

from typing import Any

from osint_recon.providers.base import LocalBinaryProvider, jsonl_to_array
from osint_recon.schema import Finding


class SubfinderProvider(LocalBinaryProvider):
    name = "subfinder"
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 604_800.0  # 7 days
    binary_name = "subfinder"

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"subfinder -d {artifact} (local binary)"

    def _argv(self, artifact: str, artifact_type: str) -> list[str]:
        return ["-d", artifact, "-silent", "-oJ", "-nc"]

    def _body(self, stdout: bytes) -> bytes:
        return jsonl_to_array(stdout)

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, list):
            return []
        seen: set[str] = set()
        findings: list[Finding] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            host = (entry.get("host") or "").strip().lower()
            source = (entry.get("source") or "").strip()
            if not host or host in seen:
                continue
            seen.add(host)
            source_label = f" (via {source})" if source else ""
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"Subdomain{source_label}: {host}",
                    selector=host,
                    confidence="medium",
                )
            )
        if findings:
            findings.insert(
                0,
                self._finding(
                    artifact,
                    artifact_type,
                    f"{len(findings)} subdomain(s) found by subfinder",
                    selector="subfinder_summary",
                    confidence="high",
                ),
            )
        return findings
