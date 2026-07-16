from __future__ import annotations

from typing import Any

from osint_recon.providers.base import LocalBinaryProvider, jsonl_to_array
from osint_recon.schema import Finding


class HttpxProvider(LocalBinaryProvider):
    name = "httpx"
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 86_400.0  # 24h
    binary_name = "httpx"
    run_timeout = 30.0
    active = True

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"httpx -l {artifact} (local binary)"

    def _argv(self, artifact: str, artifact_type: str) -> list[str]:
        return ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-cdn"]

    def _stdin(self, artifact: str, artifact_type: str) -> bytes:
        return artifact.encode("utf-8")

    def _body(self, stdout: bytes) -> bytes:
        return jsonl_to_array(stdout)

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        entries = [e for e in raw if isinstance(e, dict)] if isinstance(raw, list) else []
        if not entries:
            return []

        total = len(entries)
        live = sum(1 for e in entries if e.get("status_code"))
        findings = [
            self._finding(
                artifact,
                artifact_type,
                f"httpx: {total} probed, {live} live",
                selector="httpx_summary",
                confidence="high",
            )
        ]

        for entry in entries:
            url = entry.get("url") or entry.get("host") or ""
            if not url:
                continue
            status = entry.get("status_code")
            title = entry.get("title") or ""
            tech = entry.get("tech") or []
            cdn = entry.get("cdn") or ""

            parts = [url]
            if status:
                parts.append(f"[{status}]")
            if title:
                parts.append(title)

            finding = self._finding(
                artifact,
                artifact_type,
                " ".join(parts),
                selector=url,
                confidence="high",
            )
            if tech:
                finding.finding += f" -- tech: {', '.join(tech)}"
            if cdn:
                finding.finding += f" (CDN: {cdn})"
            findings.append(finding)

        return findings
