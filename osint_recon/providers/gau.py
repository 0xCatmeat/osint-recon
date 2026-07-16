from __future__ import annotations

import json
from typing import Any

from osint_recon.providers.base import LocalBinaryProvider
from osint_recon.schema import Finding

_MAX_URLS = 100


class GauProvider(LocalBinaryProvider):
    name = "gau"
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 604_800.0  # 7 days
    binary_name = "gau"
    version_args = ("--version",)

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"gau {artifact} (local binary)"

    def _argv(self, artifact: str, artifact_type: str) -> list[str]:
        return [artifact, "--subs", "--retries", "2"]

    def _body(self, stdout: bytes) -> bytes:
        urls = [
            line.strip() for line in stdout.decode("utf-8", "replace").splitlines() if line.strip()
        ]
        return json.dumps({"urls": urls[:_MAX_URLS], "total": len(urls)}).encode("utf-8")

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        urls = raw.get("urls", [])
        total = raw.get("total", len(urls))
        if not urls:
            return []

        findings = [
            self._finding(
                artifact,
                artifact_type,
                f"{total} historical URL(s) discovered (showing up to {_MAX_URLS})",
                selector="gau_summary",
                confidence="high",
            )
        ]

        seen: set[str] = set()
        for url in urls:
            if not isinstance(url, str) or not url.startswith("http") or url in seen:
                continue
            seen.add(url)
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"Historical URL: {url}",
                    selector=url[:120],
                    confidence="medium",
                )
            )

        return findings
