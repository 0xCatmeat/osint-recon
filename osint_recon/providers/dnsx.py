from __future__ import annotations

from typing import Any

from osint_recon.providers.base import LocalBinaryProvider, jsonl_to_array
from osint_recon.schema import Finding


class DnsxProvider(LocalBinaryProvider):
    name = "dnsx"
    supported_artifacts = ("domain",)
    cache_ttl_seconds = 86_400.0  # 24h
    binary_name = "dnsx"
    run_timeout = 30.0
    active = True

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"dnsx {artifact} (local binary)"

    def _argv(self, artifact: str, artifact_type: str) -> list[str]:
        return ["-silent", "-json", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"]

    def _stdin(self, artifact: str, artifact_type: str) -> bytes:
        return artifact.encode("utf-8")

    def _body(self, stdout: bytes) -> bytes:
        return jsonl_to_array(stdout)

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            return []
        findings: list[Finding] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            host = (entry.get("host") or "").strip()

            for record_type, selector in (
                ("a", "a"),
                ("aaaa", "aaaa"),
                ("cname", "cname"),
                ("mx", "mx"),
                ("ns", "ns"),
            ):
                for value in entry.get(record_type) or []:
                    if not value:
                        continue
                    findings.append(
                        self._finding(
                            artifact,
                            artifact_type,
                            f"{record_type.upper()}: {host} -> {value}",
                            selector=selector,
                            confidence="high",
                        )
                    )

            for txt in entry.get("txt") or []:
                if not txt:
                    continue
                txt_display = txt if len(txt) <= 120 else txt[:117] + "..."
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"TXT: {host} -> {txt_display}",
                        selector="txt",
                        confidence="high",
                    )
                )

        if findings:
            findings.insert(
                0,
                self._finding(
                    artifact,
                    artifact_type,
                    f"{len(findings)} DNS record(s) found by dnsx",
                    selector="dnsx_summary",
                    confidence="high",
                ),
            )
        return findings
