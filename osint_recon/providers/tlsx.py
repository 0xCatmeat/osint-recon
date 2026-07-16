from __future__ import annotations

from typing import Any

from osint_recon.providers.base import LocalBinaryProvider
from osint_recon.schema import Finding


class TlsxProvider(LocalBinaryProvider):
    name = "tlsx"
    supported_artifacts = ("ip", "domain")
    cache_ttl_seconds = 604_800.0  # 7 days
    binary_name = "tlsx"
    run_timeout = 15.0
    active = True

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"tlsx -host {artifact} -port 443 (local binary)"

    def _argv(self, artifact: str, artifact_type: str) -> list[str]:
        # subject_cn and subject_an come back by default in JSON. -san/-cn cannot be
        # combined with the -expired probe, so we only ask for -expired here.
        return ["-host", artifact, "-port", "443", "-silent", "-json", "-expired"]

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, dict) or not raw or raw.get("error"):
            return []
        findings: list[Finding] = []

        host = raw.get("host") or ""
        subject_cn = raw.get("subject_cn") or ""
        subject_an = raw.get("subject_an") or []
        issuer_cn = raw.get("issuer_cn") or ""
        not_before = raw.get("not_before") or ""
        not_after = raw.get("not_after") or ""
        expired = raw.get("expired", False)

        parts = []
        if subject_cn:
            parts.append(f"CN={subject_cn}")
        if issuer_cn:
            parts.append(f"issuer={issuer_cn}")
        if not_after:
            parts.append(f"expires={not_after}")
        if expired:
            parts.append("EXPIRED")

        if parts:
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    "TLS cert: " + ", ".join(parts),
                    selector=f"{host}:443",
                    confidence="high",
                    risk_level="high" if expired else "info",
                )
            )

        if isinstance(subject_an, list):
            for san in subject_an:
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"TLS SAN: {san}",
                        selector=san,
                        confidence="high",
                    )
                )

        if not_before and not_after:
            findings.append(
                self._finding(
                    artifact,
                    artifact_type,
                    f"Cert valid: {not_before} to {not_after}",
                    selector="cert_lifetime",
                    confidence="high",
                )
            )

        return findings
