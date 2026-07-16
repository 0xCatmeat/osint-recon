from __future__ import annotations

import json
import platform
import re
from datetime import datetime, timezone
from pathlib import Path

from osint_recon import __version__
from osint_recon.fs import secure_dir, secure_file
from osint_recon.schema import Finding

REPORTS_DIR = Path.home() / "OSINT" / "reports"


def slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return cleaned or "target"


class Run:
    def __init__(
        self,
        target: str,
        artifact_type: str,
        base_dir: Path | str | None = None,
        *,
        case_id: str | None = None,
    ) -> None:
        self.target = target
        self.artifact_type = artifact_type
        now = datetime.now(timezone.utc)
        self.ts = now.strftime("%Y%m%dT%H%M%SZ")
        self.case_id = case_id or f"{slug(target)}-{now.strftime('%Y%m%d')}"
        base = Path(base_dir) if base_dir else REPORTS_DIR
        self.dir = base / slug(target) / self.ts
        self.raw_dir = self.dir / "raw"
        self.norm_dir = self.dir / "normalized"
        secure_dir(self.raw_dir)
        secure_dir(self.norm_dir)
        self.findings_path = self.norm_dir / "findings.jsonl"
        self.providers_used: list[str] = []
        self.sources: list[tuple[str, str]] = []
        self.errors: list[tuple[str, str]] = []
        self.finding_count = 0
        self.raw_manifest: list[dict] = []
        self.artifacts: list[dict] = []
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_mode: str = "normal"  # normal | offline | refresh | max_age
        self.classification: str = "passive"  # passive | active

    def record_artifact(self, artifact: str, artifact_type: str, relation: str) -> None:
        item = {"artifact": artifact, "artifact_type": artifact_type, "relation": relation}
        if item not in self.artifacts:
            self.artifacts.append(item)

    def store_raw(
        self,
        provider: str,
        artifact: str,
        artifact_type: str,
        raw_bytes: bytes,
        *,
        source_url: str = "",
        observed_at: str = "",
        cache_hit: bool = False,
        cached_at: str = "",
        ttl_seconds: float = 0.0,
    ) -> str:
        name = f"{provider}-{slug(artifact)}.json"
        (self.raw_dir / name).write_bytes(raw_bytes)
        secure_file(self.raw_dir / name)
        self.raw_manifest.append(
            {
                "file": name,
                "provider": provider,
                "artifact": artifact,
                "artifact_type": artifact_type,
                "source_url": source_url,
                "observed_at": observed_at,
                "cache_hit": cache_hit,
                "cached_at": cached_at,
                "ttl_seconds": ttl_seconds,
            }
        )
        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
        return f"raw/{name}"

    def add_findings(self, findings: list[Finding], observed_at: str = "") -> None:
        with self.findings_path.open("a", encoding="utf-8") as handle:
            for finding in findings:
                finding.case_id = self.case_id
                if observed_at:
                    finding.observed_at = observed_at
                handle.write(finding.to_jsonl() + "\n")
                self.finding_count += 1
        secure_file(self.findings_path)

    def record_provider(self, provider: str, url: str) -> None:
        if provider not in self.providers_used:
            self.providers_used.append(provider)
        if url and (provider, url) not in self.sources:
            self.sources.append((provider, url))

    def write_metadata(self, command: str) -> dict:
        meta = {
            "target": self.target,
            "artifact_type": self.artifact_type,
            "case_id": self.case_id,
            "timestamp": self.ts,
            "command": command,
            "classification": self.classification,
            "providers_used": self.providers_used,
            "finding_count": self.finding_count,
            "errors": [{"provider": p, "error": e} for p, e in self.errors],
            "artifacts": self.artifacts,
            "raw": self.raw_manifest,
            "cache": {
                "hits": self.cache_hits,
                "misses": self.cache_misses,
                "mode": self.cache_mode,
            },
            "tool_versions": {
                "osint-recon": __version__,
                "python": platform.python_version(),
            },
        }
        (self.dir / "run-metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
        secure_file(self.dir / "run-metadata.json")
        return meta
