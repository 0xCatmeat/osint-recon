from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from osint_recon.artifacts import detect_artifact
from osint_recon.config import Config
from osint_recon.providers import all_providers
from osint_recon.schema import provenance_hash, utcnow_iso


def _metadata_timestamp_iso(value: str) -> str:
    try:
        return (
            datetime.strptime(value, "%Y%m%dT%H%M%SZ")
            .replace(tzinfo=timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    except ValueError:
        return value


def _existing_source_urls(run_dir: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    findings_path = run_dir / "normalized" / "findings.jsonl"
    if not findings_path.exists():
        return sources
    for line in findings_path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        raw_path = finding.get("raw_path")
        source_url = finding.get("source_url")
        if raw_path and source_url and raw_path not in sources:
            sources[raw_path] = source_url
    return sources


def run(config: Config, run_dir) -> int:  # noqa: ANN001
    run_dir = Path(run_dir)
    raw_dir = run_dir / "raw"
    if not raw_dir.is_dir():
        print(f"no raw/ directory under {run_dir}")
        return 2

    providers = {p.name: p for p in all_providers(config)}
    meta_path = run_dir / "run-metadata.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    case_id = meta.get("case_id", "")
    default_type = meta.get("artifact_type", "domain")
    default_observed_at = _metadata_timestamp_iso(meta.get("timestamp", "")) if meta else ""
    existing_sources = _existing_source_urls(run_dir)

    manifest = meta.get("raw")
    if manifest:
        entries = [
            {
                "file": e["file"],
                "provider": e["provider"],
                "artifact": e["artifact"],
                "artifact_type": e.get("artifact_type") or default_type,
                "source_url": e.get("source_url") or existing_sources.get(f"raw/{e['file']}", ""),
                "observed_at": e.get("observed_at") or default_observed_at,
            }
            for e in manifest
        ]
    else:
        # No manifest, so recover the artifact from the filename. This loses IPv6 colons.
        entries = []
        for raw_file in sorted(raw_dir.glob("*.json")):
            provider_name, _, artifact = raw_file.stem.partition("-")
            if artifact:
                entries.append(
                    {
                        "file": raw_file.name,
                        "provider": provider_name,
                        "artifact": artifact,
                        "artifact_type": detect_artifact(artifact) or default_type,
                        "source_url": existing_sources.get(f"raw/{raw_file.name}", ""),
                        "observed_at": default_observed_at,
                    }
                )

    out = run_dir / "normalized" / "findings.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out.open("w", encoding="utf-8") as handle:
        for entry in entries:
            filename = entry["file"]
            provider_name = entry["provider"]
            artifact = entry["artifact"]
            atype = entry["artifact_type"]
            provider = providers.get(provider_name)
            raw_path = raw_dir / filename
            if provider is None or not raw_path.exists():
                continue
            raw_bytes = raw_path.read_bytes()
            try:
                raw = json.loads(raw_bytes)
            except json.JSONDecodeError:
                continue
            try:
                findings = provider.parse(raw, artifact, atype)
                src = entry.get("source_url") or provider.source_url(artifact, atype)
            except NotImplementedError:
                continue
            phash = provenance_hash(raw_bytes)
            for finding in findings:
                finding.source_url = src
                finding.raw_path = f"raw/{filename}"
                finding.provenance_hash = phash
                finding.case_id = case_id
                if entry.get("observed_at"):
                    finding.observed_at = entry["observed_at"]
                handle.write(finding.to_jsonl() + "\n")
                count += 1
    if meta_path.exists():
        if manifest:
            by_file = {entry["file"]: entry for entry in entries}
            for raw_item in meta.get("raw", []):
                entry = by_file.get(raw_item.get("file"))
                if not entry:
                    continue
                raw_item.setdefault("source_url", entry.get("source_url", ""))
                raw_item.setdefault("observed_at", entry.get("observed_at", ""))
        if "artifacts" not in meta:
            artifacts = []
            seen = set()
            for entry in entries:
                key = (entry["artifact"], entry["artifact_type"])
                if key in seen:
                    continue
                relation = "primary"
                if (
                    entry["artifact"] != meta.get("target")
                    or entry["artifact_type"] != default_type
                ):
                    relation = f"resolved_{entry['artifact_type']}_pivot"
                artifacts.append(
                    {
                        "artifact": entry["artifact"],
                        "artifact_type": entry["artifact_type"],
                        "relation": relation,
                    }
                )
                seen.add(key)
            meta["artifacts"] = artifacts
        meta["normalized_at"] = utcnow_iso()
        meta["finding_count"] = count
        meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    print(f"normalized {count} finding(s) -> {out}")
    return 0
