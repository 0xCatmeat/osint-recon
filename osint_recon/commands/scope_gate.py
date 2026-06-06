"""`osint-recon scope-gate` - record authorization before any active tooling is used."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from osint_recon.artifacts import detect_artifact
from osint_recon.fs import secure_dir, secure_file
from osint_recon.run import REPORTS_DIR, slug


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def run(
    target: str,
    scope_file: Path,
    authorization_note: str,
    out_dir: Path | None = None,
) -> int:
    artifact_type = detect_artifact(target)
    if artifact_type is None:
        print(f"could not classify target {target!r} (expected ip, domain, url, or hash)")
        return 2
    if not scope_file.exists() or not scope_file.is_file():
        print(f"scope file not found: {scope_file}")
        return 2
    if not authorization_note.strip():
        print("authorization note is required")
        return 2

    now = datetime.now(timezone.utc)
    base = secure_dir(out_dir or REPORTS_DIR / slug(target))
    path = base / f"scope-gate-{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    record = {
        "target": target,
        "artifact_type": artifact_type,
        "classification": "active-authorization-record",
        "recorded_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope_file": str(scope_file.resolve()),
        "scope_file_hash": _sha256(scope_file),
        "authorization_note": authorization_note.strip(),
        "active_tooling_enabled": False,
        "note": "Authorization recorded only. No active scanner is wired into osint-recon yet.",
    }
    path.write_text(json.dumps(record, indent=2) + "\n")
    secure_file(path)
    print(f"recorded scope gate -> {path}")
    return 0
