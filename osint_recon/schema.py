"""Shared evidence schema.

Every provider normalizes its output into ``Finding`` records serialized as JSONL so
findings stream well and merge cleanly across tools.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SCHEMA_VERSION = "0.1"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def provenance_hash(raw: bytes) -> str:
    """Stable content hash of a raw provider response, for reproducibility/audit."""
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass
class Finding:
    target: str
    artifact_type: str
    source_tool: str
    finding: str
    case_id: str = ""
    source_url: str = ""
    raw_path: str = ""
    selector: str = ""
    confidence: str = "medium"  # low | medium | high
    risk_level: str = "info"  # info | low | medium | high | critical
    tlp: str = "amber"  # clear | green | amber | red
    requires_manual_review: bool = True
    legal_scope_note: str = "passive lookup only"
    provenance_hash: str = ""
    observed_at: str = field(default_factory=utcnow_iso)
    schema_version: str = SCHEMA_VERSION

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, sort_keys=True)
