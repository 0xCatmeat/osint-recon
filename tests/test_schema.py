import json

from osint_recon.schema import Finding, provenance_hash


def test_finding_to_jsonl_defaults():
    finding = Finding(
        target="example.com", artifact_type="domain", source_tool="rdap", finding="Registrar: IANA"
    )
    data = json.loads(finding.to_jsonl())
    assert data["target"] == "example.com"
    assert data["source_tool"] == "rdap"
    assert data["schema_version"] == "0.1"
    assert data["tlp"] == "amber"
    assert data["requires_manual_review"] is True
    assert data["observed_at"].endswith("Z")


def test_provenance_hash_is_stable_sha256():
    digest = provenance_hash(b"abc")
    assert digest == "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
