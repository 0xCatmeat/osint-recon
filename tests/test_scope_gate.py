import json
import stat

from osint_recon.commands import scope_gate


def test_scope_gate_writes_authorization_record(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")
    out_dir = tmp_path / "out"

    rc = scope_gate.run("example.com", scope_file, "owned test domain", out_dir=out_dir)

    assert rc == 0
    records = list(out_dir.glob("scope-gate-*.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_text())
    assert record["target"] == "example.com"
    assert record["classification"] == "active-authorization-record"
    assert record["scope_file_hash"].startswith("sha256:")
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(records[0].stat().st_mode) == 0o600


def test_scope_gate_rejects_blank_authorization_note(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n")

    rc = scope_gate.run("example.com", scope_file, "   ", out_dir=tmp_path / "out")

    assert rc == 2
    assert not (tmp_path / "out").exists()
