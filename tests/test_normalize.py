import json
from pathlib import Path

from osint_recon.commands import normalize
from osint_recon.config import Config


def test_normalize_preserves_manifest_observed_at(tmp_path):
    run_dir = tmp_path / "example.com" / "20260529T000000Z"
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True)
    raw_file = raw_dir / "rdap-example.com.json"
    raw_file.write_text(
        json.dumps(
            {"events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}]}
        )
    )
    observed_at = "2026-05-29T01:02:03Z"
    (run_dir / "run-metadata.json").write_text(
        json.dumps(
            {
                "case_id": "example.com-20260529",
                "artifact_type": "domain",
                "timestamp": "20260529T000000Z",
                "raw": [
                    {
                        "file": raw_file.name,
                        "provider": "rdap",
                        "artifact": "example.com",
                        "artifact_type": "domain",
                        "source_url": "https://rdap.org/domain/example.com",
                        "observed_at": observed_at,
                    }
                ],
            }
        )
    )

    rc = normalize.run(Config(Path("/nonexistent"), {}), run_dir)

    assert rc == 0
    finding = json.loads((run_dir / "normalized" / "findings.jsonl").read_text().splitlines()[0])
    assert finding["observed_at"] == observed_at
    meta = json.loads((run_dir / "run-metadata.json").read_text())
    assert meta["normalized_at"].endswith("Z")
