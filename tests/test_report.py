import json

from osint_recon.commands import report
from osint_recon.schema import Finding


def test_report_groups_findings_by_artifact_then_provider(tmp_path):
    run_dir = tmp_path / "example.com" / "20260529T000000Z"
    norm_dir = run_dir / "normalized"
    norm_dir.mkdir(parents=True)
    (run_dir / "run-metadata.json").write_text(
        json.dumps(
            {
                "target": "example.com",
                "artifact_type": "domain",
                "timestamp": "20260529T000000Z",
                "classification": "passive",
                "providers_used": ["rdap", "shodan"],
                "cache": {"hits": 1, "misses": 1},
                "artifacts": [
                    {"artifact": "example.com", "artifact_type": "domain", "relation": "primary"},
                    {
                        "artifact": "1.2.3.4",
                        "artifact_type": "ip",
                        "relation": "resolved_ip_pivot",
                    },
                ],
            }
        )
    )
    findings = [
        Finding("example.com", "domain", "rdap", "Registrar: Example"),
        Finding("1.2.3.4", "ip", "shodan", "Open ports: 443"),
    ]
    norm_dir.joinpath("findings.jsonl").write_text("\n".join(f.to_jsonl() for f in findings) + "\n")

    summary = report.render(run_dir)
    text = summary.read_text()

    assert "### Primary (domain): example.com" in text
    assert "### Resolved IP pivot (ip): 1.2.3.4" in text
    assert "- [info] (domain example.com)" in text
    assert "- [info] (ip 1.2.3.4)" in text
    assert "Cache: 1 hit(s), 1 miss(es)" in text
