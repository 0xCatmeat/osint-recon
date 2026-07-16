from __future__ import annotations

import json
from pathlib import Path

from osint_recon.fs import secure_file


def _load_findings(path: Path) -> list[dict]:
    findings: list[dict] = []
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                findings.append(json.loads(line))
    return findings


def _artifact_label(item: dict) -> str:
    relation = str(item.get("relation") or "artifact")
    if relation == "resolved_ip_pivot":
        relation_label = "Resolved IP pivot"
    else:
        relation_label = relation.replace("_", " ").title()
    artifact_type = item.get("artifact_type", "?")
    artifact = item.get("artifact", "?")
    return f"{relation_label} ({artifact_type}): {artifact}"


def _artifact_items(meta: dict, findings: list[dict]) -> list[dict]:
    items = list(meta.get("artifacts") or [])
    seen = {(item.get("artifact"), item.get("artifact_type")) for item in items}
    for finding in findings:
        key = (finding.get("target"), finding.get("artifact_type"))
        if key not in seen:
            items.append(
                {
                    "artifact": finding.get("target"),
                    "artifact_type": finding.get("artifact_type", "?"),
                    "relation": "artifact",
                }
            )
            seen.add(key)
    return items


def _finding_line(finding: dict) -> str:
    selector = finding.get("selector", "")
    selector_text = f" `{selector}`" if selector else ""
    artifact_type = finding.get("artifact_type", "?")
    artifact = finding.get("target", "?")
    return (
        f"- [{finding.get('risk_level', 'info')}] ({artifact_type} {artifact})"
        f"{selector_text} {finding.get('finding', '')}"
    )


def render(run_dir: Path) -> Path:
    run_dir = Path(run_dir)
    meta_path = run_dir / "run-metadata.json"
    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
    findings = _load_findings(run_dir / "normalized" / "findings.jsonl")
    target = meta.get("target", run_dir.name)

    lines = [
        f"# Report: {target}",
        "",
        f"- Generated: {meta.get('timestamp', '?')}",
        f"- Artifact type: {meta.get('artifact_type', '?')}",
        f"- Classification: {meta.get('classification', 'passive')}",
        f"- Providers: {', '.join(meta.get('providers_used', [])) or 'none'}",
        f"- Findings: {len(findings)}",
    ]
    if meta.get("normalized_at"):
        lines.append(f"- Normalized: {meta['normalized_at']}")
    cache = meta.get("cache") or {}
    if cache:
        lines.append(f"- Cache: {cache.get('hits', 0)} hit(s), {cache.get('misses', 0)} miss(es)")
    lines.append("")
    errors = meta.get("errors", [])
    if errors:
        lines += ["## Errors", ""]
        lines += [f"- **{e.get('provider')}**: {e.get('error')}" for e in errors]
        lines.append("")

    by_artifact_tool: dict[tuple[str, str], dict[str, list[dict]]] = {}
    for finding in findings:
        key = (finding.get("target", "?"), finding.get("artifact_type", "?"))
        by_artifact_tool.setdefault(key, {}).setdefault(finding.get("source_tool", "?"), []).append(
            finding
        )
    lines.append("## Findings")
    for artifact in _artifact_items(meta, findings):
        key = (artifact.get("artifact", "?"), artifact.get("artifact_type", "?"))
        tool_groups = by_artifact_tool.get(key, {})
        if not tool_groups:
            continue
        lines += ["", f"### {_artifact_label(artifact)}", ""]
        for tool in sorted(tool_groups):
            lines += [f"#### {tool}", ""]
            for finding in tool_groups[tool]:
                lines.append(_finding_line(finding))
            lines.append("")

    summary = run_dir / "summary.md"
    summary.write_text("\n".join(lines) + "\n")
    secure_file(summary)

    src_lines = [f"# Sources: {target}", ""]
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        url = finding.get("source_url", "")
        key = (finding.get("source_tool", ""), finding.get("target", ""), url)
        if not url or key in seen:
            continue
        seen.add(key)
        observed = finding.get("observed_at")
        observed_text = f", observed {observed}" if observed else ""
        src_lines.append(
            f"- **{finding.get('source_tool')}** "
            f"({finding.get('artifact_type', '?')} {finding.get('target', '?')}{observed_text}) - {url}"
        )
    (run_dir / "sources.md").write_text("\n".join(src_lines) + "\n")
    secure_file(run_dir / "sources.md")
    return summary


def run(config, run_dir) -> int:  # noqa: ANN001 - config kept for dispatch consistency
    run_dir = Path(run_dir)
    if not run_dir.exists():
        print(f"run dir not found: {run_dir}")
        return 2
    summary = render(run_dir)
    print(f"rendered {summary}")
    return 0
