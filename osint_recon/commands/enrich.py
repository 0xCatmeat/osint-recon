"""`osint-recon enrich` - fan out passive providers over a target and write a full run."""

from __future__ import annotations

import json
from pathlib import Path

from osint_recon.artifacts import detect_artifact, expand_targets
from osint_recon.cache import Store
from osint_recon.commands import report
from osint_recon.config import Config
from osint_recon.providers import all_providers
from osint_recon.run import Run
from osint_recon.schema import provenance_hash


def _dry_run_json(
    config: Config,
    target: str,
    artifact_type: str,
    store: Store,
    pivots: bool,
    max_pivots: int,
) -> str:
    """Build the JSON plan for ``enrich --dry-run --json``."""
    providers = all_providers(config)
    tasks = expand_targets(target, artifact_type, pivots=pivots, max_pivots=max_pivots)
    planned_artifacts: list[dict] = []
    planned_providers: dict[str, list[str]] = {}
    total = 0

    for artifact, atype in tasks:
        planned_artifacts.append({"artifact": artifact, "type": atype})
        enabled = []
        for provider in providers:
            if provider.supports(atype):
                enabled.append(provider.name)
                total += 1
        planned_providers[artifact] = enabled

    result = {
        "target": target,
        "artifact_type": artifact_type,
        "planned_artifacts": planned_artifacts,
        "planned_providers": planned_providers,
        "total_planned_queries": total,
        "pivots_enabled": pivots,
        "max_pivots": max_pivots,
    }
    return json.dumps(result, indent=2)


def _enrich_json(  # noqa: PLR0913
    enrich_run: Run,
    providers_used: list[str],
    errors: list[tuple[str, str]],
    cache_hits: int,
    cache_misses: int,
) -> str:
    """Build the JSON summary for a completed ``enrich --json``."""
    result = {
        "target": enrich_run.target,
        "artifact_type": enrich_run.artifact_type,
        "case_id": enrich_run.case_id,
        "run_dir": str(enrich_run.dir),
        "providers_used": providers_used,
        "finding_count": enrich_run.finding_count,
        "errors": [{"provider": p, "error": e} for p, e in errors],
        "cache": {"hits": cache_hits, "misses": cache_misses},
    }
    return json.dumps(result, indent=2)


def run(  # noqa: PLR0913
    config: Config,
    target: str,
    *,
    base_dir: Path | str | None = None,
    case_id: str | None = None,
    pivots: bool = True,
    max_pivots: int = 3,
    dry_run: bool = False,
    offline: bool = False,
    refresh: bool = False,
    max_age: int | None = None,
    shodan_search: str | None = None,
    json_output: bool = False,
) -> int:
    artifact_type = detect_artifact(target)
    if artifact_type is None:
        msg = (
            f"could not classify target {target!r} (expected ip, domain, url, evm_address, or hash)"
        )
        if json_output:
            print(json.dumps({"error": msg, "target": target}))
        else:
            print(msg)
        return 2

    store = Store()
    providers = all_providers(config)

    # Dry run: plan only, with no provider queries or output directory.
    if dry_run:
        tasks = expand_targets(target, artifact_type, pivots=pivots, max_pivots=max_pivots)
        if json_output:
            print(_dry_run_json(config, target, artifact_type, store, pivots, max_pivots))
        else:
            print(f"osint-recon enrich --dry-run {target} ({artifact_type})")
            print(f"  pivots: {'enabled' if pivots else 'disabled'} (max {max_pivots})")
            for artifact, atype in tasks:
                relation = "primary" if artifact == target else "pivot"
                enabled = [p.name for p in providers if p.supports(atype)]
                print(
                    f"  {artifact:<40} {atype:<12} {relation:<12} providers: {', '.join(enabled) or 'none'}"
                )
        return 0

    enrich_run = Run(target, artifact_type, base_dir, case_id=case_id)
    if refresh:
        enrich_run.cache_mode = "refresh"
    elif offline:
        enrich_run.cache_mode = "offline"
    elif max_age is not None:
        enrich_run.cache_mode = f"max-age:{max_age}s"
    if not json_output:
        print(f"osint-recon enrich {target} ({artifact_type})")
        print(f"  run dir: {enrich_run.dir}\n")

    for index, (artifact, atype) in enumerate(
        expand_targets(target, artifact_type, pivots=pivots, max_pivots=max_pivots)
    ):
        relation = "primary" if index == 0 else f"resolved_{atype}_pivot"
        enrich_run.record_artifact(artifact, atype, relation)
        for provider in providers:
            if not provider.supports(atype):
                continue
            try:
                fetched = provider.query(
                    artifact,
                    atype,
                    store,
                    offline=offline,
                    bypass_cache=refresh,
                    max_age=float(max_age) if max_age is not None else None,
                )
            except NotImplementedError:
                continue
            except Exception as exc:  # noqa: BLE001 - record and keep going
                enrich_run.errors.append((provider.name, f"{artifact}: {exc}"))
                if not json_output:
                    print(f"  ! {provider.name:<11} {artifact}: {exc}")
                continue
            observed_at = fetched.fetched_at or fetched.cached_at
            raw_path = enrich_run.store_raw(
                provider.name,
                artifact,
                atype,
                fetched.raw_bytes,
                source_url=fetched.source_url,
                observed_at=observed_at,
                cache_hit=fetched.cache_hit,
                cached_at=fetched.cached_at,
                ttl_seconds=fetched.ttl_seconds,
            )
            phash = provenance_hash(fetched.raw_bytes)
            for finding in fetched.findings:
                finding.raw_path = raw_path
                finding.provenance_hash = phash
            enrich_run.add_findings(fetched.findings, observed_at=observed_at)
            enrich_run.record_provider(provider.name, fetched.source_url)
            if not json_output:
                print(f"  + {provider.name:<11} {artifact}: {len(fetched.findings)} finding(s)")

    # Shodan search costs credits, so it stays opt-in.
    if shodan_search:
        from osint_recon.providers.shodan import ShodanProvider as _SP  # noqa: F811

        shodan = next((p for p in providers if isinstance(p, _SP)), None)
        if shodan and shodan.enabled():
            try:
                fetched = shodan.search(shodan_search, store)
            except Exception as exc:  # noqa: BLE001
                enrich_run.errors.append(("shodan-search", f"{shodan_search}: {exc}"))
                if not json_output:
                    print(f"  ! shodan-search {shodan_search}: {exc}")
            else:
                observed_at = fetched.fetched_at or fetched.cached_at
                raw_path = enrich_run.store_raw(
                    "shodan-search",
                    shodan_search,
                    "shodan_search",
                    fetched.raw_bytes,
                    source_url=fetched.source_url,
                    observed_at=observed_at,
                    cache_hit=fetched.cache_hit,
                    cached_at=fetched.cached_at,
                    ttl_seconds=fetched.ttl_seconds,
                )
                phash = provenance_hash(fetched.raw_bytes)
                for finding in fetched.findings:
                    finding.raw_path = raw_path
                    finding.provenance_hash = phash
                enrich_run.add_findings(fetched.findings, observed_at=observed_at)
                enrich_run.record_provider("shodan-search", fetched.source_url)
                if not json_output:
                    print(f"  + shodan-search {shodan_search}: {len(fetched.findings)} finding(s)")

    enrich_run.write_metadata(command=f"osint-recon enrich {target}")
    summary = report.render(enrich_run.dir)

    if json_output:
        print(
            _enrich_json(
                enrich_run,
                enrich_run.providers_used,
                enrich_run.errors,
                enrich_run.cache_hits,
                enrich_run.cache_misses,
            )
        )
    else:
        print(f"\n  {enrich_run.finding_count} finding(s) -> {summary}")
    return 0
