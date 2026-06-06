"""Command-line entry point for osint-recon."""

from __future__ import annotations

import argparse
from pathlib import Path

from osint_recon import __version__
from osint_recon.commands import doctor, enrich, normalize, report, scope_gate
from osint_recon.config import Config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-recon",
        description="API-first OSINT toolkit - fan out, normalize evidence, build reports.",
    )
    parser.add_argument("--version", action="version", version=f"osint-recon {__version__}")
    parser.add_argument(
        "--env",
        type=Path,
        default=None,
        help="path to apis.env (default: ~/OSINT/config/apis.env)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_doctor = sub.add_parser("doctor", help="validate API keys and show provider status/quota")
    p_doctor.add_argument("--local", action="store_true", help="also check local tools and files")
    p_doctor.add_argument("--json", action="store_true", help="output machine-readable JSON")

    p_enrich = sub.add_parser("enrich", help="fan out passive providers and build a report")
    p_enrich.add_argument("target", help="ip, domain, url, evm_address, or file hash")
    p_enrich.add_argument("--json", action="store_true", help="output machine-readable JSON")
    p_enrich.add_argument("--out", type=Path, default=None, help="custom report base directory")
    p_enrich.add_argument("--case-id", default=None, help="override generated case ID")
    p_enrich.add_argument(
        "--no-pivots", action="store_true", help="do not resolve and query IP pivots"
    )
    p_enrich.add_argument(
        "--max-pivots", type=int, default=3, help="cap resolved IP pivots (default: 3)"
    )
    p_enrich.add_argument(
        "--dry-run",
        action="store_true",
        help="show planned artifacts/providers without provider queries",
    )
    p_enrich.add_argument(
        "--offline", action="store_true", help="use cached provider responses only"
    )
    p_enrich.add_argument(
        "--refresh", action="store_true", help="bypass cache and fetch fresh data"
    )
    p_enrich.add_argument(
        "--max-age",
        type=int,
        default=None,
        help="use cache only if younger than N seconds",
    )
    p_enrich.add_argument(
        "--shodan-search",
        default=None,
        help="run a Shodan search query (costs 1 query credit; opt-in, never default)",
    )

    p_norm = sub.add_parser("normalize", help="rebuild findings.jsonl from a run's raw/ dir")
    p_norm.add_argument("run_dir", help="path to reports/<target>/<timestamp>/")

    p_report = sub.add_parser("report", help="render summary.md / sources.md from a run dir")
    p_report.add_argument("run_dir", help="path to reports/<target>/<timestamp>/")

    p_scope = sub.add_parser("scope-gate", help="authorize active tooling for a target")
    p_scope.add_argument("--target", required=True, help="target that active tooling would touch")
    p_scope.add_argument(
        "--scope-file", type=Path, required=True, help="file describing allowed scope"
    )
    p_scope.add_argument(
        "--authorization-note", required=True, help="why this active run is allowed"
    )
    p_scope.add_argument(
        "--out-dir", type=Path, default=None, help="directory for the audit record"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    ns = build_parser().parse_args(argv)
    config = Config.load(ns.env)

    if ns.command == "doctor":
        return doctor.run(config, local=ns.local, json_output=ns.json)
    if ns.command == "enrich":
        return enrich.run(
            config,
            ns.target,
            base_dir=ns.out,
            case_id=ns.case_id,
            pivots=not ns.no_pivots,
            max_pivots=ns.max_pivots,
            dry_run=ns.dry_run,
            offline=ns.offline,
            refresh=ns.refresh,
            max_age=ns.max_age,
            shodan_search=ns.shodan_search,
            json_output=ns.json,
        )
    if ns.command == "normalize":
        return normalize.run(config, ns.run_dir)
    if ns.command == "report":
        return report.run(config, ns.run_dir)
    if ns.command == "scope-gate":
        return scope_gate.run(ns.target, ns.scope_file, ns.authorization_note, ns.out_dir)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
