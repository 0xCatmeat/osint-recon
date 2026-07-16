from __future__ import annotations

import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path

from osint_recon.config import Config
from osint_recon.providers import all_providers

OSINT_ROOT = Path.home() / "OSINT"
BIN_DIR = OSINT_ROOT / "bin"
REQUIRED_BINARIES = {
    "subfinder": ["-version"],
    "mapcidr": ["-version"],
    "gau": ["--version"],
    "gitleaks": ["version"],
    "trufflehog": ["--version"],
}
# Active tools touch the target directly. doctor only inventories them.
ACTIVE_BINARIES = {
    "dnsx": ["-version"],
    "httpx": ["-version"],
    "tlsx": ["-version"],
    "nuclei": ["-version"],
    "katana": ["-version"],
    "uncover": ["-version"],
}
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))[2:]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version(path: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            [str(path), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"version check failed: {exc}"
    text = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    text = ANSI_RE.sub("", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    version_lines = [line for line in lines if "version" in line.lower()]
    if version_lines:
        return version_lines[-1]
    return lines[-1] if lines else f"exit {result.returncode}"


def _build_json_output(config: Config, local: bool) -> dict:
    providers_out: list[dict] = []
    for provider in all_providers(config):
        health = provider.health()
        entry: dict = {
            "name": provider.name,
            "status": "ok" if health.ok else "fail",
            "enabled": health.enabled,
            "detail": health.detail,
        }
        if not health.enabled:
            entry["status"] = "skip"
        elif not health.ok and not provider.requires:
            # A keyless service that blips is a warning, not a hard failure.
            entry["status"] = "warn"
        providers_out.append(entry)

    result: dict = {
        "env_path": str(config.env_path),
        "providers": providers_out,
        "exit_status": "ok",
    }

    if local:
        local_data: dict = {"paths": [], "binaries": []}
        env_entry = {"name": "apis.env"}
        if config.env_path.exists():
            env_mode = _mode(config.env_path)
            env_entry["status"] = "ok" if env_mode == "600" else "warn"
            env_entry["mode"] = env_mode
        else:
            env_entry["status"] = "missing"
        local_data["paths"].append(env_entry)

        for path_name in (".cache", "reports"):
            path = OSINT_ROOT / path_name
            entry = {"name": path_name}
            if not path.exists():
                entry["status"] = "missing"
            else:
                mode = _mode(path)
                entry["status"] = "ok" if mode == "700" else "warn"
                entry["mode"] = mode
            local_data["paths"].append(entry)

        for name, args in REQUIRED_BINARIES.items():
            path = BIN_DIR / name
            entry = {"name": name, "kind": "passive"}
            if not path.exists():
                entry["status"] = "missing"
            else:
                entry["status"] = "ok"
                entry["version"] = _version(path, args)
                entry["sha256"] = _sha256(path)
                entry["mode"] = _mode(path)
            local_data["binaries"].append(entry)

        for name, args in ACTIVE_BINARIES.items():
            path = BIN_DIR / name
            entry = {"name": name, "kind": "active"}
            if not path.exists():
                entry["status"] = "warn"
            else:
                entry["status"] = "ok"
                entry["version"] = _version(path, args)
                entry["sha256"] = _sha256(path)
                entry["mode"] = _mode(path)
            local_data["binaries"].append(entry)

        result["local"] = local_data

        for p in result["providers"]:
            if p["status"] == "fail":
                result["exit_status"] = "error"
        for p in local_data["paths"]:
            if p.get("status") in ("warn", "missing"):
                result["exit_status"] = "warn"
        for b in local_data["binaries"]:
            if b["status"] == "missing":
                result["exit_status"] = "error"
            elif b["status"] == "warn" and result["exit_status"] == "ok":
                result["exit_status"] = "warn"

    return result


def _print_local_checks(config: Config) -> int:
    exit_code = 0
    print("\nLOCAL CHECKS")
    print("-" * 96)

    env_status = "ok"
    env_detail = "missing"
    if config.env_path.exists():
        env_mode = _mode(config.env_path)
        env_status = "ok" if env_mode == "600" else "WARN"
        env_detail = f"mode={env_mode} (expected 600)"
        if env_status != "ok":
            exit_code = 1
    print(f"{'apis.env':<12} {env_status:<7} {env_detail}")

    for path in (OSINT_ROOT / ".cache", OSINT_ROOT / "reports"):
        if not path.exists():
            print(f"{path.name:<12} WARN    missing")
            exit_code = 1
            continue
        mode = _mode(path)
        status = "ok" if mode == "700" else "WARN"
        if status != "ok":
            exit_code = 1
        print(f"{path.name:<12} {status:<7} mode={mode} (expected 700)")

    print(f"{'python':<12} ok      {sys.version.split()[0]}")
    for name, args in REQUIRED_BINARIES.items():
        path = BIN_DIR / name
        if not path.exists():
            print(f"{name:<12} FAIL    missing from {BIN_DIR}")
            exit_code = 1
            continue
        detail = f"{_version(path, args)}; sha256={_sha256(path)[:16]}...; mode={_mode(path)}"
        print(f"{name:<12} ok      {detail}")
    for name, args in ACTIVE_BINARIES.items():
        path = BIN_DIR / name
        if not path.exists():
            print(f"{name:<12} warn    missing (active) from {BIN_DIR}")
            continue
        detail = f"{_version(path, args)}; sha256={_sha256(path)[:16]}...; mode={_mode(path)}"
        print(f"{name:<12} ok      {detail} (active)")
    return exit_code


def run(config: Config, *, local: bool = False, json_output: bool = False) -> int:
    if json_output:
        result = _build_json_output(config, local)
        print(json.dumps(result, indent=2))
        if result["exit_status"] == "error":
            return 1
        return 0

    providers = all_providers(config)
    print(f"osint-recon doctor - env: {config.env_path}")
    if not config.env_path.exists():
        print("  (env file not found - keyed providers will show as disabled)")
    print(f"\n{'PROVIDER':<12} {'STATUS':<7} DETAIL")
    print("-" * 64)

    exit_code = 0
    for provider in providers:
        health = provider.health()
        keyless = not provider.requires
        if not health.enabled:
            status = "skip"
        elif health.ok:
            status = "ok"
        elif keyless:
            status = "warn"
        else:
            status = "FAIL"
            exit_code = 1
        print(f"{health.provider:<12} {status:<7} {health.detail}")
    if local:
        exit_code = max(exit_code, _print_local_checks(config))
    return exit_code
