"""Artifact-type detection and target expansion."""

from __future__ import annotations

import ipaddress
import re
import socket

_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_EVM_ADDRESS_RE = re.compile(r"^0x[A-Fa-f0-9]{40}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]{1,63}\.)+[A-Za-z]{2,}$")


def detect_artifact(target: str) -> str | None:
    """Classify a target as one of: url, evm_address, hash, ip, domain. None if unrecognized."""
    value = target.strip()
    if value.lower().startswith(("http://", "https://")):
        return "url"
    if _EVM_ADDRESS_RE.match(value):
        return "evm_address"
    if _HASH_RE.match(value):
        return "hash"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if _DOMAIN_RE.match(value):
        return "domain"
    return None


def resolve_ips(domain: str, limit: int = 3) -> list[str]:
    """Best-effort A/AAAA resolution so a domain run can also query IP providers."""
    ips: list[str] = []
    try:
        for info in socket.getaddrinfo(domain, None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except OSError:
        pass
    return ips[:limit]


def expand_targets(
    target: str,
    artifact_type: str,
    *,
    pivots: bool = True,
    max_pivots: int = 3,
) -> list[tuple[str, str]]:
    """The primary target plus any pivots (a domain expands to its resolved IPs).

    Set ``pivots=False`` to suppress IP resolution (``--no-pivots``).
    ``max_pivots`` caps resolved IPs when pivots are enabled (``--max-pivots``).
    """
    tasks = [(target, artifact_type)]
    if artifact_type == "domain" and pivots:
        tasks.extend((ip, "ip") for ip in resolve_ips(target, limit=max_pivots))
    return tasks
