from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding


class EtherscanProvider(Provider):
    name = "etherscan"
    requires = ("ETHERSCAN_API_KEY",)
    supported_artifacts = ("evm_address",)
    cache_ttl_seconds = 3600.0  # 1h

    _BASE = "https://api.etherscan.io/v2/api"
    _CHAINID = "1"  # Ethereum mainnet

    def health(self) -> Health:
        if not self.enabled():
            return self._disabled()
        key = self.config.get("ETHERSCAN_API_KEY")
        try:
            with self.client() as client:
                resp = client.get(
                    self._BASE,
                    params={
                        "chainid": self._CHAINID,
                        "module": "stats",
                        "action": "ethprice",
                        "apikey": key,
                    },
                )
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        if resp.status_code != 200:
            return Health(self.name, ok=False, detail=f"HTTP {resp.status_code}")
        data = resp.json()
        if str(data.get("status")) == "1":
            result = data.get("result", {})
            eth = result.get("ethusd", "?") if isinstance(result, dict) else "?"
            return Health(self.name, ok=True, detail=f"V2 OK (ETH=${eth})")
        return Health(self.name, ok=False, detail=str(data.get("result") or data.get("message")))

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return f"https://etherscan.io/address/{artifact}"

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        key = self.config.get("ETHERSCAN_API_KEY")

        results: dict[str, Any] = {}
        with self.client() as client:
            try:
                bal_resp = client.get(
                    self._BASE,
                    params={
                        "chainid": self._CHAINID,
                        "module": "account",
                        "action": "balance",
                        "address": artifact,
                        "apikey": key,
                    },
                )
                if bal_resp.status_code == 200:
                    results["balance"] = bal_resp.json()
                else:
                    results["balance"] = {}
            except httpx.HTTPError:
                results["balance"] = {}

            try:
                tx_resp = client.get(
                    self._BASE,
                    params={
                        "chainid": self._CHAINID,
                        "module": "account",
                        "action": "txlist",
                        "address": artifact,
                        "page": "1",
                        "offset": "5",
                        "apikey": key,
                    },
                )
                if tx_resp.status_code == 200:
                    results["transactions"] = tx_resp.json()
                else:
                    results["transactions"] = {}
            except httpx.HTTPError:
                results["transactions"] = {}

        body = json.dumps(results, ensure_ascii=False).encode("utf-8")
        resp = httpx.Response(
            200,
            content=body,
            request=httpx.Request("GET", self.source_url(artifact, artifact_type)),
        )
        return resp

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(raw, dict):
            return findings

        bal = raw.get("balance", {}) if isinstance(raw, dict) else {}
        if isinstance(bal, dict) and str(bal.get("status")) == "1":
            wei_str = bal.get("result", "0")
            try:
                wei = Decimal(wei_str)
                eth = wei / Decimal("1e18")
                eth_str = f"{eth:,.6f}".rstrip("0").rstrip(".")
                if eth_str == "":
                    eth_str = "0"
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"Balance: {eth_str} ETH",
                        selector="balance",
                        confidence="high",
                    )
                )
            except (InvalidOperation, ValueError, TypeError):
                pass

        txs = raw.get("transactions", {})
        if isinstance(txs, dict) and str(txs.get("status")) == "1":
            tx_list = txs.get("result", [])
            if isinstance(tx_list, list) and tx_list:
                count = len(tx_list)
                latest_block = (
                    tx_list[0].get("blockNumber", "?") if isinstance(tx_list[0], dict) else "?"
                )
                findings.append(
                    self._finding(
                        artifact,
                        artifact_type,
                        f"Recent txs: {count}, latest block: {latest_block}",
                        selector="txlist",
                        confidence="high",
                    )
                )

        return findings
