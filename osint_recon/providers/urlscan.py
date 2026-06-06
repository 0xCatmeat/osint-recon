"""urlscan.io - search EXISTING public scans (passive; never submits a new public scan)."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlencode

import httpx

from osint_recon.providers.base import Health, Provider
from osint_recon.schema import Finding

_MAX_RESULTS = 5


class UrlscanProvider(Provider):
    name = "urlscan"
    requires = ("URLSCAN_API_KEY",)
    supported_artifacts = ("domain", "url")

    def _headers(self) -> dict[str, str]:
        return {"API-Key": self.config.get("URLSCAN_API_KEY") or ""}

    def health(self) -> Health:
        if not self.enabled():
            return self._disabled()
        try:
            with self.client() as client:
                resp = client.get("https://urlscan.io/user/quotas/", headers=self._headers())
        except httpx.HTTPError as exc:
            return Health(self.name, ok=False, detail=f"request failed: {exc}")
        ok = resp.status_code == 200
        return Health(self.name, ok=ok, detail="key valid" if ok else f"HTTP {resp.status_code}")

    def _query_string(self, artifact: str, artifact_type: str) -> str:
        if artifact_type == "url":
            return f'page.url:"{artifact}"'
        return f"page.domain:{artifact}"

    def source_url(self, artifact: str, artifact_type: str) -> str:
        return "https://urlscan.io/api/v1/search/?" + urlencode(
            {"q": self._query_string(artifact, artifact_type)}
        )

    def fetch(self, artifact: str, artifact_type: str) -> httpx.Response:
        with self.client() as client:
            return client.get(
                "https://urlscan.io/api/v1/search/",
                headers=self._headers(),
                params={"q": self._query_string(artifact, artifact_type), "size": "100"},
            )

    def parse(self, raw: Any, artifact: str, artifact_type: str) -> list[Finding]:
        if not isinstance(raw, dict):
            return []
        results = raw.get("results", []) or []
        total = raw.get("total", len(results))
        findings = [
            self._finding(
                artifact,
                artifact_type,
                f"{total} existing urlscan result(s)",
                selector="urlscan_total",
                confidence="high" if results else "medium",
            )
        ]
        for result in results[:_MAX_RESULTS]:
            page = result.get("page") or {}
            task = result.get("task") or {}
            page_url = page.get("url") or ""
            task_url = task.get("url") or ""
            result_url = result.get("result", "")
            label = f"Final page: {page_url or task_url}"
            if task_url and task_url != page_url:
                label += f" (submitted URL: {task_url})"
            if result_url:
                label += f" - {result_url}"
            findings.append(
                self._finding(artifact, artifact_type, label, selector=result.get("_id", ""))
            )
        return findings
