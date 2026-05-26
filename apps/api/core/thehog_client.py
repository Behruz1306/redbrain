"""The Hog API client — social listening and threat intelligence.

The Hog (YC F25) provides AI-powered GTM intelligence including
social listening across Reddit, LinkedIn, X, forums, and review sites.

RedBrain uses The Hog to enrich vulnerability reports with real-world
threat intelligence: are attackers discussing this vulnerability?
Are there public exploits? Is the CVE trending?

Set THE_HOG_API_KEY and THE_HOG_API_SECRET environment variables.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class TheHogClient:
    def __init__(self) -> None:
        self.api_key = os.getenv("THE_HOG_API_KEY", "")
        self.api_secret = os.getenv("THE_HOG_API_SECRET", "")
        self.base_url = "https://api.thehog.ai"
        self._http: httpx.AsyncClient | None = None

    @property
    def available(self) -> bool:
        return bool(self.api_key and self.api_secret)

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "x-api-key": self.api_key,
                    "x-api-secret": self.api_secret,
                    "apikey": self.api_key,
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        return self._http

    async def search_threat_intel(
        self, query: str, sources: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Search for threat intelligence signals related to a vulnerability.

        Uses The Hog's social listening to find discussions about
        CVEs, exploits, and vulnerability classes across the internet.
        """
        if not self.available:
            return self._offline_threat_intel(query)

        try:
            client = await self._get_client()
            payload = {
                "query": query,
                "sources": sources or ["reddit", "twitter", "forums"],
                "limit": 5,
            }

            for endpoint in [
                "/functions/v1/social-listen",
                "/functions/v1/search",
                "/v1/search",
                "/v1/signals",
            ]:
                try:
                    resp = await client.post(endpoint, json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        return data.get("results", data.get("signals", []))
                except Exception:
                    continue

            logger.info(f"The Hog API: no working endpoint found, using offline intel for '{query}'")
            return self._offline_threat_intel(query)

        except Exception as e:
            logger.warning(f"The Hog API error: {e}")
            return self._offline_threat_intel(query)

    async def monitor_cve(self, cve_id: str) -> dict[str, Any]:
        """Check if a CVE is being actively discussed or exploited."""
        signals = await self.search_threat_intel(
            f"{cve_id} exploit vulnerability",
            sources=["reddit", "twitter", "forums", "github"],
        )
        return {
            "cve_id": cve_id,
            "signal_count": len(signals),
            "signals": signals[:3],
            "trending": len(signals) > 2,
        }

    async def get_vuln_class_intel(self, vuln_class: str) -> dict[str, Any]:
        """Get threat intelligence for a vulnerability class (sqli, xss, etc)."""
        query_map = {
            "sqli": "SQL injection attack exploit 2026",
            "xss": "XSS cross-site scripting exploit payload",
            "idor": "IDOR insecure direct object reference bypass",
            "broken_auth": "authentication bypass default credentials attack",
            "info_disclosure": "information disclosure sensitive data exposure",
        }
        query = query_map.get(vuln_class, f"{vuln_class} security vulnerability exploit")
        signals = await self.search_threat_intel(query)
        return {
            "vuln_class": vuln_class,
            "threat_level": "high" if len(signals) > 3 else "medium" if signals else "low",
            "signals": signals,
        }

    def _offline_threat_intel(self, query: str) -> list[dict[str, Any]]:
        """Provide curated threat intelligence when API is unavailable.

        Note: These are general security advisories based on public data,
        not real-time signals. Live data requires The Hog API connection.
        """
        intel_db = {
            "sql injection": [
                {"source": "OWASP", "signal": "SQL injection is A03:2021 Injection in OWASP Top 10", "severity": "high"},
                {"source": "CWE", "signal": "CWE-89: SQL Injection — consistently in CWE Top 25 Most Dangerous Weaknesses", "severity": "high"},
            ],
            "xss": [
                {"source": "OWASP", "signal": "XSS falls under A03:2021 Injection in OWASP Top 10", "severity": "medium"},
                {"source": "CWE", "signal": "CWE-79: Cross-site Scripting — a top reported vulnerability class on bug bounty platforms", "severity": "medium"},
            ],
            "authentication": [
                {"source": "OWASP", "signal": "A07:2021 Identification and Authentication Failures in OWASP Top 10", "severity": "high"},
                {"source": "CWE", "signal": "CWE-287: Improper Authentication — credential attacks remain a leading breach vector", "severity": "critical"},
            ],
            "idor": [
                {"source": "OWASP", "signal": "A01:2021 Broken Access Control — #1 in OWASP Top 10", "severity": "high"},
            ],
            "default credentials": [
                {"source": "CWE", "signal": "CWE-798: Use of Hard-coded Credentials — listed in CWE Top 25", "severity": "critical"},
            ],
        }

        results = []
        query_lower = query.lower()
        for key, signals in intel_db.items():
            if key in query_lower:
                results.extend(signals)
        return results[:5]

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()


thehog = TheHogClient()
