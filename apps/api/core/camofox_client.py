"""Jo Camofox Browser client — stealth headless browser for DAST.

Camofox (by Jo, YC W24) is a stealth headless browser built on a
Firefox fork with C++ anti-detection. It bypasses Cloudflare, WAFs,
and bot detection — ideal for security testing.

REST API at http://localhost:9377 when running.
Falls back to standard httpx when camofox is not available.

Set CAMOFOX_URL environment variable (default: http://localhost:9377).
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class CamofoxClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("CAMOFOX_URL", "http://localhost:9377")
        self._available: bool | None = None
        self._http: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=30.0)
        return self._http

    @property
    async def available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url}/health", timeout=3.0)
            self._available = resp.status_code == 200
        except Exception:
            self._available = False
        return self._available

    async def create_tab(
        self, url: str, user_id: str = "redbrain", session_key: str = "scan"
    ) -> dict[str, Any] | None:
        """Create a new browser tab navigated to URL."""
        if not await self.available:
            return None

        client = await self._get_client()
        resp = await client.post(
            f"{self.base_url}/tabs",
            json={"userId": user_id, "sessionKey": session_key, "url": url},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_snapshot(self, tab_id: str, user_id: str = "redbrain") -> dict[str, Any] | None:
        """Get accessibility snapshot of page with element refs."""
        if not await self.available:
            return None

        client = await self._get_client()
        resp = await client.get(
            f"{self.base_url}/tabs/{tab_id}/snapshot",
            params={"userId": user_id},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_links(self, tab_id: str, user_id: str = "redbrain") -> list[str]:
        """Extract all links from current page."""
        if not await self.available:
            return []

        client = await self._get_client()
        resp = await client.get(
            f"{self.base_url}/tabs/{tab_id}/links",
            params={"userId": user_id},
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("links", [])

    async def navigate(self, tab_id: str, url: str, user_id: str = "redbrain") -> bool:
        """Navigate tab to URL."""
        if not await self.available:
            return False

        client = await self._get_client()
        resp = await client.post(
            f"{self.base_url}/tabs/{tab_id}/navigate",
            json={"userId": user_id, "url": url},
        )
        return resp.status_code == 200

    async def click(self, tab_id: str, ref: str, user_id: str = "redbrain") -> bool:
        """Click element by reference ID."""
        if not await self.available:
            return False

        client = await self._get_client()
        resp = await client.post(
            f"{self.base_url}/tabs/{tab_id}/click",
            json={"userId": user_id, "ref": ref},
        )
        return resp.status_code == 200

    async def type_text(
        self, tab_id: str, ref: str, text: str, user_id: str = "redbrain"
    ) -> bool:
        """Type text into element."""
        if not await self.available:
            return False

        client = await self._get_client()
        resp = await client.post(
            f"{self.base_url}/tabs/{tab_id}/type",
            json={"userId": user_id, "ref": ref, "text": text, "pressEnter": False},
        )
        return resp.status_code == 200

    async def stealth_crawl(self, base_url: str) -> list[str]:
        """Crawl a website using stealth browser to bypass WAF/bot detection.

        Returns list of discovered URLs.
        """
        if not await self.available:
            return []

        try:
            tab = await self.create_tab(base_url, session_key="crawl")
            if not tab:
                return []

            tab_id = tab.get("id", "")
            links = await self.get_links(tab_id)
            return links
        except Exception as e:
            logger.warning(f"Camofox crawl failed: {e}")
            return []

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()


camofox = CamofoxClient()
