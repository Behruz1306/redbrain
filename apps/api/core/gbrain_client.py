from __future__ import annotations

import os
from typing import Any

import httpx


class GBrainClient:
    """Client for GBrain knowledge graph API.

    Falls back to in-memory storage if GBRAIN_API_KEY is not set.
    """

    def __init__(self) -> None:
        self.api_key = os.getenv("GBRAIN_API_KEY", "")
        self.base_url = os.getenv("GBRAIN_BASE_URL", "https://api.gbrain.io")
        self._local_pages: dict[str, dict[str, Any]] = {}
        self._local_links: list[dict[str, str]] = []
        self._use_local = not self.api_key

    async def create_page(
        self,
        title: str,
        content: str,
        page_type: str,
        metadata: dict[str, Any] | None = None,
        links: list[str] | None = None,
    ) -> str:
        """Create a page in GBrain. Returns page ID."""
        if self._use_local:
            page_id = f"{page_type}/{title}"
            self._local_pages[page_id] = {
                "title": title,
                "content": content,
                "type": page_type,
                "metadata": metadata or {},
                "links": links or [],
            }
            if links:
                for link in links:
                    self._local_links.append({
                        "source": page_id,
                        "target": link,
                    })
            return page_id

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/v1/pages",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "title": title,
                    "content": content,
                    "metadata": {
                        "type": page_type,
                        **(metadata or {}),
                    },
                    "links": links or [],
                },
            )
            resp.raise_for_status()
            return resp.json()["id"]

    async def get_page(self, page_id: str) -> dict[str, Any] | None:
        """Get a page by ID."""
        if self._use_local:
            return self._local_pages.get(page_id)

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}/v1/pages/{page_id}",
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()

    async def search_pages(
        self, query: str, page_type: str | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Search pages by content or metadata."""
        if self._use_local:
            results = []
            for pid, page in self._local_pages.items():
                if page_type and page["type"] != page_type:
                    continue
                if query.lower() in page["content"].lower() or query.lower() in page["title"].lower():
                    results.append({"id": pid, **page})
            return results[:limit]

        async with httpx.AsyncClient() as client:
            params: dict[str, Any] = {"q": query, "limit": limit}
            if page_type:
                params["type"] = page_type
            resp = await client.get(
                f"{self.base_url}/v1/pages/search",
                headers={"Authorization": f"Bearer {self.api_key}"},
                params=params,
            )
            resp.raise_for_status()
            return resp.json()["results"]

    async def create_link(
        self, source_id: str, target_id: str, link_type: str
    ) -> None:
        """Create a typed edge between two pages."""
        if self._use_local:
            self._local_links.append({
                "source": source_id,
                "target": target_id,
                "type": link_type,
            })
            return

        async with httpx.AsyncClient() as client:
            await client.post(
                f"{self.base_url}/v1/links",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "source": source_id,
                    "target": target_id,
                    "type": link_type,
                },
            )

    async def get_graph(self, root_id: str | None = None) -> dict[str, Any]:
        """Get full graph or subgraph from a root."""
        if self._use_local:
            nodes = [
                {"id": pid, "label": p["title"], "type": p["type"]}
                for pid, p in self._local_pages.items()
            ]
            edges = self._local_links
            return {"nodes": nodes, "edges": edges}

        async with httpx.AsyncClient() as client:
            params = {}
            if root_id:
                params["root"] = root_id
            resp = await client.get(
                f"{self.base_url}/v1/graph",
                headers={"Authorization": f"Bearer {self.api_key}"},
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    @property
    def page_count(self) -> int:
        return len(self._local_pages)

    @property
    def link_count(self) -> int:
        return len(self._local_links)


gbrain = GBrainClient()
