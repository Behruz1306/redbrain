from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from ..core.models import EndpointInfo
from ..event_bus import event_bus


class ReconAgent:
    def __init__(self, scan_id: str, deployed_url: str) -> None:
        self.scan_id = scan_id
        self.base_url = deployed_url.rstrip("/")
        self.endpoints: list[EndpointInfo] = []
        self._visited: set[str] = set()
        self._max_depth = 3
        self._timeout = 30.0

    async def run(self) -> list[EndpointInfo]:
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=10.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            await self._crawl(client, "/", depth=0)

            # Probe common API paths
            await self._probe_common_paths(client)

        await event_bus.emit(self.scan_id, "recon:complete", {
            "endpoints_count": len(self.endpoints),
        })
        return self.endpoints

    async def _crawl(self, client: httpx.AsyncClient, path: str, depth: int) -> None:
        if depth > self._max_depth or path in self._visited:
            return
        self._visited.add(path)

        try:
            resp = await client.get(path)
        except Exception:
            return

        await event_bus.emit(self.scan_id, "recon:page_visited", {
            "url": path,
            "status": resp.status_code,
        })

        # Detect stack from headers
        techs = self._detect_stack(resp)
        if techs:
            await event_bus.emit(self.scan_id, "recon:stack_detected", {
                "technologies": techs,
            })

        # Extract links
        links = self._extract_links(resp.text, path)
        # Extract API calls from inline scripts
        api_paths = self._extract_api_calls(resp.text)

        for api_path in api_paths:
            await self._register_endpoint("GET", api_path, client)

        tasks = []
        for link in links[:20]:
            if link not in self._visited:
                tasks.append(self._crawl(client, link, depth + 1))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_common_paths(self, client: httpx.AsyncClient) -> None:
        common = [
            "/api", "/api/v1", "/rest", "/graphql",
            "/api/users", "/api/products", "/api/login",
            "/api/admin", "/admin", "/swagger.json",
            "/api-docs", "/.env", "/debug", "/health",
            "/api/Feedbacks", "/api/Complaints", "/api/Orders",
            "/api/BasketItems", "/api/Quantitys", "/api/Challenges",
        ]
        for path in common:
            if path in self._visited:
                continue
            try:
                resp = await client.get(path)
                if resp.status_code < 404:
                    await self._register_endpoint("GET", path, client)
            except Exception:
                continue

    async def _register_endpoint(
        self, method: str, path: str, client: httpx.AsyncClient
    ) -> None:
        if any(e.path == path and e.method == method for e in self.endpoints):
            return

        auth_required = await self._check_auth(client, path)

        endpoint = EndpointInfo(
            method=method,
            path=path,
            auth_required=auth_required,
        )
        self.endpoints.append(endpoint)

        await event_bus.emit(self.scan_id, "recon:endpoint_found", {
            "method": method,
            "path": path,
            "auth_required": auth_required,
        })

    async def _check_auth(self, client: httpx.AsyncClient, path: str) -> bool | None:
        try:
            resp = await client.get(path)
            if resp.status_code in (401, 403):
                return True
            if resp.status_code == 200:
                return False
        except Exception:
            pass
        return None

    def _detect_stack(self, resp: httpx.Response) -> list[str]:
        techs = []
        headers = resp.headers
        if "x-powered-by" in headers:
            techs.append(headers["x-powered-by"])
        if "server" in headers:
            techs.append(headers["server"])
        body = resp.text[:5000]
        if "express" in body.lower() or "Express" in (headers.get("x-powered-by") or ""):
            techs.append("Express.js")
        if "angular" in body.lower():
            techs.append("Angular")
        if "react" in body.lower():
            techs.append("React")
        return techs

    def _extract_links(self, html: str, current_path: str) -> list[str]:
        links: list[str] = []
        for match in re.finditer(r'href=["\']([^"\'#]+)', html):
            href = match.group(1)
            if href.startswith("http"):
                parsed = urlparse(href)
                base_parsed = urlparse(self.base_url)
                if parsed.netloc == base_parsed.netloc:
                    links.append(parsed.path)
            elif href.startswith("/"):
                links.append(href)
            elif not href.startswith(("javascript:", "mailto:", "tel:")):
                links.append(urljoin(current_path, href))
        return links

    def _extract_api_calls(self, html: str) -> list[str]:
        paths: list[str] = []
        for match in re.finditer(r"""(?:fetch|axios\.get|axios\.post|\.get|\.post)\s*\(\s*['"](/[^'"]+)['"]""", html):
            paths.append(match.group(1))
        for match in re.finditer(r"""['"](/api/[^'"]+)['"]""", html):
            paths.append(match.group(1))
        return list(set(paths))
