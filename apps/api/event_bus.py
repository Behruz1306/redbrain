from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime
from typing import Any

from fastapi import WebSocket


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = defaultdict(list)

    def subscribe(self, scan_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers[scan_id].append(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers[scan_id] = [
            q for q in self._subscribers[scan_id] if q is not queue
        ]

    async def emit(self, scan_id: str, event_type: str, payload: dict[str, Any] | None = None) -> None:
        event = {
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "payload": payload or {},
        }
        for queue in self._subscribers[scan_id]:
            await queue.put(event)

    async def stream_to_ws(self, scan_id: str, ws: WebSocket) -> None:
        queue = self.subscribe(scan_id)
        try:
            while True:
                event = await queue.get()
                await ws.send_json(event)
                if event["type"] == "scan:complete":
                    break
        finally:
            self.unsubscribe(scan_id, queue)


event_bus = EventBus()
