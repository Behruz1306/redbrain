from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from .core.models import ScanRequest, ScanResponse, Severity
from .event_bus import event_bus
from .orchestrator import start_scan, scan_results
from .seed.seed_brain import ensure_seeded

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await ensure_seeded()
    yield


app = FastAPI(title="RedBrain API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan(req: ScanRequest) -> ScanResponse:
    scan_id = await start_scan(req.repo_url, req.deployed_url)
    return ScanResponse(scan_id=scan_id, ws_url=f"/api/scan/{scan_id}/stream")


@app.websocket("/api/scan/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    try:
        await event_bus.stream_to_ws(scan_id, websocket)
    except WebSocketDisconnect:
        pass


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str) -> dict[str, Any]:
    result = scan_results.get(scan_id)
    is_done = event_bus.is_complete(scan_id)
    if result:
        vuln_count = len(result.get("vulnerabilities", []))
        return {
            "scan_id": scan_id,
            "status": "complete" if is_done else "running",
            "progress": 1.0 if is_done else 0.5,
            "current_stage": "done" if is_done else "scanning",
            "vulnerability_count": vuln_count,
        }
    return {
        "scan_id": scan_id,
        "status": "running" if not is_done else "error",
        "progress": 0.0,
        "current_stage": "initializing",
        "vulnerability_count": 0,
    }


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str) -> dict[str, Any]:
    result = scan_results.get(scan_id)
    if not result:
        return {"vulnerabilities": [], "report_markdown": "", "stats": {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "bounty_value": 0
        }}

    vulns = result.get("vulnerabilities", [])
    crit = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
    high = sum(1 for v in vulns if v.severity == Severity.HIGH)
    med = sum(1 for v in vulns if v.severity == Severity.MEDIUM)
    low = sum(1 for v in vulns if v.severity == Severity.LOW)

    return {
        "vulnerabilities": [v.model_dump() for v in vulns],
        "report_markdown": result.get("report_markdown", ""),
        "stats": {
            "total": len(vulns),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "bounty_value": crit * 3000 + high * 1500 + med * 500 + low * 100,
        },
    }


@app.get("/api/scan/{scan_id}/report/download")
async def download_report(scan_id: str) -> PlainTextResponse:
    result = scan_results.get(scan_id, {})
    md = result.get("report_markdown", "# No report available")
    return PlainTextResponse(md, media_type="text/markdown", headers={
        "Content-Disposition": f"attachment; filename=redbrain-report-{scan_id}.md"
    })


@app.get("/api/brain/graph")
async def brain_graph(scan_id: str | None = None) -> dict[str, Any]:
    if scan_id:
        result = scan_results.get(scan_id, {})
    elif scan_results:
        result = list(scan_results.values())[-1]
    else:
        result = {}
    return {
        "nodes": result.get("graph_nodes", []),
        "edges": result.get("graph_edges", []),
    }


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
