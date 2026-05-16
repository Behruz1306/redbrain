from __future__ import annotations

import asyncio
import uuid
from typing import Any

from .agents.sast import SASTAgent
from .agents.recon import ReconAgent
from .agents.correlate import CorrelateAgent
from .agents.exploit import ExploitAgent
from .agents.report import ReportAgent
from .event_bus import event_bus

scan_results: dict[str, dict[str, Any]] = {}


class ScanOrchestrator:
    def __init__(self, scan_id: str, repo_url: str, deployed_url: str) -> None:
        self.scan_id = scan_id
        self.repo_url = repo_url
        self.deployed_url = deployed_url
        self.sast = SASTAgent(scan_id, repo_url)
        self.recon = ReconAgent(scan_id, deployed_url)
        self.correlate = CorrelateAgent(scan_id)
        self.exploit = ExploitAgent(scan_id, deployed_url)
        self.report = ReportAgent(scan_id)

    async def run(self) -> None:
        try:
            await asyncio.wait_for(self._run_pipeline(), timeout=180.0)
        except asyncio.TimeoutError:
            await event_bus.emit(self.scan_id, "scan:error", {
                "error": "Scan timed out after 180 seconds",
            })
        except Exception as e:
            await event_bus.emit(self.scan_id, "scan:error", {
                "error": str(e),
            })

    async def _run_pipeline(self) -> None:
        await event_bus.emit(self.scan_id, "scan:started", {
            "repo_url": self.repo_url,
            "deployed_url": self.deployed_url,
        })

        # Phase 1: SAST + Recon in parallel
        sast_result, recon_result = await asyncio.gather(
            self.sast.run(),
            self.recon.run(),
        )

        # Phase 2: Correlation
        correlations = await self.correlate.run(sast_result, recon_result)

        # Phase 3: Exploitation
        vulnerabilities, exploits = await self.exploit.run(correlations, sast_result, recon_result)

        # Phase 4: Report generation
        report_md = await self.report.run(
            sast_result, recon_result, correlations, (vulnerabilities, exploits)
        )

        # Build graph data for frontend
        graph_nodes = []
        graph_edges = []
        cve_node_ids: set[str] = set()

        for f in sast_result:
            if f.risk_signals:
                graph_nodes.append({"id": f.id, "label": f.name, "type": "function"})
                for match in f.cve_matches:
                    cve_node_id = f"cve-{match.cve_id}"
                    if cve_node_id not in cve_node_ids:
                        graph_nodes.append({"id": cve_node_id, "label": match.cve_id, "type": "cve"})
                        cve_node_ids.add(cve_node_id)
                    graph_edges.append({"source": f.id, "target": cve_node_id, "label": "similar_to"})

        for e in recon_result:
            graph_nodes.append({"id": e.id, "label": f"{e.method} {e.path}", "type": "endpoint"})
        for v in vulnerabilities:
            graph_nodes.append({"id": v.id, "label": v.title[:30], "type": "vulnerability"})
        for c in correlations:
            graph_edges.append({"source": c.function_id, "target": c.endpoint_id, "label": "implements"})
        for v in vulnerabilities:
            if v.function_id:
                graph_edges.append({"source": v.id, "target": v.function_id, "label": "located_in"})
            if v.endpoint_id:
                graph_edges.append({"source": v.id, "target": v.endpoint_id, "label": "affects"})

        scan_results[self.scan_id] = {
            "vulnerabilities": vulnerabilities,
            "exploits": exploits,
            "report_markdown": report_md,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
            "status": "complete",
        }

        await event_bus.emit(self.scan_id, "scan:complete", {
            "scan_id": self.scan_id,
        })


_active_scans: dict[str, asyncio.Task[None]] = {}


async def start_scan(repo_url: str, deployed_url: str) -> str:
    scan_id = str(uuid.uuid4())[:8]
    orchestrator = ScanOrchestrator(scan_id, repo_url, deployed_url)
    task = asyncio.create_task(orchestrator.run())
    _active_scans[scan_id] = task
    return scan_id
