from __future__ import annotations

import asyncio
import uuid
from typing import Any

from .agents.sast import SASTAgent
from .agents.recon import ReconAgent
from .agents.correlate import CorrelateAgent
from .agents.exploit import ExploitAgent
from .agents.report import ReportAgent
from .agents.remediate import RemediateAgent
from .core.ai_insights import ai_insights
from .core.brain_store import brain_store
from .event_bus import event_bus

scan_results: dict[str, dict[str, Any]] = {}


class ScanOrchestrator:
    def __init__(self, scan_id: str, repo_url: str, deployed_url: str) -> None:
        self.scan_id = scan_id
        self.repo_url = repo_url
        self.deployed_url = deployed_url
        self.sast = SASTAgent(scan_id, repo_url)
        self.recon = ReconAgent(scan_id, deployed_url) if deployed_url else None
        self.correlate = CorrelateAgent(scan_id)
        self.exploit = ExploitAgent(scan_id, deployed_url) if deployed_url else None
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
        code_only = not self.deployed_url
        scan_mode = "Code-Only (SAST)" if code_only else "Full (SAST + DAST)"

        await event_bus.emit(self.scan_id, "scan:started", {
            "repo_url": self.repo_url,
            "deployed_url": self.deployed_url or "(code-only mode)",
            "scan_mode": scan_mode,
        })

        # Emit brain knowledge context
        knowledge = brain_store.get_knowledge_summary()
        await event_bus.emit(self.scan_id, "brain:context", {
            "prior_scans": knowledge["total_scans"],
            "known_patterns": knowledge["total_patterns"],
            "vuln_classes_seen": knowledge["vuln_classes_seen"],
        })

        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "orchestrator",
            "thought": f"Starting {scan_mode} pipeline. Brain has {knowledge['total_scans']} prior scans and {knowledge['total_patterns']} known vulnerability patterns.",
        })

        if code_only:
            # Code-only mode: SAST only, no recon/exploit
            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "orchestrator",
                "thought": "Code-only mode: Running deep SAST analysis with 16 detectors + AI deep analysis. No deployed URL = no DAST.",
            })
            sast_result = await self.sast.run()
            recon_result: list[Any] = []
            correlations: list[Any] = []

            # Generate vulns from SAST findings directly
            vulnerabilities: list[Any] = []
            exploits: list[Any] = []
            from .core.models import Vulnerability, Severity, VulnClass, VulnStatus
            severity_map = {
                "raw_sql": Severity.CRITICAL,
                "command_injection": Severity.CRITICAL,
                "ssti": Severity.CRITICAL,
                "nosql_injection": Severity.CRITICAL,
                "ssrf": Severity.HIGH,
                "path_traversal": Severity.HIGH,
                "jwt_vulnerability": Severity.HIGH,
                "prototype_pollution": Severity.HIGH,
                "race_condition": Severity.HIGH,
                "eval_user_input": Severity.HIGH,
                "unsafe_deserialization": Severity.HIGH,
                "missing_auth": Severity.MEDIUM,
                "mass_assignment": Severity.MEDIUM,
                "open_redirect": Severity.MEDIUM,
                "insecure_crypto": Severity.MEDIUM,
                "hardcoded_secrets": Severity.MEDIUM,
            }
            class_map = {
                "raw_sql": VulnClass.SQLI,
                "command_injection": VulnClass.COMMAND_INJECTION,
                "ssti": VulnClass.SSTI,
                "nosql_injection": VulnClass.NOSQL_INJECTION,
                "ssrf": VulnClass.SSRF,
                "path_traversal": VulnClass.PATH_TRAVERSAL,
                "jwt_vulnerability": VulnClass.JWT_VULN,
                "prototype_pollution": VulnClass.PROTOTYPE_POLLUTION,
                "race_condition": VulnClass.RACE_CONDITION,
                "eval_user_input": VulnClass.XSS,
                "unsafe_deserialization": VulnClass.DESERIALIZATION,
                "missing_auth": VulnClass.BROKEN_AUTH,
                "mass_assignment": VulnClass.MASS_ASSIGNMENT,
                "open_redirect": VulnClass.OPEN_REDIRECT,
                "insecure_crypto": VulnClass.INSECURE_CRYPTO,
                "hardcoded_secrets": VulnClass.INFO_DISCLOSURE,
            }
            for func in sast_result:
                for signal in func.risk_signals:
                    vuln_class = class_map.get(signal, VulnClass.INFO_DISCLOSURE)
                    sev = severity_map.get(signal, Severity.MEDIUM)
                    vuln = Vulnerability(
                        vuln_class=vuln_class,
                        severity=sev,
                        status=VulnStatus.SUSPECTED,
                        confidence=0.7,
                        function_id=func.id,
                        title=f"{signal.replace('_', ' ').title()} in {func.name}",
                        description=f"Detected {signal} pattern in {func.file_path}:{func.line}",
                    )
                    vulnerabilities.append(vuln)

            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "orchestrator",
                "thought": f"SAST complete: {len(sast_result)} functions, {len(vulnerabilities)} potential vulnerabilities found in code.",
            })
        else:
            # Full mode: SAST + Recon in parallel
            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "orchestrator",
                "thought": "Phase 1: Launching SAST and Recon agents in parallel for maximum coverage",
            })

            sast_result, recon_result = await asyncio.gather(
                self.sast.run(),
                self.recon.run(),
            )

            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "orchestrator",
                "thought": f"Phase 1 complete: {len(sast_result)} functions analyzed, {len(recon_result)} endpoints discovered. Moving to semantic correlation.",
            })

            # Phase 2: Correlation (heuristic + semantic)
            correlations = await self.correlate.run(sast_result, recon_result)

            # Phase 3: Exploitation
            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "orchestrator",
                "thought": f"Phase 3: Exploiting {len(correlations)} correlation links. Using ZeroEntropy to prioritize highest-impact payloads.",
            })

            vulnerabilities, exploits = await self.exploit.run(correlations, sast_result, recon_result)

        # Phase 3.5: AI Insights
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "orchestrator",
            "thought": "Running AI insights: attack chain detection, deduplication, risk scoring...",
        })

        attack_chains = []
        risk_score = {}
        dedup_groups = []

        try:
            attack_chains = await ai_insights.compute_attack_chains(vulnerabilities, correlations)
            if attack_chains:
                await event_bus.emit(self.scan_id, "ai:attack_chains", {
                    "chains": attack_chains[:5],
                    "total": len(attack_chains),
                })

            risk_score = await ai_insights.generate_risk_score(vulnerabilities, recon_result)
            await event_bus.emit(self.scan_id, "ai:risk_score", risk_score)

            dedup_groups = await ai_insights.deduplicate_vulns(vulnerabilities)
            unique_count = len(dedup_groups)
            duplicate_count = len(vulnerabilities) - unique_count
            if duplicate_count > 0:
                await event_bus.emit(self.scan_id, "ai:deduplication", {
                    "unique_vulns": unique_count,
                    "duplicates_merged": duplicate_count,
                })
        except Exception:
            pass

        # Phase 3.75: AI Remediation — generate code fixes
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "orchestrator",
            "thought": "Generating AI-powered code fixes for each vulnerability...",
        })

        func_map = {f.id: f for f in sast_result}
        remediate = RemediateAgent(self.scan_id)
        await remediate.run(vulnerabilities, func_map)

        # Phase 4: Report generation
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "orchestrator",
            "thought": "Phase 4: Generating comprehensive security report with AI-enhanced insights",
        })

        report_md = await self.report.run(
            sast_result, recon_result, correlations, (vulnerabilities, exploits),
            attack_chains=attack_chains,
            risk_score=risk_score,
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

        # Add attack chain edges
        for chain in attack_chains[:10]:
            chain_vulns = chain.get("vulnerabilities", [])
            for i in range(len(chain_vulns) - 1):
                graph_edges.append({
                    "source": chain_vulns[i],
                    "target": chain_vulns[i + 1],
                    "label": "chains_to",
                })

        result = {
            "vulnerabilities": vulnerabilities,
            "exploits": exploits,
            "report_markdown": report_md,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
            "attack_chains": attack_chains,
            "risk_score": risk_score,
            "status": "complete",
        }

        scan_results[self.scan_id] = result

        # Store in persistent brain for knowledge compounding
        await brain_store.store_scan_result(self.scan_id, result)

        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "orchestrator",
            "thought": f"Scan complete. Knowledge brain updated: now has {brain_store.total_scans} scans, {brain_store.total_patterns} patterns.",
        })

        await event_bus.emit(self.scan_id, "scan:complete", {
            "scan_id": self.scan_id,
            "risk_score": risk_score.get("score", 0),
            "risk_grade": risk_score.get("grade", "?"),
        })


_active_scans: dict[str, asyncio.Task[None]] = {}


async def start_scan(repo_url: str, deployed_url: str) -> str:
    scan_id = str(uuid.uuid4())[:8]
    orchestrator = ScanOrchestrator(scan_id, repo_url, deployed_url)
    task = asyncio.create_task(orchestrator.run())
    _active_scans[scan_id] = task
    return scan_id
