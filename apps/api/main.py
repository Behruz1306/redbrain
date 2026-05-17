from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse

from .core.brain_store import brain_store
from .core.models import ScanRequest, ScanResponse, Severity
from .event_bus import event_bus
from .orchestrator import start_scan, scan_results
from .seed.seed_brain import ensure_seeded

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    await ensure_seeded()
    yield


app = FastAPI(title="RedBrain API", version="2.0.0", lifespan=lifespan)

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
        risk = result.get("risk_score", {})
        return {
            "scan_id": scan_id,
            "status": "complete" if is_done else "running",
            "progress": 1.0 if is_done else 0.5,
            "current_stage": "done" if is_done else "scanning",
            "vulnerability_count": vuln_count,
            "risk_score": risk.get("score", 0),
            "risk_grade": risk.get("grade", "?"),
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
        }, "risk_score": {}, "attack_chains": []}

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
        "risk_score": result.get("risk_score", {}),
        "attack_chains": result.get("attack_chains", []),
    }


@app.get("/api/scan/{scan_id}/remediate")
async def get_remediations(scan_id: str) -> dict[str, Any]:
    result = scan_results.get(scan_id)
    if not result:
        return {"remediations": []}

    vulns = result.get("vulnerabilities", [])
    remediations = []
    for v in vulns:
        if v.remediation and v.remediation.fixed_code:
            remediations.append({
                "vuln_id": v.id,
                "title": v.title,
                "severity": v.severity.value,
                "vuln_class": v.vuln_class.value,
                "file_path": v.remediation.file_path,
                "line": v.remediation.line,
                "fixed_code": v.remediation.fixed_code,
                "explanation": v.remediation.explanation,
            })
    return {"remediations": remediations}


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


@app.get("/api/brain/knowledge")
async def brain_knowledge() -> dict[str, Any]:
    """Get brain knowledge summary — how smart is RedBrain right now."""
    from .core.zeroentropy_client import zeroentropy
    from .core.gbrain_client import gbrain

    summary = brain_store.get_knowledge_summary()
    return {
        **summary,
        "embedding_corpus_size": zeroentropy.corpus_size,
        "gbrain_pages": gbrain.page_count,
        "gbrain_links": gbrain.link_count,
        "active_scans": len(scan_results),
    }


@app.get("/api/brain/kb")
async def brain_kb() -> dict[str, Any]:
    """Full knowledge base: CVEs, techniques, detectors."""
    import json as _json
    from pathlib import Path

    seed_dir = Path(__file__).parent / "seed"
    cves = _json.loads((seed_dir / "cves.json").read_text())
    adv_path = seed_dir / "advanced_cves.json"
    if adv_path.exists():
        cves.extend(_json.loads(adv_path.read_text()))
    techniques = _json.loads((seed_dir / "techniques.json").read_text())

    detectors = [
        {"name": "SQL Injection", "id": "raw_sql", "category": "injection"},
        {"name": "XSS / Eval", "id": "eval_user_input", "category": "injection"},
        {"name": "Command Injection", "id": "command_injection", "category": "injection"},
        {"name": "NoSQL Injection", "id": "nosql_injection", "category": "injection"},
        {"name": "SSTI", "id": "ssti", "category": "injection"},
        {"name": "SSRF", "id": "ssrf", "category": "network"},
        {"name": "Path Traversal", "id": "path_traversal", "category": "file"},
        {"name": "Open Redirect", "id": "open_redirect", "category": "network"},
        {"name": "Prototype Pollution", "id": "prototype_pollution", "category": "logic"},
        {"name": "JWT Vulnerabilities", "id": "jwt_vulnerability", "category": "auth"},
        {"name": "Race Condition", "id": "race_condition", "category": "logic"},
        {"name": "Mass Assignment", "id": "mass_assignment", "category": "logic"},
        {"name": "Insecure Crypto", "id": "insecure_crypto", "category": "crypto"},
        {"name": "Hardcoded Secrets", "id": "hardcoded_secrets", "category": "crypto"},
        {"name": "Missing Auth", "id": "missing_auth", "category": "auth"},
        {"name": "Unsafe Deserialization", "id": "unsafe_deserialization", "category": "injection"},
    ]

    vuln_classes = list({c["class"] for c in cves})
    technique_classes = list({t["class"] for t in techniques})

    return {
        "cves": cves,
        "techniques": techniques,
        "detectors": detectors,
        "stats": {
            "total_cves": len(cves),
            "total_techniques": len(techniques),
            "total_detectors": len(detectors),
            "vuln_classes": sorted(set(vuln_classes + technique_classes)),
            "total_payloads": sum(len(t["payloads"]) for t in techniques),
        },
    }


@app.get("/api/brain/agents")
async def brain_agents() -> dict[str, Any]:
    """Get GStack agent role definitions."""
    from pathlib import Path

    roles_dir = Path(__file__).parent.parent.parent / ".claude" / "commands"
    agents = []

    if roles_dir.exists():
        for md_file in sorted(roles_dir.glob("*.md")):
            content = md_file.read_text()
            name = md_file.stem.replace("redbrain-", "")
            lines = content.strip().split("\n")
            description = ""
            for line in lines:
                if line.strip() and not line.startswith("#") and not line.startswith("---"):
                    description = line.strip()
                    break
            agents.append({
                "name": name,
                "file": md_file.name,
                "description": description,
                "role_content": content[:500],
            })

    return {"agents": agents, "framework": "GStack"}


@app.post("/api/v1/check")
async def realtime_check(req: dict[str, Any]) -> dict[str, Any]:
    """Real-time code analysis API for IDE integrations (MCP/API Key).

    Body: {"code": "...", "language": "javascript|python", "file_path": "optional"}
    Returns: {"vulnerabilities": [...], "risk_level": "...", "suggestions": [...]}
    """
    code = req.get("code", "")
    language = req.get("language", "javascript")
    file_path = req.get("file_path", "inline")

    if not code:
        return {"vulnerabilities": [], "risk_level": "safe", "suggestions": []}

    from .patterns.sast import (
        raw_sql, eval_user_input, hardcoded_secrets, missing_auth,
        unsafe_deserialization, command_injection,
    )
    from .patterns.sast import (
        ssrf, prototype_pollution, jwt_vulnerabilities, path_traversal,
        nosql_injection, ssti, race_condition, mass_assignment,
        insecure_crypto, open_redirect,
    )

    detectors = [
        ("sql_injection", raw_sql.detect),
        ("xss", eval_user_input.detect),
        ("hardcoded_secrets", hardcoded_secrets.detect),
        ("missing_auth", missing_auth.detect),
        ("unsafe_deserialization", unsafe_deserialization.detect),
        ("command_injection", command_injection.detect),
        ("ssrf", ssrf.detect),
        ("prototype_pollution", prototype_pollution.detect),
        ("jwt_vulnerability", jwt_vulnerabilities.detect),
        ("path_traversal", path_traversal.detect),
        ("nosql_injection", nosql_injection.detect),
        ("ssti", ssti.detect),
        ("race_condition", race_condition.detect),
        ("mass_assignment", mass_assignment.detect),
        ("insecure_crypto", insecure_crypto.detect),
        ("open_redirect", open_redirect.detect),
    ]

    findings = []
    for name, detect_fn in detectors:
        if detect_fn(code):
            findings.append({
                "type": name,
                "severity": "critical" if name in ("sql_injection", "command_injection", "ssti", "nosql_injection") else
                           "high" if name in ("ssrf", "path_traversal", "jwt_vulnerability", "prototype_pollution", "xss") else "medium",
                "message": f"Potential {name.replace('_', ' ')} detected",
                "file": file_path,
            })

    risk_level = "safe"
    if any(f["severity"] == "critical" for f in findings):
        risk_level = "critical"
    elif any(f["severity"] == "high" for f in findings):
        risk_level = "high"
    elif findings:
        risk_level = "medium"

    suggestions = []
    if findings:
        from .core.llm_client import llm
        if llm.available:
            try:
                prompt = (
                    f"Given these security findings in {language} code:\n"
                    f"Findings: {[f['type'] for f in findings]}\n"
                    f"Code:\n```\n{code[:500]}\n```\n"
                    f"Give 1-2 sentence fix suggestion for EACH finding. JSON array format: "
                    f'[{{"type": "...", "fix": "..."}}]'
                )
                result = await llm.ask_json("remediate", prompt)
                if isinstance(result, list):
                    suggestions = result
                elif isinstance(result, dict) and not result.get("parse_error"):
                    suggestions = result.get("suggestions", [])
            except Exception:
                pass

    return {
        "vulnerabilities": findings,
        "risk_level": risk_level,
        "count": len(findings),
        "suggestions": suggestions,
        "api_version": "v1",
    }


@app.get("/api/v1/mcp/manifest")
async def mcp_manifest() -> dict[str, Any]:
    """MCP server manifest for IDE integrations."""
    return {
        "name": "redbrain",
        "version": "1.0.0",
        "description": "RedBrain AI Security Scanner — real-time vulnerability detection for your code",
        "tools": [
            {
                "name": "check_code",
                "description": "Analyze code for security vulnerabilities in real-time. Returns findings with severity and fix suggestions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "The source code to analyze"},
                        "language": {"type": "string", "enum": ["javascript", "typescript", "python"], "description": "Programming language"},
                        "file_path": {"type": "string", "description": "Optional file path for context"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "scan_repo",
                "description": "Start a full security scan of a GitHub repository. Returns scan_id for tracking.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_url": {"type": "string", "description": "GitHub repository URL"},
                        "deployed_url": {"type": "string", "description": "Optional deployed URL for DAST"},
                    },
                    "required": ["repo_url"],
                },
            },
            {
                "name": "get_kb",
                "description": "Get knowledge base information: CVEs, techniques, and detection capabilities.",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ],
        "authentication": {"type": "bearer", "description": "Use your RedBrain API key"},
    }


@app.get("/api/health")
async def health() -> dict[str, Any]:
    from .core.llm_client import llm
    from .core.thehog_client import thehog
    return {
        "status": "ok",
        "version": "2.0.0",
        "engine": "redbrain-ai",
        "ai_provider": llm.provider,
        "ai_available": llm.available,
        "thehog_available": thehog.available,
        "integrations": ["ZeroEntropy", "GBrain", "GStack"]
            + (["Gemini"] if "gemini" in llm.provider else [])
            + (["Groq"] if "groq" in llm.provider else [])
            + (["The Hog"] if thehog.available else [])
            + ["Jo/Camofox"],
    }
