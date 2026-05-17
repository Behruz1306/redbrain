from __future__ import annotations

import os
import tempfile
from pathlib import Path

import git

from ..core.llm_client import llm
from ..core.models import CVEMatch, FunctionInfo
from ..core.zeroentropy_client import zeroentropy
from ..event_bus import event_bus
from ..parsers.javascript import JavaScriptParser
from ..parsers.python import PythonParser
from ..patterns.sast import (
    command_injection,
    eval_user_input,
    hardcoded_secrets,
    missing_auth,
    raw_sql,
    unsafe_deserialization,
)
from ..patterns.sast import ssrf
from ..patterns.sast import prototype_pollution
from ..patterns.sast import jwt_vulnerabilities
from ..patterns.sast import path_traversal
from ..patterns.sast import nosql_injection
from ..patterns.sast import ssti
from ..patterns.sast import race_condition
from ..patterns.sast import mass_assignment
from ..patterns.sast import insecure_crypto
from ..patterns.sast import open_redirect

DETECTORS = [
    ("raw_sql", raw_sql.detect),
    ("eval_user_input", eval_user_input.detect),
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

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "coverage",
    "__pycache__", ".venv", "vendor", ".next",
}

MAX_FILE_SIZE = 100_000


class SASTAgent:
    def __init__(self, scan_id: str, repo_url: str) -> None:
        self.scan_id = scan_id
        self.repo_url = repo_url
        self.js_parser = JavaScriptParser()
        self.py_parser = PythonParser()
        self.functions: list[FunctionInfo] = []

    async def run(self) -> list[FunctionInfo]:
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "sast",
            "thought": f"Cloning {self.repo_url} for deep static analysis. Running {len(DETECTORS)} detectors: SQLi, XSS, SSRF, prototype pollution, JWT attacks, path traversal, NoSQL injection, SSTI, race conditions, mass assignment, insecure crypto, open redirect, command injection, secrets, deserialization.",
        })

        clone_dir = tempfile.mkdtemp(prefix=f"redbrain-{self.scan_id}-")
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, lambda: git.Repo.clone_from(self.repo_url, clone_dir, depth=1)),
                timeout=60.0,
            )
        except asyncio.TimeoutError:
            await event_bus.emit(self.scan_id, "sast:error", {"error": "Git clone timed out after 60 seconds"})
            import shutil
            shutil.rmtree(clone_dir, ignore_errors=True)
            return []
        except Exception as e:
            await event_bus.emit(self.scan_id, "sast:error", {"error": f"Clone failed: {str(e)}"})
            import shutil
            shutil.rmtree(clone_dir, ignore_errors=True)
            return []

        try:
            all_files = self._collect_files(clone_dir)

            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "sast",
                "thought": f"Found {len(all_files)} source files (.js/.ts/.py). Parsing functions and running pattern detectors.",
            })

            for file_path in all_files:
                rel_path = os.path.relpath(file_path, clone_dir)
                await event_bus.emit(self.scan_id, "sast:file_started", {"path": rel_path})

                try:
                    source = Path(file_path).read_text(errors="ignore")
                except Exception:
                    continue

                if len(source) > MAX_FILE_SIZE:
                    continue

                ext = Path(file_path).suffix
                parser = self._get_parser(ext)
                if not parser:
                    continue

                parsed = parser.parse_file(rel_path, source)
                for func in parsed:
                    signals = self._detect_patterns(func.source_code)
                    func_info = FunctionInfo(
                        file_path=rel_path,
                        name=func.name,
                        line=func.line,
                        source_code=func.source_code,
                        parameters=func.parameters,
                        risk_signals=signals,
                    )
                    self.functions.append(func_info)

                    if signals:
                        await event_bus.emit(self.scan_id, "sast:function_analyzed", {
                            "function_id": func_info.id,
                            "name": func_info.name,
                            "file": rel_path,
                            "line": func.line,
                            "risk_signals": signals,
                        })
        finally:
            import shutil
            shutil.rmtree(clone_dir, ignore_errors=True)

        # Phase 2: CVE matching via ZeroEntropy for high-risk functions
        high_risk = [f for f in self.functions if f.risk_signals]
        if high_risk and zeroentropy.corpus_size > 0:
            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "sast",
                "thought": f"Phase 2: Matching {len(high_risk)} high-risk functions against {zeroentropy.corpus_size} CVE embeddings using semantic similarity (ZeroEntropy zembed-1).",
            })
            await self._match_cves(high_risk)

        # Phase 3: AI validation of top findings
        if llm.available and high_risk:
            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "sast",
                "thought": f"Phase 3: Using {llm.provider} to validate top {min(8, len(high_risk))} findings and assess real exploitability.",
            })
            await self._ai_validate(high_risk[:8])

        # Phase 4: AI deep analysis for complex vulns (business logic, race conditions, auth flaws)
        if llm.available and len(self.functions) > 0:
            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "sast",
                "thought": f"Phase 4: Deep AI analysis — scanning for complex vulnerabilities that regex cannot detect: business logic flaws, race conditions, insecure auth flows, privilege escalation paths...",
            })
            await self._ai_deep_analysis()

        await event_bus.emit(self.scan_id, "sast:complete", {
            "total_functions": len(self.functions),
            "high_risk_count": len([f for f in self.functions if f.risk_signals]),
            "ai_provider": llm.provider,
        })

        return self.functions

    def _collect_files(self, root: str) -> list[str]:
        files: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                ext = Path(fname).suffix
                if ext in (".js", ".ts", ".mjs", ".cjs", ".py"):
                    files.append(os.path.join(dirpath, fname))
        return files

    def _get_parser(self, ext: str):
        if ext in self.js_parser.supported_extensions():
            return self.js_parser
        if ext in self.py_parser.supported_extensions():
            return self.py_parser
        return None

    def _detect_patterns(self, source: str) -> list[str]:
        signals = []
        for name, detect_fn in DETECTORS:
            if detect_fn(source):
                signals.append(name)
        return signals

    async def _ai_validate(self, high_risk: list[FunctionInfo]) -> None:
        """Use LLM to validate whether detected patterns are real vulnerabilities."""
        for func in high_risk:
            try:
                prompt = (
                    f"Analyze this function for security vulnerabilities.\n"
                    f"Function: {func.name}\n"
                    f"File: {func.file_path}\n"
                    f"Detected signals: {func.risk_signals}\n"
                    f"Code:\n```\n{func.source_code[:600]}\n```\n\n"
                    f"In 1 sentence: Is this a real exploitable vulnerability or a false positive? "
                    f"Rate confidence 0-100."
                )
                response = await llm.ask("sast", prompt, max_tokens=100)
                if response and "offline" not in response:
                    await event_bus.emit(self.scan_id, "ai:sast_validation", {
                        "function": func.name,
                        "signals": func.risk_signals,
                        "ai_assessment": response.strip()[:200],
                    })
            except Exception:
                continue

    async def _ai_deep_analysis(self) -> None:
        """Use LLM to find complex vulnerabilities that regex detectors miss."""
        candidates = [f for f in self.functions if not f.risk_signals]
        interesting = [
            f for f in candidates
            if any(kw in f.source_code.lower() for kw in (
                "password", "auth", "token", "session", "cookie", "admin",
                "balance", "transfer", "payment", "price", "role", "permission",
                "redirect", "url", "file", "path", "upload", "download",
                "crypto", "hash", "encrypt", "sign", "verify", "secret",
                "query", "find", "delete", "update", "create",
            ))
        ]

        batch = interesting[:10]
        if not batch:
            return

        for func in batch:
            try:
                prompt = (
                    f"You are an elite security researcher. Analyze this function for complex vulnerabilities "
                    f"that automated scanners miss.\n\n"
                    f"Function: {func.name}\nFile: {func.file_path}\nLine: {func.line}\n"
                    f"Code:\n```\n{func.source_code[:800]}\n```\n\n"
                    f"Look specifically for:\n"
                    f"1. Race conditions (TOCTOU, check-then-act without locks)\n"
                    f"2. Business logic flaws (negative amounts, skipped steps, privilege escalation)\n"
                    f"3. Insecure authentication (weak comparison, timing attacks, token prediction)\n"
                    f"4. Authorization bypass (missing role checks, IDOR patterns)\n"
                    f"5. Cryptographic issues (weak algorithms, predictable IVs, static keys)\n"
                    f"6. Injection via complex data flows (second-order, serialization)\n\n"
                    f"Respond with JSON: {{\"vulnerable\": true/false, \"signals\": [\"signal_name\"], \"confidence\": 0-100, \"description\": \"...\"}}"
                )
                result = await llm.ask_json("sast", prompt)

                if result.get("vulnerable") and result.get("confidence", 0) >= 60:
                    signals = result.get("signals", ["ai_detected_complex_vuln"])
                    func.risk_signals.extend(signals)
                    await event_bus.emit(self.scan_id, "ai:deep_analysis", {
                        "function": func.name,
                        "file": func.file_path,
                        "signals": signals,
                        "confidence": result.get("confidence"),
                        "description": result.get("description", "")[:200],
                    })
            except Exception:
                continue

    async def _match_cves(self, high_risk: list[FunctionInfo]) -> None:
        """Embed high-risk functions and find similar CVEs."""
        for func in high_risk[:30]:
            try:
                query_text = f"{func.name} {' '.join(func.risk_signals)} {func.source_code[:500]}"
                query_embedding = await zeroentropy.embed(query_text, input_type="query")

                matches = await zeroentropy.similarity_search(
                    query_embedding, top_k=3
                )

                for cve_id, score in matches:
                    if score < 0.3:
                        continue
                    clean_id = cve_id.replace("cve:", "")
                    func.cve_matches.append(CVEMatch(cve_id=clean_id, similarity=score))

                    await event_bus.emit(self.scan_id, "sast:cve_match", {
                        "function_id": func.id,
                        "function_name": func.name,
                        "cve_id": clean_id,
                        "similarity_score": round(score, 3),
                    })
            except Exception:
                continue
