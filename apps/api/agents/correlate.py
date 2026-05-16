from __future__ import annotations

import re

from ..core.ai_insights import ai_insights
from ..core.llm_client import llm
from ..core.models import Correlation, EndpointInfo, FunctionInfo
from ..event_bus import event_bus


class CorrelateAgent:
    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id

    async def run(
        self,
        functions: list[FunctionInfo],
        endpoints: list[EndpointInfo],
    ) -> list[Correlation]:
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "correlate",
            "thought": f"Analyzing {len(functions)} functions against {len(endpoints)} endpoints using hybrid heuristic + semantic correlation",
        })

        correlations: list[Correlation] = []
        high_risk = [f for f in functions if f.risk_signals]

        # Phase 1: Heuristic correlation
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "correlate",
            "thought": f"Phase 1: Heuristic matching for {len(high_risk)} high-risk functions",
        })

        heuristic_pairs: set[tuple[str, str]] = set()
        for func in high_risk:
            best_match: EndpointInfo | None = None
            best_confidence = 0.0
            best_reasoning = ""

            for endpoint in endpoints:
                confidence, reasoning = self._score_match(func, endpoint)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = endpoint
                    best_reasoning = reasoning

            if best_match and best_confidence >= 0.3:
                corr = Correlation(
                    function_id=func.id,
                    endpoint_id=best_match.id,
                    confidence=best_confidence,
                    reasoning=best_reasoning,
                )
                correlations.append(corr)
                heuristic_pairs.add((func.id, best_match.id))
                await event_bus.emit(self.scan_id, "correlate:link_created", {
                    "function_id": func.id,
                    "function_name": func.name,
                    "endpoint": f"{best_match.method} {best_match.path}",
                    "confidence": best_confidence,
                    "reasoning": best_reasoning,
                    "method": "heuristic",
                })

        # Phase 2: Semantic correlation via ZeroEntropy
        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "correlate",
            "thought": "Phase 2: Semantic correlation using ZeroEntropy embeddings to find non-obvious links",
        })

        try:
            semantic_links = await ai_insights.semantic_correlate(functions, endpoints)
            for func_id, ep_id, score, reasoning in semantic_links:
                if (func_id, ep_id) in heuristic_pairs:
                    continue
                if score >= 0.3:
                    corr = Correlation(
                        function_id=func_id,
                        endpoint_id=ep_id,
                        confidence=score * 0.8,
                        reasoning=f"[AI] {reasoning}",
                    )
                    correlations.append(corr)

                    func_name = next((f.name for f in functions if f.id == func_id), "?")
                    ep = next((e for e in endpoints if e.id == ep_id), None)
                    ep_label = f"{ep.method} {ep.path}" if ep else "?"

                    await event_bus.emit(self.scan_id, "correlate:link_created", {
                        "function_id": func_id,
                        "function_name": func_name,
                        "endpoint": ep_label,
                        "confidence": score * 0.8,
                        "reasoning": f"[AI] {reasoning}",
                        "method": "semantic",
                    })
        except Exception:
            pass

        # Phase 3: AI-enhanced reasoning (if LLM available)
        if llm.available and correlations:
            await event_bus.emit(self.scan_id, "agent:reasoning", {
                "agent": "correlate",
                "thought": f"Phase 3: Using {llm.provider} to validate and explain top correlations",
            })
            await self._ai_validate_correlations(correlations[:5], functions, endpoints)

        await event_bus.emit(self.scan_id, "agent:reasoning", {
            "agent": "correlate",
            "thought": f"Correlation complete: {len(correlations)} total links (heuristic + semantic + AI)",
        })

        await event_bus.emit(self.scan_id, "correlate:complete", {
            "links_count": len(correlations),
            "heuristic_count": len(heuristic_pairs),
            "semantic_count": len(correlations) - len(heuristic_pairs),
            "ai_provider": llm.provider,
        })
        return correlations

    async def _ai_validate_correlations(
        self,
        correlations: list[Correlation],
        functions: list[FunctionInfo],
        endpoints: list[EndpointInfo],
    ) -> None:
        func_map = {f.id: f for f in functions}
        ep_map = {e.id: e for e in endpoints}

        for corr in correlations:
            func = func_map.get(corr.function_id)
            ep = ep_map.get(corr.endpoint_id)
            if not func or not ep:
                continue

            prompt = (
                f"Vulnerable function '{func.name}' in {func.file_path} has risk signals: {func.risk_signals}.\n"
                f"It is correlated to endpoint {ep.method} {ep.path}.\n"
                f"Code snippet:\n{func.source_code[:300]}\n\n"
                f"In 1-2 sentences, explain the security risk of this correlation. "
                f"How could an attacker exploit this function through this endpoint?"
            )

            try:
                explanation = await llm.ask("correlate", prompt, max_tokens=150)
                if explanation and "offline" not in explanation:
                    corr.reasoning = f"[AI] {explanation.strip()}"
                    await event_bus.emit(self.scan_id, "ai:correlation_insight", {
                        "function": func.name,
                        "endpoint": f"{ep.method} {ep.path}",
                        "insight": explanation.strip()[:200],
                    })
            except Exception:
                continue

    def _score_match(self, func: FunctionInfo, endpoint: EndpointInfo) -> tuple[float, str]:
        score = 0.0
        reasons: list[str] = []

        if endpoint.path in func.source_code:
            score += 0.5
            reasons.append(f"direct path reference '{endpoint.path}' in source")

        func_name_lower = func.name.lower().replace("_", "").replace("-", "")
        path_parts = endpoint.path.lower().strip("/").split("/")
        for part in path_parts:
            clean_part = part.replace("-", "").replace("_", "")
            if clean_part and clean_part in func_name_lower:
                score += 0.3
                reasons.append(f"name match: '{func.name}' ~ '{endpoint.path}'")
                break

        if func.parameters and endpoint.parameters:
            overlap = set(func.parameters) & set(endpoint.parameters)
            if overlap:
                score += 0.2 * len(overlap)
                reasons.append(f"parameter overlap: {overlap}")

        method_patterns = [
            rf"\.{endpoint.method.lower()}\s*\(\s*['\"].*{re.escape(endpoint.path)}",
            rf"@app\.{endpoint.method.lower()}\s*\(\s*['\"].*{re.escape(endpoint.path)}",
            rf"router\.{endpoint.method.lower()}\s*\(\s*['\"].*{re.escape(endpoint.path)}",
        ]
        for pat in method_patterns:
            if re.search(pat, func.source_code, re.IGNORECASE):
                score += 0.6
                reasons.append(f"route definition for {endpoint.method} {endpoint.path}")
                break

        if any(kw in func.file_path.lower() for kw in ("route", "controller", "api", "endpoint")):
            score += 0.1
            reasons.append("file is route/controller")

        return min(score, 1.0), "; ".join(reasons) if reasons else "no match signals"
