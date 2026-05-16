from __future__ import annotations

import re

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
        correlations: list[Correlation] = []
        high_risk = [f for f in functions if f.risk_signals]

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
                await event_bus.emit(self.scan_id, "correlate:link_created", {
                    "function_id": func.id,
                    "function_name": func.name,
                    "endpoint": f"{best_match.method} {best_match.path}",
                    "confidence": best_confidence,
                    "reasoning": best_reasoning,
                })

        await event_bus.emit(self.scan_id, "correlate:complete", {
            "links_count": len(correlations),
        })
        return correlations

    def _score_match(self, func: FunctionInfo, endpoint: EndpointInfo) -> tuple[float, str]:
        score = 0.0
        reasons: list[str] = []

        # Direct path reference in code
        if endpoint.path in func.source_code:
            score += 0.5
            reasons.append(f"direct path reference '{endpoint.path}' in source")

        # Name-to-path heuristic
        func_name_lower = func.name.lower().replace("_", "").replace("-", "")
        path_parts = endpoint.path.lower().strip("/").split("/")
        for part in path_parts:
            clean_part = part.replace("-", "").replace("_", "")
            if clean_part and clean_part in func_name_lower:
                score += 0.3
                reasons.append(f"name match: '{func.name}' ~ '{endpoint.path}'")
                break

        # Parameter overlap
        if func.parameters and endpoint.parameters:
            overlap = set(func.parameters) & set(endpoint.parameters)
            if overlap:
                score += 0.2 * len(overlap)
                reasons.append(f"parameter overlap: {overlap}")

        # Route definition pattern in source
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

        # File path heuristic: route/controller files likely implement endpoints
        if any(kw in func.file_path.lower() for kw in ("route", "controller", "api", "endpoint")):
            score += 0.1
            reasons.append("file is route/controller")

        return min(score, 1.0), "; ".join(reasons) if reasons else "no match signals"
