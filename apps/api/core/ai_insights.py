"""AI Insights Engine — semantic intelligence powered by ZeroEntropy.

Provides AI-native capabilities without requiring Claude API:
- Semantic vulnerability chaining (finds attack paths)
- Smart deduplication (groups similar findings)
- Risk scoring with contextual understanding
- Attack surface mapping via embeddings
"""
from __future__ import annotations

from typing import Any

from .models import Correlation, EndpointInfo, FunctionInfo, Vulnerability
from .zeroentropy_client import zeroentropy


class AIInsights:
    async def semantic_correlate(
        self,
        functions: list[FunctionInfo],
        endpoints: list[EndpointInfo],
    ) -> list[tuple[str, str, float, str]]:
        """Use embeddings to find semantic links between code and endpoints."""
        if not functions or not endpoints:
            return []

        high_risk = [f for f in functions if f.risk_signals][:20]
        if not high_risk:
            return []

        func_texts = [
            f"{f.name} {' '.join(f.risk_signals)} {f.source_code[:200]}"
            for f in high_risk
        ]
        endpoint_texts = [
            f"{e.method} {e.path} {' '.join(e.parameters)}"
            for e in endpoints
        ]

        func_embeddings = await zeroentropy.embed_batch(func_texts, input_type="query")
        endpoint_embeddings = await zeroentropy.embed_batch(endpoint_texts, input_type="document")

        links: list[tuple[str, str, float, str]] = []
        import numpy as np

        for i, func in enumerate(high_risk):
            func_vec = np.array(func_embeddings[i])
            best_score = 0.0
            best_idx = -1

            for j, ep in enumerate(endpoints):
                ep_vec = np.array(endpoint_embeddings[j])
                sim = float(np.dot(func_vec, ep_vec) / (
                    np.linalg.norm(func_vec) * np.linalg.norm(ep_vec) + 1e-8
                ))
                if sim > best_score:
                    best_score = sim
                    best_idx = j

            if best_idx >= 0 and best_score > 0.2:
                ep = endpoints[best_idx]
                reasoning = f"semantic similarity {best_score:.0%} between '{func.name}' and '{ep.method} {ep.path}'"
                links.append((func.id, ep.id, best_score, reasoning))

        return links

    async def deduplicate_vulns(
        self, vulnerabilities: list[Vulnerability]
    ) -> list[list[int]]:
        """Group similar vulnerabilities using embedding similarity."""
        if len(vulnerabilities) <= 1:
            return [[i] for i in range(len(vulnerabilities))]

        texts = [f"{v.title} {v.description} {v.vuln_class.value}" for v in vulnerabilities]
        embeddings = await zeroentropy.embed_batch(texts, input_type="document")

        import numpy as np
        groups: list[list[int]] = []
        assigned = set()

        for i in range(len(vulnerabilities)):
            if i in assigned:
                continue
            group = [i]
            assigned.add(i)
            vec_i = np.array(embeddings[i])

            for j in range(i + 1, len(vulnerabilities)):
                if j in assigned:
                    continue
                vec_j = np.array(embeddings[j])
                sim = float(np.dot(vec_i, vec_j) / (
                    np.linalg.norm(vec_i) * np.linalg.norm(vec_j) + 1e-8
                ))
                if sim > 0.7:
                    group.append(j)
                    assigned.add(j)

            groups.append(group)

        return groups

    async def compute_attack_chains(
        self,
        vulnerabilities: list[Vulnerability],
        correlations: list[Correlation],
    ) -> list[dict[str, Any]]:
        """Find multi-step attack chains using semantic relationships."""
        if len(vulnerabilities) < 2:
            return []

        chains: list[dict[str, Any]] = []

        vuln_by_endpoint: dict[str, list[Vulnerability]] = {}
        for v in vulnerabilities:
            if v.endpoint_id:
                vuln_by_endpoint.setdefault(v.endpoint_id, []).append(v)

        for endpoint_id, vulns in vuln_by_endpoint.items():
            if len(vulns) >= 2:
                chain_severity = max(
                    v.severity.value for v in vulns
                )
                chains.append({
                    "endpoint_id": endpoint_id,
                    "vulnerabilities": [v.id for v in vulns],
                    "chain_length": len(vulns),
                    "max_severity": chain_severity,
                    "description": f"Attack chain: {' → '.join(v.vuln_class.value for v in vulns)}",
                })

        texts = [f"{v.title} {v.vuln_class.value}" for v in vulnerabilities]
        embeddings = await zeroentropy.embed_batch(texts, input_type="document")

        import numpy as np
        for i in range(len(vulnerabilities)):
            for j in range(i + 1, len(vulnerabilities)):
                if vulnerabilities[i].endpoint_id == vulnerabilities[j].endpoint_id:
                    continue
                vec_i = np.array(embeddings[i])
                vec_j = np.array(embeddings[j])
                sim = float(np.dot(vec_i, vec_j) / (
                    np.linalg.norm(vec_i) * np.linalg.norm(vec_j) + 1e-8
                ))
                if sim > 0.5:
                    chains.append({
                        "vulnerabilities": [vulnerabilities[i].id, vulnerabilities[j].id],
                        "chain_length": 2,
                        "similarity": sim,
                        "description": (
                            f"Related vulns: {vulnerabilities[i].vuln_class.value} "
                            f"↔ {vulnerabilities[j].vuln_class.value} ({sim:.0%} similar)"
                        ),
                    })

        return chains

    async def generate_risk_score(
        self,
        vulnerabilities: list[Vulnerability],
        endpoints: list[EndpointInfo],
    ) -> dict[str, Any]:
        """Generate overall risk assessment."""
        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        raw_score = sum(
            severity_weights.get(v.severity.value, 0) * v.confidence
            for v in vulnerabilities
        )

        max_possible = len(vulnerabilities) * 10
        normalized = min(raw_score / max(max_possible, 1), 1.0)

        auth_endpoints = sum(1 for e in endpoints if e.auth_required is False)
        exposure_factor = 1.0 + (auth_endpoints / max(len(endpoints), 1)) * 0.5

        final_score = min(normalized * exposure_factor, 1.0)

        return {
            "score": round(final_score * 100),
            "grade": self._score_to_grade(final_score),
            "raw_score": raw_score,
            "vulnerability_impact": len(vulnerabilities),
            "exposure_factor": round(exposure_factor, 2),
            "recommendation": self._get_recommendation(final_score, vulnerabilities),
        }

    def _score_to_grade(self, score: float) -> str:
        if score >= 0.8:
            return "F"
        if score >= 0.6:
            return "D"
        if score >= 0.4:
            return "C"
        if score >= 0.2:
            return "B"
        return "A"

    def _get_recommendation(self, score: float, vulns: list[Vulnerability]) -> str:
        if score >= 0.8:
            return "Critical: immediate remediation required. Multiple high-severity attack vectors identified."
        if score >= 0.6:
            return "High risk: prioritize fixing authentication and injection vulnerabilities."
        if score >= 0.4:
            return "Moderate risk: address high-severity findings before next release."
        if score >= 0.2:
            return "Low risk: minor issues found. Schedule fixes in next sprint."
        return "Minimal risk: good security posture. Continue regular scanning."


ai_insights = AIInsights()
