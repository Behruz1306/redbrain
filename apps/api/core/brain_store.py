"""Persistent knowledge brain for cross-scan intelligence.

Stores scan results, vulnerability patterns, and embeddings to disk
so each subsequent scan builds on prior knowledge.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from .zeroentropy_client import zeroentropy

logger = logging.getLogger(__name__)

BRAIN_DIR = Path("/tmp/redbrain-brain")


class BrainStore:
    def __init__(self) -> None:
        self._dir = BRAIN_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / "scans").mkdir(exist_ok=True)
        (self._dir / "patterns").mkdir(exist_ok=True)
        (self._dir / "knowledge").mkdir(exist_ok=True)
        self._pattern_cache: dict[str, list[dict[str, Any]]] = {}
        self._load_patterns()

    def _load_patterns(self) -> None:
        patterns_file = self._dir / "patterns" / "vuln_patterns.json"
        if patterns_file.exists():
            try:
                data = json.loads(patterns_file.read_text())
                self._pattern_cache = data
            except Exception:
                self._pattern_cache = {}

    def _save_patterns(self) -> None:
        patterns_file = self._dir / "patterns" / "vuln_patterns.json"
        patterns_file.write_text(json.dumps(self._pattern_cache, indent=2))

    async def store_scan_result(self, scan_id: str, result: dict[str, Any]) -> None:
        scan_file = self._dir / "scans" / f"{scan_id}.json"
        serializable = {
            "scan_id": scan_id,
            "timestamp": time.time(),
            "vulnerability_count": len(result.get("vulnerabilities", [])),
            "vulnerabilities": [
                {
                    "title": v.title,
                    "vuln_class": v.vuln_class.value,
                    "severity": v.severity.value,
                    "function_id": v.function_id,
                    "endpoint_id": v.endpoint_id,
                    "confidence": v.confidence,
                }
                for v in result.get("vulnerabilities", [])
            ],
            "graph_node_count": len(result.get("graph_nodes", [])),
            "graph_edge_count": len(result.get("graph_edges", [])),
        }
        scan_file.write_text(json.dumps(serializable, indent=2))
        await self._extract_patterns(serializable)

    async def _extract_patterns(self, scan_data: dict[str, Any]) -> None:
        for vuln in scan_data.get("vulnerabilities", []):
            vuln_class = vuln["vuln_class"]
            if vuln_class not in self._pattern_cache:
                self._pattern_cache[vuln_class] = []
            self._pattern_cache[vuln_class].append({
                "severity": vuln["severity"],
                "confidence": vuln["confidence"],
                "scan_id": scan_data["scan_id"],
                "timestamp": scan_data["timestamp"],
            })
        self._save_patterns()

    def get_historical_patterns(self, vuln_class: str) -> list[dict[str, Any]]:
        return self._pattern_cache.get(vuln_class, [])

    @property
    def total_scans(self) -> int:
        return len(list((self._dir / "scans").glob("*.json")))

    @property
    def total_patterns(self) -> int:
        return sum(len(v) for v in self._pattern_cache.values())

    def get_knowledge_summary(self) -> dict[str, Any]:
        return {
            "total_scans": self.total_scans,
            "total_patterns": self.total_patterns,
            "vuln_classes_seen": list(self._pattern_cache.keys()),
            "brain_size_kb": sum(
                f.stat().st_size for f in self._dir.rglob("*") if f.is_file()
            ) // 1024,
        }

    async def get_similar_past_vulns(
        self, description: str, top_k: int = 3
    ) -> list[dict[str, Any]]:
        """Find similar vulnerabilities from past scans using embeddings."""
        query_emb = await zeroentropy.embed(description, input_type="query")
        results = await zeroentropy.similarity_search(query_emb, top_k=top_k)
        past_vulns = []
        for doc_id, score in results:
            if doc_id.startswith("vuln:") and score > 0.25:
                past_vulns.append({"id": doc_id, "similarity": score})
        return past_vulns


brain_store = BrainStore()
