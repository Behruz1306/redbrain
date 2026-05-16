from __future__ import annotations

import os
from typing import Any

import httpx
import numpy as np


class ZeroEntropyClient:
    """Client for ZeroEntropy embedding and reranking API.

    Falls back to simple cosine similarity with cached numpy vectors
    when ZEROENTROPY_API_KEY is not set.
    """

    def __init__(self) -> None:
        self.api_key = os.getenv("ZEROENTROPY_API_KEY", "")
        self.base_url = os.getenv("ZEROENTROPY_BASE_URL", "https://api.zeroentropy.dev")
        self._use_local = not self.api_key
        self._local_embeddings: dict[str, list[float]] = {}
        self._embedding_dim = 384

    async def embed(
        self, text: str, input_type: str = "document"
    ) -> list[float]:
        """Get embedding for text using zembed-1."""
        if self._use_local:
            return self._local_embed(text)

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/v1/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": "zembed-1",
                    "input": text,
                    "input_type": input_type,
                },
            )
            resp.raise_for_status()
            return resp.json()["data"][0]["embedding"]

    async def embed_batch(
        self, texts: list[str], input_type: str = "document"
    ) -> list[list[float]]:
        """Batch embed multiple texts."""
        if self._use_local:
            return [self._local_embed(t) for t in texts]

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/v1/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": "zembed-1",
                    "input": texts,
                    "input_type": input_type,
                },
            )
            resp.raise_for_status()
            return [d["embedding"] for d in resp.json()["data"]]

    async def rerank(
        self, query: str, documents: list[str], top_n: int = 3
    ) -> list[dict[str, Any]]:
        """Rerank documents by relevance to query using zerank-2."""
        if self._use_local:
            return self._local_rerank(query, documents, top_n)

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}/v1/rerank",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": "zerank-2",
                    "query": query,
                    "documents": documents,
                    "top_n": top_n,
                },
            )
            resp.raise_for_status()
            return resp.json()["results"]

    async def similarity_search(
        self, query_embedding: list[float], corpus_ids: list[str], top_k: int = 5
    ) -> list[tuple[str, float]]:
        """Find most similar items in corpus by embedding."""
        if not self._local_embeddings:
            return []

        query_vec = np.array(query_embedding)
        results: list[tuple[str, float]] = []

        for doc_id in corpus_ids:
            if doc_id not in self._local_embeddings:
                continue
            doc_vec = np.array(self._local_embeddings[doc_id])
            sim = float(np.dot(query_vec, doc_vec) / (
                np.linalg.norm(query_vec) * np.linalg.norm(doc_vec) + 1e-8
            ))
            results.append((doc_id, sim))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def store_embedding(self, doc_id: str, embedding: list[float]) -> None:
        """Cache an embedding locally for similarity search."""
        self._local_embeddings[doc_id] = embedding

    def _local_embed(self, text: str) -> list[float]:
        """Simple deterministic hash-based embedding for offline mode."""
        vec = np.zeros(self._embedding_dim)
        words = text.lower().split()
        for i, word in enumerate(words[:100]):
            h = hash(word) % self._embedding_dim
            vec[h] += 1.0 / (i + 1)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()

    def _local_rerank(
        self, query: str, documents: list[str], top_n: int
    ) -> list[dict[str, Any]]:
        """Simple keyword overlap reranking for offline mode."""
        query_words = set(query.lower().split())
        scored = []
        for i, doc in enumerate(documents):
            doc_words = set(doc.lower().split())
            overlap = len(query_words & doc_words)
            score = overlap / (len(query_words) + 1)
            scored.append({"index": i, "relevance_score": score, "document": doc})

        scored.sort(key=lambda x: x["relevance_score"], reverse=True)
        return scored[:top_n]


zeroentropy = ZeroEntropyClient()
