"""
Embedder — Encodes exploit records into vector embeddings and manages FAISS index.

Uses sentence-transformers (all-MiniLM-L6-v2) for encoding.
FAISS for similarity search.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np

from .knowledge_base import ExploitKnowledgeBase

try:
    import faiss  # type: ignore
except Exception:  # pragma: no cover
    faiss = None

class ExploitEmbedder:
    """Embed exploit descriptions and build FAISS index for retrieval."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.index = None
        self._matrix: np.ndarray | None = None
        self._model = None
        self.exploit_texts: list[str] = []
        self.exploits: list[dict[str, Any]] = []

    def build_index(self, exploits: list[dict]) -> None:
        """Encode all exploits and build FAISS index."""
        self.exploits = exploits
        kb = ExploitKnowledgeBase()
        self.exploit_texts = [kb.to_text(e) for e in exploits]
        if not self.exploit_texts:
            self.index = None
            self._matrix = None
            return

        embeddings = self._encode_texts(self.exploit_texts)
        self._matrix = embeddings

        if faiss is not None:
            dim = embeddings.shape[1]
            idx = faiss.IndexFlatIP(dim)
            faiss.normalize_L2(embeddings)
            idx.add(embeddings)
            self.index = idx
        else:
            self.index = "numpy_cosine"

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        """Retrieve top-k most similar exploits for a given query."""
        if not self.exploits or self._matrix is None:
            return []

        top_k = max(1, min(top_k, len(self.exploits)))
        q = self._encode_texts([query])

        if faiss is not None and self.index is not None and hasattr(self.index, "search"):
            emb = self._matrix.copy()
            qn = q.copy()
            faiss.normalize_L2(emb)
            faiss.normalize_L2(qn)
            _, idxs = self.index.search(qn, top_k)
            return [self.exploits[i] for i in idxs[0] if 0 <= i < len(self.exploits)]

        # Numpy fallback
        mat = self._matrix
        qv = q[0]
        scores = self._cosine_scores(mat, qv)
        ranked = np.argsort(scores)[::-1][:top_k]
        return [self.exploits[int(i)] for i in ranked]

    def save_index(self, path: str) -> None:
        """Persist FAISS index to disk."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        if faiss is not None and self.index is not None and hasattr(self.index, "ntotal"):
            faiss.write_index(self.index, str(p))
        else:
            payload = {"model_name": self.model_name, "exploit_texts": self.exploit_texts}
            p.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def load_index(self, path: str) -> None:
        """Load FAISS index from disk."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(path)
        if faiss is not None and p.suffix in {".faiss", ".index"}:
            self.index = faiss.read_index(str(p))
        else:
            data = json.loads(p.read_text(encoding="utf-8"))
            self.model_name = data.get("model_name", self.model_name)
            self.exploit_texts = data.get("exploit_texts", [])
            self._matrix = self._encode_texts(self.exploit_texts) if self.exploit_texts else None
            self.index = "numpy_cosine"

    def _encode_texts(self, texts: list[str]) -> np.ndarray:
        # Lazy import: sentence_transformers can pull in TF / NumPy edge cases on import;
        # keep the module import-free until embeddings are actually needed.
        try:
            if self._model is None:
                from sentence_transformers import SentenceTransformer  # type: ignore

                self._model = SentenceTransformer(self.model_name)
            vectors = self._model.encode(texts, normalize_embeddings=False)
            return np.asarray(vectors, dtype=np.float32)
        except Exception:  # pragma: no cover
            return np.asarray([self._hash_embed(t) for t in texts], dtype=np.float32)

    def _hash_embed(self, text: str, dim: int = 256) -> np.ndarray:
        vec = np.zeros(dim, dtype=np.float32)
        for token in text.lower().split():
            idx = hash(token) % dim
            vec[idx] += 1.0
        norm = np.linalg.norm(vec) + 1e-8
        return vec / norm

    def _cosine_scores(self, matrix: np.ndarray, query: np.ndarray) -> np.ndarray:
        m_norm = np.linalg.norm(matrix, axis=1) + 1e-8
        q_norm = np.linalg.norm(query) + 1e-8
        return (matrix @ query) / (m_norm * q_norm)
