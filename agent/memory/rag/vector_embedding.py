"""Vector embedding generator — sentence-transformers wrapper (768-dim).

Provides lazy-loaded embedding generation with graceful degradation
when ``sentence-transformers`` is not installed.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class EmbeddingGenerator:
    """Sentence-transformers embedding wrapper (all-mpnet-base-v2, 768-dim).

    The model is loaded lazily on the first :meth:`embed` call to avoid
    heavy startup cost.  If ``sentence-transformers`` is not installed the
    generator degrades gracefully — :attr:`is_available` returns ``False``
    and all embedding methods return ``None``.
    """

    MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"
    EMBEDDING_DIM = 768

    def __init__(self) -> None:
        self._model: Any = None
        self._lock = threading.Lock()
        self._load_attempted = False
        self._available = False

    def _load_model(self) -> bool:
        """Load the sentence-transformers model (thread-safe, once)."""
        if self._load_attempted:
            return self._available
        with self._lock:
            if self._load_attempted:
                return self._available
            self._load_attempted = True
            try:
                from sentence_transformers import SentenceTransformer

                self._model = SentenceTransformer(self.MODEL_NAME)
                self._available = True
                logger.info("Loaded embedding model: %s", self.MODEL_NAME)
            except Exception:
                self._available = False
                logger.info(
                    "sentence-transformers unavailable — embedding disabled",
                    exc_info=True,
                )
        return self._available

    @property
    def is_available(self) -> bool:
        """Whether the embedding model is loaded and usable."""
        if not self._load_attempted:
            self._load_model()
        return self._available

    def embed(self, text: str) -> list[float] | None:
        """Embed a single text string into a 768-dim vector.

        Returns:
            List of floats, or ``None`` if the model is unavailable.
        """
        if not self.is_available:
            return None
        try:
            import numpy as np

            vec = self._model.encode(text, show_progress_bar=False)
            return np.asarray(vec, dtype=float).tolist()
        except Exception:
            logger.warning("Embedding failed for text (len=%d)", len(text), exc_info=True)
            return None

    def embed_batch(
        self, texts: list[str], batch_size: int = 32
    ) -> list[list[float]] | None:
        """Embed multiple texts in batch.

        Returns:
            List of embedding vectors, or ``None`` if unavailable.
        """
        if not self.is_available or not texts:
            return None
        try:
            import numpy as np

            vecs = self._model.encode(texts, batch_size=batch_size, show_progress_bar=False)
            return [np.asarray(v, dtype=float).tolist() for v in vecs]
        except Exception:
            logger.warning("Batch embedding failed (n=%d)", len(texts), exc_info=True)
            return None

    @staticmethod
    def create_embedding_text(
        scenario: str,
        target: str = "",
        tools: list[str] | None = None,
        cves: list[str] | None = None,
        result: str = "",
        tags: list[str] | None = None,
        steps: list[str] | None = None,
    ) -> str:
        """Build a canonical text representation for embedding.

        Combines scenario, target, tools, CVEs, result, tags, and steps
        into a single string that maximises embedding quality.
        """
        parts = [scenario]
        if target:
            parts.append(f"target: {target}")
        if steps:
            parts.append(f"steps: {'; '.join(steps[:5])}")
        if tools:
            parts.append(f"tools: {', '.join(tools)}")
        if cves:
            parts.append(f"cve: {', '.join(cves)}")
        if result:
            parts.append(f"result: {result}")
        if tags:
            parts.append(f"tags: {', '.join(tags)}")
        return " | ".join(parts)

    @staticmethod
    def similarity(vec1: list[float], vec2: list[float]) -> float:
        """Compute cosine similarity between two vectors.

        Returns:
            Similarity in [0.0, 1.0].  Returns 0.0 on error.
        """
        try:
            import numpy as np

            a = np.asarray(vec1, dtype=float)
            b = np.asarray(vec2, dtype=float)
            denom = float(np.linalg.norm(a) * np.linalg.norm(b))
            if denom == 0.0:
                return 0.0
            return max(0.0, float(np.dot(a, b) / denom))
        except Exception:
            return 0.0

    def get_info(self) -> dict:
        """Return model metadata."""
        return {
            "model_name": self.MODEL_NAME,
            "embedding_dim": self.EMBEDDING_DIM,
            "is_available": self.is_available,
        }
