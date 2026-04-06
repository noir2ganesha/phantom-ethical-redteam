"""Layer 1 Attack Memory — vector + BM25 hybrid search for similar attacks.

Requires PostgreSQL with pgvector.  When the database is unavailable the
class degrades gracefully: :attr:`is_available` returns ``False`` and all
public methods return ``None`` or empty lists.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from memory.rag.rrf_fusion import rrf_fusion
from memory.rag.vector_embedding import EmbeddingGenerator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS attacks (
    id              SERIAL PRIMARY KEY,
    target          VARCHAR(255) NOT NULL,
    scenario        TEXT NOT NULL,
    steps           JSONB DEFAULT '[]',
    tools_used      TEXT[] DEFAULT '{}',
    cve_exploited   TEXT[] DEFAULT '{}',
    result          TEXT,
    success         BOOLEAN DEFAULT TRUE,
    extraction_logic    JSONB,
    attack_chain        JSONB,
    credentials_obtained JSONB,
    tags            TEXT[] DEFAULT '{}',
    embedding       vector(768),
    search_tsv      tsvector,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

_INSERT = """
INSERT INTO attacks
    (target, scenario, steps, tools_used, cve_exploited, result,
     success, extraction_logic, attack_chain, credentials_obtained,
     tags, embedding, created_at)
VALUES
    (%(target)s, %(scenario)s, %(steps)s, %(tools_used)s, %(cve_exploited)s,
     %(result)s, %(success)s, %(extraction_logic)s, %(attack_chain)s,
     %(credentials_obtained)s, %(tags)s, %(embedding)s, %(created_at)s)
RETURNING id;
"""

_SEARCH_VECTOR = """
SELECT *, GREATEST(0.0, 1 - (embedding <=> %(embedding)s::vector)) AS similarity
FROM attacks
WHERE embedding IS NOT NULL
  AND (NOT %(success_only)s OR success = TRUE)
ORDER BY embedding <=> %(embedding)s::vector
LIMIT %(top_k)s;
"""

_SEARCH_BM25 = """
SELECT *, ts_rank(search_tsv, plainto_tsquery('english', %(query)s)) AS rank
FROM attacks
WHERE search_tsv @@ plainto_tsquery('english', %(query)s)
  AND (NOT %(success_only)s OR success = TRUE)
ORDER BY rank DESC
LIMIT %(top_k)s;
"""

_SEARCH_BY_TAGS_ALL = """
SELECT * FROM attacks WHERE tags @> %(tags)s ORDER BY created_at DESC LIMIT %(top_k)s;
"""

_SEARCH_BY_TAGS_ANY = """
SELECT * FROM attacks WHERE tags && %(tags)s ORDER BY created_at DESC LIMIT %(top_k)s;
"""

_SEARCH_BY_CVE = """
SELECT * FROM attacks WHERE %(cve)s = ANY(cve_exploited)
ORDER BY created_at DESC LIMIT %(top_k)s;
"""

_GET_STATS = """
SELECT
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE success) AS successes,
    COUNT(*) FILTER (WHERE NOT success) AS failures,
    COUNT(*) FILTER (WHERE embedding IS NOT NULL) AS with_embedding
FROM attacks;
"""


class AttackMemory:
    """Layer 1 attack memory — PostgreSQL + pgvector hybrid search.

    Instantiate with DI:

    .. code-block:: python

        emb = EmbeddingGenerator()
        mem = AttackMemory(db_config={"host": ..., "dbname": ...}, embedding_generator=emb)
    """

    def __init__(
        self,
        db_config: dict[str, Any] | str | None = None,
        embedding_generator: EmbeddingGenerator | None = None,
    ) -> None:
        self._db_config = db_config
        self._embedding = embedding_generator
        self._pool: Any = None
        self._available = False
        self._tables_ensured = False
        # TTL cache for search_hybrid (key → (timestamp, results))
        self._search_cache: dict[str, tuple[float, list[dict]]] = {}
        self._cache_ttl: float = 300.0  # 5 minutes
        self._cache_lock = threading.Lock()
        self._init_pool()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _init_pool(self) -> None:
        """Initialise the connection pool (fail-safe)."""
        if not self._db_config:
            return
        try:
            import psycopg2
            from psycopg2.pool import ThreadedConnectionPool

            kwargs: dict[str, Any]
            if isinstance(self._db_config, str):
                kwargs = {"dsn": self._db_config}
            else:
                kwargs = dict(self._db_config)
            self._pool = ThreadedConnectionPool(minconn=1, maxconn=5, **kwargs)
            self._available = True
            logger.info("AttackMemory: connected to PostgreSQL")
        except Exception:
            self._available = False
            logger.info("AttackMemory: PostgreSQL unavailable", exc_info=True)

    def _get_connection(self) -> Any:
        if self._pool is None:
            raise RuntimeError("No connection pool")
        return self._pool.getconn()

    def _release_connection(self, conn: Any) -> None:
        if self._pool is not None and conn is not None:
            self._pool.putconn(conn)

    def _ensure_tables(self) -> None:
        if self._tables_ensured or not self._available:
            return
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(_CREATE_TABLE)
            conn.commit()
            self._tables_ensured = True
        except Exception:
            logger.warning("Failed to ensure attacks table", exc_info=True)
            if conn:
                conn.rollback()
        finally:
            self._release_connection(conn)

    def close(self) -> None:
        """Close the connection pool."""
        if self._pool is not None:
            try:
                self._pool.closeall()
            except Exception:
                pass
            self._pool = None
            self._available = False

    @property
    def is_available(self) -> bool:
        """Whether the database is connected and usable."""
        return self._available

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def save_attack(
        self,
        target: str,
        scenario: str,
        steps: list[str] | None = None,
        result: str = "",
        success: bool = True,
        tools_used: list[str] | None = None,
        cve_exploited: list[str] | None = None,
        tags: list[str] | None = None,
        extraction_logic: dict | None = None,
        attack_chain: dict | None = None,
        credentials_obtained: dict | None = None,
    ) -> int | None:
        """Save an attack record with auto-generated embedding.

        Returns:
            The new ``attack_id``, or ``None`` on failure.
        """
        if not self._available:
            return None
        self._ensure_tables()

        tools = tools_used or []
        cves = cve_exploited or []
        tag_list = tags or []

        # Generate embedding
        embedding_vec: list[float] | None = None
        if self._embedding and self._embedding.is_available:
            text = EmbeddingGenerator.create_embedding_text(
                scenario=scenario,
                target=target,
                tools=tools,
                cves=cves,
                result=result,
                tags=tag_list,
                steps=steps,
            )
            embedding_vec = self._embedding.embed(text)

        embedding_str: str | None = None
        if embedding_vec is not None:
            embedding_str = str(embedding_vec)

        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(
                    _INSERT,
                    {
                        "target": target,
                        "scenario": scenario,
                        "steps": json.dumps(steps or []),
                        "tools_used": tools,
                        "cve_exploited": cves,
                        "result": result,
                        "success": success,
                        "extraction_logic": json.dumps(extraction_logic) if extraction_logic else None,
                        "attack_chain": json.dumps(attack_chain) if attack_chain else None,
                        "credentials_obtained": (
                            json.dumps(credentials_obtained) if credentials_obtained else None
                        ),
                        "tags": tag_list,
                        "embedding": embedding_str,
                        "created_at": datetime.now(timezone.utc),
                    },
                )
                row = cur.fetchone()
                conn.commit()
                # Invalidate search cache — new data may affect results
                self._search_cache.clear()
                return row[0] if row else None
        except Exception:
            logger.warning("Failed to save attack", exc_info=True)
            if conn:
                conn.rollback()
            return None
        finally:
            self._release_connection(conn)

    # ------------------------------------------------------------------
    # Search — Vector
    # ------------------------------------------------------------------

    def search_vector(
        self,
        query: str,
        top_k: int = 5,
        success_only: bool = True,
        min_similarity: float = 0.3,
    ) -> list[dict]:
        """Search by vector (embedding) similarity."""
        if not self._available:
            return []
        if not self._embedding or not self._embedding.is_available:
            return []

        vec = self._embedding.embed(query)
        if vec is None:
            return []

        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    _SEARCH_VECTOR,
                    {"embedding": str(vec), "success_only": success_only, "top_k": top_k},
                )
                rows = [dict(r) for r in cur.fetchall()]
            # Filter by min similarity
            return [r for r in rows if r.get("similarity", 0) >= min_similarity]
        except Exception:
            logger.warning("Vector search failed", exc_info=True)
            return []
        finally:
            self._release_connection(conn)

    # ------------------------------------------------------------------
    # Search — BM25
    # ------------------------------------------------------------------

    def search_bm25(
        self,
        query: str,
        top_k: int = 10,
        success_only: bool = True,
    ) -> list[dict]:
        """Search by BM25 (tsvector full-text search)."""
        if not self._available:
            return []

        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    _SEARCH_BM25,
                    {"query": query, "success_only": success_only, "top_k": top_k},
                )
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            logger.warning("BM25 search failed", exc_info=True)
            return []
        finally:
            self._release_connection(conn)

    # ------------------------------------------------------------------
    # Search — Hybrid (RRF)
    # ------------------------------------------------------------------

    def search_hybrid(
        self,
        query: str,
        top_k: int = 5,
        success_only: bool = True,
    ) -> list[dict]:
        """Hybrid search using Reciprocal Rank Fusion (vector + BM25).

        Results are cached with a TTL to avoid repeated DB round-trips
        for the same query within a single Orient-Deep cycle.
        """
        cache_key = f"{query}:{top_k}:{success_only}"
        with self._cache_lock:
            cached = self._search_cache.get(cache_key)
            if cached is not None:
                ts, results = cached
                if time.monotonic() - ts < self._cache_ttl:
                    return results
                del self._search_cache[cache_key]

        vec_results = self.search_vector(query, top_k=top_k * 2, success_only=success_only)
        bm25_results = self.search_bm25(query, top_k=top_k * 2, success_only=success_only)

        if not vec_results and not bm25_results:
            return []

        results = rrf_fusion(vec_results, bm25_results, top_k=top_k)
        with self._cache_lock:
            self._search_cache[cache_key] = (time.monotonic(), results)
        return results

    def clear_search_cache(self) -> None:
        """Clear the hybrid search cache."""
        with self._cache_lock:
            self._search_cache.clear()

    # ------------------------------------------------------------------
    # Specialised search
    # ------------------------------------------------------------------

    def search_by_tags(
        self,
        tags: list[str],
        match_all: bool = True,
        top_k: int = 10,
    ) -> list[dict]:
        """Search attacks by tags (PostgreSQL array operators)."""
        if not self._available or not tags:
            return []

        sql = _SEARCH_BY_TAGS_ALL if match_all else _SEARCH_BY_TAGS_ANY
        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, {"tags": tags, "top_k": top_k})
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            logger.warning("Tag search failed", exc_info=True)
            return []
        finally:
            self._release_connection(conn)

    def search_by_cve(self, cve: str, top_k: int = 10) -> list[dict]:
        """Search attacks that exploited a specific CVE."""
        if not self._available or not cve:
            return []

        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(_SEARCH_BY_CVE, {"cve": cve, "top_k": top_k})
                return [dict(r) for r in cur.fetchall()]
        except Exception:
            logger.warning("CVE search failed", exc_info=True)
            return []
        finally:
            self._release_connection(conn)

    # ------------------------------------------------------------------
    # Context generation (for LLM prompts)
    # ------------------------------------------------------------------

    def generate_context(self, query: str, top_k: int = 3) -> str:
        """Generate markdown context from similar past attacks.

        Used by Orient-Deep to inject RAG knowledge into the LLM prompt.
        """
        results = self.search_hybrid(query, top_k=top_k, success_only=True)
        if not results:
            return ""

        lines = []
        for i, r in enumerate(results, 1):
            scenario = r.get("scenario", "unknown")
            target = r.get("target", "")
            tools = r.get("tools_used", [])
            result = r.get("result", "")
            score = r.get("rrf_score", 0.0)
            tags = r.get("tags", [])

            lines.append(f"**{i}. {scenario}** (score={score:.3f})")
            if target:
                lines.append(f"   Target: {target}")
            if tools:
                lines.append(f"   Tools: {', '.join(tools[:5])}")
            if tags:
                lines.append(f"   Tags: {', '.join(tags[:5])}")
            if result:
                lines.append(f"   Result: {result[:200]}")
            lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return aggregate statistics."""
        if not self._available:
            return {"total": 0, "successes": 0, "failures": 0, "with_embedding": 0}

        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(_GET_STATS)
                row = cur.fetchone()
                return dict(row) if row else {"total": 0}
        except Exception:
            logger.warning("Failed to get stats", exc_info=True)
            return {"total": 0}
        finally:
            self._release_connection(conn)
