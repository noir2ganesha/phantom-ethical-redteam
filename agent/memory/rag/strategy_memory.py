"""Layer 2+3 Strategy Memory — attack strategies and meta-cognitive patterns.

Layer 2 (strategies): tool sequences, phase transitions, success rates.
Layer 3 (meta_patterns): failure recovery, false-positive detection.

Requires PostgreSQL with pgvector.  Degrades gracefully when unavailable.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from memory.rag.rrf_fusion import rrf_fusion
from memory.rag.vector_embedding import EmbeddingGenerator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Tool category mapping
# ---------------------------------------------------------------------------

_TOOL_CATEGORIES: dict[str, set[str]] = {
    "recon": {"nmap", "dig", "whatweb", "whois", "dnsrecon", "enum4linux", "ldapsearch"},
    "scan": {"nuclei", "nikto", "gobuster", "ffuf", "feroxbuster", "dirsearch", "wpscan"},
    "exploit": {
        "sqlmap", "hydra", "metasploit", "crackmapexec", "certipy-ad",
        "impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
        "impacket-GetNPUsers", "impacket-GetUserSPNs", "impacket-secretsdump",
        "evil-winrm", "bloodhound-python",
    },
    "post": {"linpeas", "winpeas", "mimikatz", "rubeus", "sharphound", "seatbelt"},
    "pivot": {"ssh", "chisel", "socat", "ligolo", "proxychains"},
}

_TOOL_TO_CATEGORY: dict[str, str] = {}
for _cat, _tools in _TOOL_CATEGORIES.items():
    for _t in _tools:
        _TOOL_TO_CATEGORY[_t] = _cat

# ---------------------------------------------------------------------------
# SQL constants
# ---------------------------------------------------------------------------

_CREATE_STRATEGIES = """
CREATE TABLE IF NOT EXISTS strategies (
    id              SERIAL PRIMARY KEY,
    strategy_hash   VARCHAR(64) UNIQUE,
    name            VARCHAR(255),
    description     TEXT,
    target_type     VARCHAR(100),
    tool_sequence   TEXT[] DEFAULT '{}',
    phase_transitions JSONB DEFAULT '[]',
    preconditions   TEXT[] DEFAULT '{}',
    success_count   INTEGER DEFAULT 0,
    failure_count   INTEGER DEFAULT 0,
    success_rate    FLOAT DEFAULT 0.0,
    attack_ids      INTEGER[] DEFAULT '{}',
    tags            TEXT[] DEFAULT '{}',
    embedding       vector(768),
    search_tsv      tsvector,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

_CREATE_META_PATTERNS = """
CREATE TABLE IF NOT EXISTS meta_patterns (
    id              SERIAL PRIMARY KEY,
    pattern_type    VARCHAR(100) NOT NULL,
    pattern_key     VARCHAR(255) UNIQUE,
    description     TEXT,
    trigger_conditions   JSONB,
    recommended_actions  JSONB,
    observation_count       INTEGER DEFAULT 1,
    success_when_followed   INTEGER DEFAULT 0,
    failure_when_ignored    INTEGER DEFAULT 0,
    confidence      FLOAT DEFAULT 0.5,
    strategy_ids    INTEGER[] DEFAULT '{}',
    embedding       vector(768),
    search_tsv      tsvector,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

_UPSERT_STRATEGY = """
INSERT INTO strategies
    (strategy_hash, name, description, target_type, tool_sequence,
     phase_transitions, preconditions, success_count, failure_count,
     success_rate, attack_ids, tags, embedding, created_at)
VALUES
    (%(hash)s, %(name)s, %(description)s, %(target_type)s, %(tool_sequence)s,
     %(phase_transitions)s, %(preconditions)s,
     %(success_count)s, %(failure_count)s, %(success_rate)s,
     %(attack_ids)s, %(tags)s, %(embedding)s, %(created_at)s)
ON CONFLICT (strategy_hash) DO UPDATE SET
    success_count = strategies.success_count + EXCLUDED.success_count,
    failure_count = strategies.failure_count + EXCLUDED.failure_count,
    success_rate = CASE
        WHEN (strategies.success_count + strategies.failure_count
              + EXCLUDED.success_count + EXCLUDED.failure_count) > 0
        THEN (strategies.success_count + EXCLUDED.success_count)::float
             / (strategies.success_count + strategies.failure_count
                + EXCLUDED.success_count + EXCLUDED.failure_count)
        ELSE 0.0 END,
    attack_ids = strategies.attack_ids || EXCLUDED.attack_ids,
    updated_at = CURRENT_TIMESTAMP
RETURNING id;
"""

_SEARCH_STRATEGIES_VECTOR = """
SELECT *, GREATEST(0.0, 1 - (embedding <=> %(embedding)s::vector)) AS similarity
FROM strategies
WHERE embedding IS NOT NULL
  AND (%(target_type)s::text IS NULL OR target_type = %(target_type)s)
ORDER BY embedding <=> %(embedding)s::vector
LIMIT %(top_k)s;
"""

_SEARCH_STRATEGIES_BM25 = """
SELECT *, ts_rank(search_tsv, plainto_tsquery('english', %(query)s)) AS rank
FROM strategies
WHERE search_tsv @@ plainto_tsquery('english', %(query)s)
  AND (%(target_type)s::text IS NULL OR target_type = %(target_type)s)
ORDER BY rank DESC
LIMIT %(top_k)s;
"""

_UPSERT_META_PATTERN = """
INSERT INTO meta_patterns
    (pattern_type, pattern_key, description, trigger_conditions,
     recommended_actions, observation_count, success_when_followed,
     failure_when_ignored, confidence, strategy_ids, embedding, created_at)
VALUES
    (%(pattern_type)s, %(pattern_key)s, %(description)s, %(trigger_conditions)s,
     %(recommended_actions)s, 1, %(success_inc)s, %(failure_inc)s, %(confidence)s,
     %(strategy_ids)s, %(embedding)s, %(created_at)s)
ON CONFLICT (pattern_key) DO UPDATE SET
    observation_count = meta_patterns.observation_count + 1,
    success_when_followed = meta_patterns.success_when_followed + EXCLUDED.success_when_followed,
    failure_when_ignored = meta_patterns.failure_when_ignored + EXCLUDED.failure_when_ignored,
    confidence = CASE
        WHEN (meta_patterns.observation_count + 1) > 0
        THEN (meta_patterns.success_when_followed + EXCLUDED.success_when_followed)::float
             / (meta_patterns.observation_count + 1)
        ELSE 0.5 END,
    updated_at = CURRENT_TIMESTAMP
RETURNING id;
"""

_SEARCH_META_PATTERNS = """
SELECT * FROM meta_patterns
WHERE pattern_type = %(pattern_type)s
ORDER BY confidence DESC, observation_count DESC
LIMIT %(top_k)s;
"""

_GET_STATS = """
SELECT
    (SELECT COUNT(*) FROM strategies) AS total_strategies,
    (SELECT COUNT(*) FROM meta_patterns) AS total_meta_patterns,
    (SELECT COUNT(DISTINCT target_type) FROM strategies) AS target_types
;
"""


class StrategyMemory:
    """Layer 2+3 memory for attack strategies and meta-cognitive patterns.

    Instantiate with DI:

    .. code-block:: python

        emb = EmbeddingGenerator()
        mem = StrategyMemory(db_config={...}, embedding_generator=emb)
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
        self._init_pool()

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _init_pool(self) -> None:
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
            self._pool = ThreadedConnectionPool(minconn=1, maxconn=3, **kwargs)
            self._available = True
            logger.info("StrategyMemory: connected to PostgreSQL")
        except Exception:
            self._available = False
            logger.info("StrategyMemory: PostgreSQL unavailable", exc_info=True)

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
                cur.execute(_CREATE_STRATEGIES)
                cur.execute(_CREATE_META_PATTERNS)
            conn.commit()
            self._tables_ensured = True
        except Exception:
            logger.warning("Failed to ensure strategy tables", exc_info=True)
            if conn:
                conn.rollback()
        finally:
            self._release_connection(conn)

    def close(self) -> None:
        if self._pool is not None:
            try:
                self._pool.closeall()
            except Exception:
                pass
            self._pool = None
            self._available = False

    @property
    def is_available(self) -> bool:
        return self._available

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_tool_sequence(actions: list[dict]) -> list[str]:
        """Extract unique consecutive tool names from action dicts."""
        tools: list[str] = []
        for action in actions:
            name = action.get("tool") or action.get("tool_name") or action.get("name", "")
            name = name.strip().lower()
            if name and (not tools or tools[-1] != name):
                tools.append(name)
        return tools

    @staticmethod
    def _classify_target_type(
        target: str, objective: str = "", tags: list[str] | None = None
    ) -> str:
        """Classify the target type for strategy grouping."""
        combined = f"{target} {objective} {' '.join(tags or [])}".lower()
        if any(kw in combined for kw in ("active directory", "domain", "kerberos", "ldap", "dc")):
            return "active_directory"
        if any(kw in combined for kw in ("web", "http", "api", "sql injection", "xss")):
            return "web_app"
        if any(kw in combined for kw in ("linux", "privesc", "suid", "sudo")):
            return "linux_privesc"
        if any(kw in combined for kw in ("windows", "privilege", "token", "uac")):
            return "windows_privesc"
        return "general"

    @staticmethod
    def _extract_phase_transitions(actions: list[dict]) -> list[dict]:
        """Detect tool-category changes in the action sequence."""
        transitions: list[dict] = []
        prev_cat = ""
        for action in actions:
            name = (action.get("tool") or action.get("name", "")).strip().lower()
            cat = _TOOL_TO_CATEGORY.get(name, "unknown")
            if prev_cat and cat != prev_cat and cat != "unknown":
                transitions.append({"from": prev_cat, "to": cat, "tool": name})
            if cat != "unknown":
                prev_cat = cat
        return transitions

    @staticmethod
    def _compute_strategy_hash(tool_sequence: list[str], target_type: str) -> str:
        """SHA-256 hash for UPSERT deduplication."""
        raw = f"{target_type}:{','.join(tool_sequence)}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def _embed_text(self, text: str) -> str | None:
        """Generate embedding string for SQL, or None."""
        if not self._embedding or not self._embedding.is_available:
            return None
        vec = self._embedding.embed(text)
        return str(vec) if vec is not None else None

    # ------------------------------------------------------------------
    # Layer 2: Strategy CRUD
    # ------------------------------------------------------------------

    def extract_strategy(
        self,
        actions: list[dict],
        target: str,
        objective: str,
        success: bool,
        attack_id: int | None = None,
        tags: list[str] | None = None,
    ) -> int | None:
        """Extract and upsert a strategy from action history.

        Returns:
            The ``strategy_id``, or ``None`` on failure.
        """
        if not self._available:
            return None
        self._ensure_tables()

        tool_seq = self._normalize_tool_sequence(actions)
        if len(tool_seq) < 2:
            return None  # Too short to be a strategy

        target_type = self._classify_target_type(target, objective, tags)
        strat_hash = self._compute_strategy_hash(tool_seq, target_type)
        transitions = self._extract_phase_transitions(actions)
        name = f"{target_type}: {' → '.join(tool_seq[:5])}"
        description = f"Strategy for {target_type} ({objective[:100]})" if objective else name

        embedding_str = self._embed_text(
            f"{target_type} {' '.join(tool_seq)} {objective}"
        )

        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(
                    _UPSERT_STRATEGY,
                    {
                        "hash": strat_hash,
                        "name": name,
                        "description": description,
                        "target_type": target_type,
                        "tool_sequence": tool_seq,
                        "phase_transitions": json.dumps(transitions),
                        "preconditions": tags or [],
                        "success_count": 1 if success else 0,
                        "failure_count": 0 if success else 1,
                        "success_rate": 1.0 if success else 0.0,
                        "attack_ids": [attack_id] if attack_id else [],
                        "tags": tags or [],
                        "embedding": embedding_str,
                        "created_at": datetime.now(timezone.utc),
                    },
                )
                row = cur.fetchone()
                conn.commit()
                return row[0] if row else None
        except Exception:
            logger.warning("Failed to extract strategy", exc_info=True)
            if conn:
                conn.rollback()
            return None
        finally:
            self._release_connection(conn)

    def search_strategies(
        self,
        query: str,
        target_type: str | None = None,
        top_k: int = 5,
    ) -> list[dict]:
        """Hybrid search for strategies (vector + BM25 RRF)."""
        if not self._available:
            return []

        vec_results: list[dict] = []
        if self._embedding and self._embedding.is_available:
            vec = self._embedding.embed(query)
            if vec is not None:
                conn = None
                try:
                    import psycopg2.extras

                    conn = self._get_connection()
                    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                        cur.execute(
                            _SEARCH_STRATEGIES_VECTOR,
                            {"embedding": str(vec), "target_type": target_type, "top_k": top_k * 2},
                        )
                        vec_results = [dict(r) for r in cur.fetchall()]
                except Exception:
                    logger.warning("Strategy vector search failed", exc_info=True)
                finally:
                    self._release_connection(conn)

        bm25_results: list[dict] = []
        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    _SEARCH_STRATEGIES_BM25,
                    {"query": query, "target_type": target_type, "top_k": top_k * 2},
                )
                bm25_results = [dict(r) for r in cur.fetchall()]
        except Exception:
            logger.warning("Strategy BM25 search failed", exc_info=True)
        finally:
            self._release_connection(conn)

        if vec_results or bm25_results:
            return rrf_fusion(vec_results, bm25_results, top_k=top_k)
        return []

    def get_strategy_boost(
        self,
        scenario: str,
        target_type: str | None = None,
        top_k: int = 3,
    ) -> list[dict]:
        """Get strategy suggestions for hypothesis boosting.

        Returns list of dicts with keys: id, name, tool_sequence,
        success_rate, preconditions, target_type.
        """
        results = self.search_strategies(scenario, target_type=target_type, top_k=top_k)
        boosts: list[dict] = []
        for r in results:
            boosts.append({
                "id": r.get("id"),
                "name": r.get("name", ""),
                "tool_sequence": r.get("tool_sequence", []),
                "success_rate": r.get("success_rate", 0.0),
                "preconditions": r.get("preconditions", []),
                "target_type": r.get("target_type", ""),
            })
        return boosts

    # ------------------------------------------------------------------
    # Layer 3: Meta-Patterns
    # ------------------------------------------------------------------

    def save_meta_pattern(
        self,
        pattern_type: str,
        trigger: dict,
        action: dict,
        success: bool = True,
        strategy_id: int | None = None,
    ) -> int | None:
        """Save or update a meta-cognitive pattern.

        Valid ``pattern_type`` values: ``"failure_recovery"``,
        ``"phase_transition"``, ``"tool_selection"``,
        ``"target_adaptation"``, ``"false_positive"``.

        Returns:
            The ``pattern_id``, or ``None`` on failure.
        """
        if not self._available:
            return None
        self._ensure_tables()

        pattern_key = self._generate_pattern_key(pattern_type, trigger, action)
        description = f"{pattern_type}: {json.dumps(trigger)[:100]} → {json.dumps(action)[:100]}"
        embedding_str = self._embed_text(description)

        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(
                    _UPSERT_META_PATTERN,
                    {
                        "pattern_type": pattern_type,
                        "pattern_key": pattern_key,
                        "description": description,
                        "trigger_conditions": json.dumps(trigger),
                        "recommended_actions": json.dumps(action),
                        "success_inc": 1 if success else 0,
                        "failure_inc": 0 if success else 1,
                        "confidence": 0.5,
                        "strategy_ids": [strategy_id] if strategy_id else [],
                        "embedding": embedding_str,
                        "created_at": datetime.now(timezone.utc),
                    },
                )
                row = cur.fetchone()
                conn.commit()
                return row[0] if row else None
        except Exception:
            logger.warning("Failed to save meta pattern", exc_info=True)
            if conn:
                conn.rollback()
            return None
        finally:
            self._release_connection(conn)

    def get_failure_recovery(
        self,
        situation: str,
        tool: str | None = None,
    ) -> dict | None:
        """Look up a failure-recovery pattern for the given situation."""
        if not self._available:
            return None
        self._ensure_tables()

        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    _SEARCH_META_PATTERNS,
                    {"pattern_type": "failure_recovery", "top_k": 5},
                )
                rows = [dict(r) for r in cur.fetchall()]

            # Score matches by keyword overlap
            situation_lower = situation.lower()
            best: dict | None = None
            best_score = 0
            for row in rows:
                trigger_str = json.dumps(row.get("trigger_conditions", {})).lower()
                desc = (row.get("description") or "").lower()
                score = sum(1 for word in situation_lower.split() if word in trigger_str or word in desc)
                if tool and tool.lower() in trigger_str:
                    score += 3
                if score > best_score:
                    best_score = score
                    best = row
            return best
        except Exception:
            logger.warning("Failure recovery lookup failed", exc_info=True)
            return None
        finally:
            self._release_connection(conn)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_pattern_key(
        pattern_type: str, trigger: dict, action: dict
    ) -> str:
        """Generate a unique key for UPSERT deduplication."""
        raw = f"{pattern_type}:{json.dumps(trigger, sort_keys=True)}:{json.dumps(action, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return aggregate statistics for strategies and meta-patterns."""
        if not self._available:
            return {"total_strategies": 0, "total_meta_patterns": 0, "target_types": 0}

        conn = None
        try:
            import psycopg2.extras

            conn = self._get_connection()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(_GET_STATS)
                row = cur.fetchone()
                return dict(row) if row else {"total_strategies": 0}
        except Exception:
            logger.warning("Failed to get strategy stats", exc_info=True)
            return {"total_strategies": 0}
        finally:
            self._release_connection(conn)
