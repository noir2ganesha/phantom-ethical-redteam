"""Reciprocal Rank Fusion — combines vector and BM25 search results."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def rrf_fusion(
    vector_results: list[dict],
    bm25_results: list[dict],
    k: int = 60,
    top_k: int = 5,
) -> list[dict]:
    """Merge vector and BM25 search results using Reciprocal Rank Fusion.

    RRF_score(d) = Σ 1/(k + rank_i(d))

    Args:
        vector_results: Results from vector (embedding) search.  Each dict
            must contain an ``"id"`` key.
        bm25_results: Results from BM25 (tsvector) search.  Same requirement.
        k: RRF constant (default 60 — standard value from the original paper).
        top_k: Number of results to return.

    Returns:
        Merged results sorted by ``rrf_score`` descending, enriched with
        ``rrf_score``, ``vector_rank``, ``bm25_rank``, ``similarity_score``,
        and ``search_type`` keys.
    """
    scores: dict[int, float] = {}
    vector_map: dict[int, dict] = {}
    bm25_map: dict[int, dict] = {}

    # Score vector results
    for rank, result in enumerate(vector_results, start=1):
        rid = result.get("id")
        if rid is None:
            continue
        scores[rid] = scores.get(rid, 0.0) + 1.0 / (k + rank)
        vector_map[rid] = result

    # Score BM25 results
    for rank, result in enumerate(bm25_results, start=1):
        rid = result.get("id")
        if rid is None:
            continue
        scores[rid] = scores.get(rid, 0.0) + 1.0 / (k + rank)
        bm25_map[rid] = result

    if not scores:
        return []

    # Pre-build rank lookup maps (O(n) instead of O(n²))
    vector_rank_map = {r.get("id"): i for i, r in enumerate(vector_results, 1)}
    bm25_rank_map = {r.get("id"): i for i, r in enumerate(bm25_results, 1)}

    # Merge and sort
    merged: list[dict] = []
    sorted_ids = sorted(scores, key=lambda rid: scores[rid], reverse=True)

    for rid in sorted_ids[:top_k]:
        # Prefer vector result (has embedding similarity), fall back to BM25
        base = vector_map.get(rid, bm25_map.get(rid, {})).copy()
        base["rrf_score"] = round(scores[rid], 6)
        base["vector_rank"] = vector_rank_map.get(rid)
        base["bm25_rank"] = bm25_rank_map.get(rid)
        # Preserve original similarity score if present
        base.setdefault("similarity_score", None)
        base["search_type"] = "hybrid_rrf"
        merged.append(base)

    return merged
