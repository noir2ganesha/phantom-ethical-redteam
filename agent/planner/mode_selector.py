"""Execution-mode selector based on the current TDI score.

Maps the continuous TDI value to one of three discrete execution modes:
reconnaissance (BFS-style broad enumeration), exploitation (DFS-style
deep dive), or LLM-decided (let the language model choose).
"""

from __future__ import annotations


def select_mode(
    tdi_value: float,
    bfs_threshold: float = 0.6,
    dfs_threshold: float = 0.3,
    recon_saturated: bool = False,
) -> str:
    """Select the execution mode for the current planning step.

    The mapping is:

    * ``recon_saturated`` is True -- **"exploitation"** (forced):
      reconnaissance has produced no new findings for N consecutive
      iterations, so the planner should switch to exploitation.
    * ``tdi_value > bfs_threshold`` -- **"reconnaissance"** (BFS):
      high difficulty means the planner should cast a wider net.
    * ``tdi_value < dfs_threshold`` -- **"exploitation"** (DFS):
      low difficulty means the planner should exploit a known path.
    * Otherwise -- **"llm_decide"**: let the LLM pick the best
      strategy for the ambiguous middle ground.

    Args:
        tdi_value: The composite TDI score (0..1).
        bfs_threshold: Values above this trigger reconnaissance mode.
        dfs_threshold: Values below this trigger exploitation mode.
        recon_saturated: If True, force exploitation mode regardless of TDI.

    Returns:
        One of ``"reconnaissance"``, ``"exploitation"``, or
        ``"llm_decide"``.
    """
    if dfs_threshold >= bfs_threshold:
        raise ValueError(
            f"dfs_threshold ({dfs_threshold}) must be < bfs_threshold ({bfs_threshold})"
        )
    if recon_saturated:
        return "exploitation"
    if tdi_value > bfs_threshold:
        return "reconnaissance"
    if tdi_value < dfs_threshold:
        return "exploitation"
    return "llm_decide"
