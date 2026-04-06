"""Backpropagation of action outcomes through the attack tree."""

from __future__ import annotations

from planner.models import ActionOutcome, AttackNode, AttackTree


def backpropagate(
    tree: AttackTree,
    node: AttackNode,
    outcome: ActionOutcome,
    alpha: float = 0.7,
) -> None:
    """Traverse the path from *node* to root, updating promise scores.

    Each ancestor's promise score is updated via exponential smoothing::

        phi(n) = alpha * phi(n) + (1 - alpha) * r(outcome)

    Visit, success, and failure counters are also incremented along the
    entire path so that UCB exploration terms remain accurate.

    Args:
        tree: The attack tree containing the node.
        node: The node whose outcome was just observed.
        outcome: The action outcome (SUCCESS, PARTIAL, or FAILURE).
        alpha: Smoothing factor; higher values retain more history.
    """
    path = tree.get_path_to_root(node.id)
    reward = outcome.value

    for path_node in path:
        new_promise = alpha * path_node.promise_score + (1 - alpha) * reward
        path_node.promise_score = max(0.0, min(1.0, new_promise))  # Clamp to [0, 1]
        path_node.visit_count += 1
        if outcome == ActionOutcome.SUCCESS:
            path_node.success_count += 1.0
        elif outcome == ActionOutcome.PARTIAL:
            path_node.success_count += 0.5
        elif outcome == ActionOutcome.FAILURE:
            path_node.failure_count += 1.0
