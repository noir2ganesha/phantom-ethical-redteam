"""Pivot spawning for lateral movement across compromised hosts."""

from __future__ import annotations

import re

from planner.models import (
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
)
from planner.pruning import reevaluate_pruned

# Allow IPs, hostnames, IPv6, CIDR — reject shell metacharacters
_SAFE_HOST_RE = re.compile(r"^[a-zA-Z0-9._:\-/]+$")


def spawn_pivot(
    tree: AttackTree,
    host: str,
    parent_node: AttackNode | None,
) -> AttackNode:
    """Create a new observation sub-tree rooted at a compromised *host*.

    When a host is compromised, a pivot node is added as a child of the
    action that achieved the compromise. This node becomes the root for
    further enumeration and exploitation of the newly accessible host.

    Args:
        tree: The attack tree.
        host: The IP or hostname of the compromised machine.
        parent_node: The action node that achieved the compromise.

    Returns:
        The newly created pivot ``AttackNode``.
    """
    if not host or not _SAFE_HOST_RE.match(host):
        raise ValueError(f"Invalid host for pivot: {host!r}")

    parent_id = parent_node.id if parent_node else None

    pivot_node = AttackNode(
        node_type=NodeType.OBSERVATION,
        status=NodeStatus.PENDING,
        description=f"Pivot to compromised host: {host}",
        parent_id=parent_id,
        host=host,
        evidence_level=EvidenceLevel.VERIFIED,
        promise_score=0.7,
    )
    tree.add_node(pivot_node)
    if host not in tree.compromised_hosts:
        tree.compromised_hosts.append(host)
    return pivot_node


def propagate_credentials(
    tree: AttackTree,
    credentials: list[str],
) -> list[str]:
    """Re-evaluate all pruned nodes with newly discovered *credentials*.

    Delegates to :func:`nirvana.planner.pruning.reevaluate_pruned` to
    reopen authentication-related branches that were previously pruned.

    Args:
        tree: The attack tree.
        credentials: Newly discovered credential strings.

    Returns:
        A list of node IDs that were reopened.
    """
    return reevaluate_pruned(tree, credentials)
