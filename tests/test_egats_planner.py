"""Tests for planner/ EGATS core — Sprint 3 (old 4)."""

import sys
from pathlib import Path

_AGENT = Path(__file__).resolve().parent.parent / "agent"
if str(_AGENT) not in sys.path:
    sys.path.insert(0, str(_AGENT))

import pytest
from planner.egats import EGATSPlanner
from planner.models import (
    ActionOutcome,
    AttackNode,
    AttackTree,
    EvidenceLevel,
    NodeStatus,
    NodeType,
    TDIScore,
)
from planner.backpropagation import backpropagate
from planner.pruning import should_prune, prune_branch
from planner.pivot import spawn_pivot, propagate_credentials
from planner.tda import TDAComputer
from planner.ucb import select_node
from planner.mode_selector import select_mode


@pytest.fixture
def planner():
    return EGATSPlanner()


@pytest.fixture
def tree(planner):
    return planner.init_tree("10.129.245.50")


# ── Models ─────────────────────────────────────────────────────


class TestModels:
    def test_tdi_score_formula(self):
        """TDI = w_h*H + w_e*(1-E) + w_c*C + w_s*(1-S)"""
        tdi = TDIScore(
            horizon=1.0,
            evidence_confidence=1.0,
            context_load=0.0,
            success_rate=1.0,
        )
        # 0.3*1.0 + 0.3*(1-1.0) + 0.2*0.0 + 0.2*(1-1.0) = 0.3
        assert abs(tdi.value - 0.3) < 0.001

    def test_tdi_score_max_difficulty(self):
        tdi = TDIScore(
            horizon=1.0,
            evidence_confidence=0.0,
            context_load=1.0,
            success_rate=0.0,
        )
        # 0.3*1.0 + 0.3*1.0 + 0.2*1.0 + 0.2*1.0 = 1.0
        assert abs(tdi.value - 1.0) < 0.001

    def test_tdi_score_min_difficulty(self):
        tdi = TDIScore(
            horizon=0.0,
            evidence_confidence=1.0,
            context_load=0.0,
            success_rate=1.0,
        )
        assert abs(tdi.value - 0.0) < 0.001

    def test_attack_node_defaults(self):
        node = AttackNode()
        assert node.node_type == NodeType.ACTION
        assert node.status == NodeStatus.PENDING
        assert node.promise_score == 0.5
        assert node.visit_count == 0
        assert len(node.id) == 8

    def test_attack_tree_add_and_get(self):
        tree = AttackTree()
        node = AttackNode(description="test")
        tree.nodes[node.id] = node
        tree.root_id = node.id
        assert tree.get_node(node.id) is not None
        assert tree.get_node("nonexistent") is None

    def test_attack_tree_parent_child(self):
        tree = AttackTree()
        parent = AttackNode(description="parent")
        child = AttackNode(description="child", parent_id=parent.id)
        tree.nodes[parent.id] = parent
        tree.add_node(child)
        assert child.id in parent.children_ids

    def test_attack_tree_path_to_root(self):
        tree = AttackTree()
        root = AttackNode(id="root", description="root")
        mid = AttackNode(id="mid", description="mid", parent_id="root")
        leaf = AttackNode(id="leaf", description="leaf", parent_id="mid")
        tree.nodes["root"] = root
        tree.nodes["mid"] = mid
        tree.nodes["leaf"] = leaf
        tree.root_id = "root"

        path = tree.get_path_to_root("leaf")
        assert len(path) == 3
        assert path[0].id == "leaf"
        assert path[-1].id == "root"

    def test_attack_tree_active_leaves(self):
        tree = AttackTree()
        root = AttackNode(id="root", status=NodeStatus.ACTIVE, children_ids=["c1", "c2"])
        c1 = AttackNode(id="c1", status=NodeStatus.ACTIVE, parent_id="root")
        c2 = AttackNode(id="c2", status=NodeStatus.PRUNED, parent_id="root")
        tree.nodes = {"root": root, "c1": c1, "c2": c2}
        leaves = tree.get_active_leaves()
        assert len(leaves) == 1
        assert leaves[0].id == "c1"

    def test_action_outcome_values(self):
        assert ActionOutcome.SUCCESS.value == 1.0
        assert ActionOutcome.PARTIAL.value == 0.5
        assert ActionOutcome.FAILURE.value == 0.1


# ── EGATSPlanner ───────────────────────────────────────────────


class TestEGATSPlanner:
    def test_init_tree(self, planner):
        tree = planner.init_tree("10.0.0.1")
        assert len(tree.nodes) == 1
        root = tree.get_node(tree.root_id)
        assert root is not None
        assert root.node_type == NodeType.OBSERVATION
        assert root.evidence_level == EvidenceLevel.VERIFIED
        assert root.promise_score == 0.5

    def test_select_next_node_returns_root(self, planner, tree):
        node = planner.select_next_node(tree)
        assert node is not None
        assert node.id == tree.root_id

    def test_compute_tdi(self, planner, tree):
        node = planner.select_next_node(tree)
        tdi = planner.compute_tdi(node, tree, context_load=0.0)
        assert 0.0 <= tdi.value <= 1.0
        # With no context load, TDI should be moderate
        assert tdi.context_load == 0.0

    def test_compute_tdi_with_context_load(self, planner, tree):
        node = planner.select_next_node(tree)
        tdi_low = planner.compute_tdi(node, tree, context_load=0.1)
        tdi_high = planner.compute_tdi(node, tree, context_load=0.9)
        assert tdi_high.value > tdi_low.value  # Higher context load → higher difficulty

    def test_select_mode(self, planner, tree):
        node = planner.select_next_node(tree)
        tdi = planner.compute_tdi(node, tree, 0.0)
        mode = planner.select_mode(tdi)
        assert mode in ("reconnaissance", "exploitation", "llm_decide")

    def test_expand_tree(self, planner, tree):
        root = tree.get_node(tree.root_id)
        findings = [
            {"description": "Port 80 HTTP service discovered", "host": "10.129.245.50"},
            {"description": "Port 22 SSH service discovered", "host": "10.129.245.50"},
        ]
        new_nodes = planner.expand_tree(tree, root, findings)
        assert len(new_nodes) >= 1
        assert len(tree.nodes) > 1


# ── UCB ────────────────────────────────────────────────────────


class TestUCB:
    def test_select_node_single(self, tree):
        node = select_node(tree)
        assert node is not None
        assert node.id == tree.root_id

    def test_select_node_prefers_unvisited(self):
        tree = AttackTree()
        root = AttackNode(id="root", status=NodeStatus.ACTIVE, children_ids=["a", "b"])
        a = AttackNode(id="a", status=NodeStatus.ACTIVE, parent_id="root", visit_count=10, promise_score=0.5)
        b = AttackNode(id="b", status=NodeStatus.ACTIVE, parent_id="root", visit_count=0, promise_score=0.5)
        tree.nodes = {"root": root, "a": a, "b": b}
        tree.root_id = "root"
        tree.total_actions = 10

        selected = select_node(tree)
        # Unvisited node "b" should have higher UCB due to exploration bonus
        assert selected.id == "b"


# ── TDA ────────────────────────────────────────────────────────


class TestTDA:
    def test_compute_tdi_basic(self):
        computer = TDAComputer()
        tree = AttackTree()
        node = AttackNode(id="n1", evidence_level=EvidenceLevel.VERIFIED)
        tree.nodes = {"n1": node}
        tree.root_id = "n1"

        tdi = computer.compute_tdi(node, tree, context_load=0.0)
        assert isinstance(tdi, TDIScore)
        assert 0.0 <= tdi.value <= 1.0


# ── Backpropagation ────────────────────────────────────────────


class TestBackpropagation:
    def test_success_increases_promise(self, tree):
        node = tree.get_node(tree.root_id)
        old_promise = node.promise_score
        backpropagate(tree, node, ActionOutcome.SUCCESS)
        assert node.promise_score > old_promise
        assert node.visit_count == 1
        assert node.success_count > 0

    def test_failure_decreases_promise(self, tree):
        node = tree.get_node(tree.root_id)
        old_promise = node.promise_score
        backpropagate(tree, node, ActionOutcome.FAILURE)
        assert node.promise_score < old_promise
        assert node.visit_count == 1
        assert node.failure_count > 0

    def test_multiple_failures_compound(self, tree):
        node = tree.get_node(tree.root_id)
        for _ in range(5):
            backpropagate(tree, node, ActionOutcome.FAILURE)
        assert node.promise_score < 0.3  # Should be significantly reduced
        assert node.visit_count == 5

    def test_promise_clamped_0_to_1(self, tree):
        node = tree.get_node(tree.root_id)
        for _ in range(20):
            backpropagate(tree, node, ActionOutcome.SUCCESS)
        assert node.promise_score <= 1.0
        for _ in range(40):
            backpropagate(tree, node, ActionOutcome.FAILURE)
        assert node.promise_score >= 0.0


# ── Pruning ────────────────────────────────────────────────────


class TestPruning:
    def test_should_not_prune_low_visits(self):
        node = AttackNode(visit_count=1)
        node.tdi = TDIScore(horizon=1.0, evidence_confidence=0.0, context_load=1.0, success_rate=0.0)
        assert not should_prune(node)  # min_attempts=3 not met

    def test_should_prune_high_tdi_enough_visits(self):
        node = AttackNode(visit_count=5)
        node.tdi = TDIScore(horizon=1.0, evidence_confidence=0.0, context_load=1.0, success_rate=0.0)
        # TDI = 1.0, visits=5 > min_attempts=3 → prune
        assert should_prune(node)

    def test_should_not_prune_low_tdi(self):
        node = AttackNode(visit_count=5)
        node.tdi = TDIScore(horizon=0.0, evidence_confidence=1.0, context_load=0.0, success_rate=1.0)
        # TDI = 0.0, even with visits → no prune
        assert not should_prune(node)

    def test_prune_branch_marks_subtree(self):
        tree = AttackTree()
        root = AttackNode(id="root", status=NodeStatus.ACTIVE, children_ids=["a"])
        a = AttackNode(id="a", status=NodeStatus.ACTIVE, parent_id="root", children_ids=["b"])
        b = AttackNode(id="b", status=NodeStatus.ACTIVE, parent_id="a")
        tree.nodes = {"root": root, "a": a, "b": b}

        pruned_ids = prune_branch(tree, a)
        assert "a" in pruned_ids
        assert "b" in pruned_ids
        assert tree.nodes["a"].status == NodeStatus.PRUNED
        assert tree.nodes["b"].status == NodeStatus.PRUNED
        assert tree.nodes["root"].status == NodeStatus.ACTIVE  # Root not pruned


# ── Pivot ──────────────────────────────────────────────────────


class TestPivot:
    def test_spawn_pivot_creates_node(self, tree):
        root = tree.get_node(tree.root_id)
        pivot = spawn_pivot(tree, "10.129.245.51", root)
        assert pivot.host == "10.129.245.51"
        assert pivot.node_type == NodeType.OBSERVATION
        assert pivot.evidence_level == EvidenceLevel.VERIFIED
        assert pivot.promise_score == 0.7
        assert "10.129.245.51" in tree.compromised_hosts

    def test_spawn_pivot_parent_linked(self, tree):
        root = tree.get_node(tree.root_id)
        pivot = spawn_pivot(tree, "10.0.0.2", root)
        assert pivot.parent_id == root.id

    def test_spawn_pivot_rejects_shell_metacharacters(self, tree):
        root = tree.get_node(tree.root_id)
        # pivot.py validates host against ^[a-zA-Z0-9._:\-/]+$ and raises ValueError
        with pytest.raises(ValueError, match="Invalid host"):
            spawn_pivot(tree, "10.0.0.1; rm -rf /", root)


# ── Mode Selector ──────────────────────────────────────────────


class TestModeSelector:
    def test_high_tdi_recon(self):
        tdi = TDIScore(horizon=1.0, evidence_confidence=0.0, context_load=1.0, success_rate=0.0)
        assert select_mode(tdi.value) == "reconnaissance"

    def test_low_tdi_exploit(self):
        tdi = TDIScore(horizon=0.0, evidence_confidence=1.0, context_load=0.0, success_rate=1.0)
        assert select_mode(tdi.value) == "exploitation"

    def test_mid_tdi_llm_decide(self):
        tdi = TDIScore(horizon=0.5, evidence_confidence=0.5, context_load=0.2, success_rate=0.5)
        mode = select_mode(tdi.value)
        assert mode in ("reconnaissance", "exploitation", "llm_decide")


# ── Kobold.htb Scenario Simulation ────────────────────────────


class TestKoboldScenario:
    """Simulate the kobold.htb attack flow and verify EGATS behavior."""

    def test_arcane_auth_failure_leads_to_pruning(self, planner):
        """F3: Arcane authentication fails 3+ times → TDI rises → branch pruned."""
        tree = planner.init_tree("10.129.245.50")
        root = tree.get_node(tree.root_id)

        # Simulate: Arcane auth attempt node
        arcane_node = AttackNode(
            description="Arcane default credential authentication",
            parent_id=root.id,
            node_type=NodeType.ACTION,
        )
        tree.add_node(arcane_node)

        # 3 consecutive failures
        for _ in range(3):
            backpropagate(tree, arcane_node, ActionOutcome.FAILURE)
            arcane_node.tdi = planner.compute_tdi(arcane_node, tree, 0.3)

        # After 3 failures, promise should be low
        assert arcane_node.promise_score < 0.3
        assert arcane_node.visit_count == 3

        # TDI should be elevated due to low success rate
        assert arcane_node.tdi.value > 0.5

    def test_new_host_pivot(self, planner):
        """After discovering mcp.kobold.htb, pivot to new host."""
        tree = planner.init_tree("10.129.245.50")
        root = tree.get_node(tree.root_id)

        # Discover subdomain → pivot
        pivot = spawn_pivot(tree, "mcp.kobold.htb", root)
        assert pivot is not None
        assert pivot.host == "mcp.kobold.htb"
        assert "mcp.kobold.htb" in tree.compromised_hosts

        # New node should be selectable
        leaves = tree.get_active_leaves()
        leaf_ids = {l.id for l in leaves}
        assert pivot.id in leaf_ids

    def test_ucb_prefers_unexplored_after_failure(self, planner):
        """UCB should prefer unexplored nodes after explored ones fail."""
        tree = planner.init_tree("10.129.245.50")
        root = tree.get_node(tree.root_id)
        tree.total_actions = 5

        # Create two child nodes
        explored = AttackNode(id="explored", parent_id=root.id, visit_count=5, promise_score=0.2)
        unexplored = AttackNode(id="unexplored", parent_id=root.id, visit_count=0, promise_score=0.5)
        tree.add_node(explored)
        tree.add_node(unexplored)

        selected = select_node(tree)
        assert selected.id == "unexplored"  # UCB exploration bonus
