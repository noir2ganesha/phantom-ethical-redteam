"""Tests for 4-layer hypothesis generation engine — Sprint 6."""

import sys
from pathlib import Path

_AGENT = Path(__file__).resolve().parent.parent / "agent"
if str(_AGENT) not in sys.path:
    sys.path.insert(0, str(_AGENT))

import pytest
from reasoning.hypothesis_engine import (
    HypothesisEngine,
    PRODUCT_CATALOG,
    SSRF_HOSTNAME_PATTERNS,
    PRODUCT_SIGNATURES,
)
from reasoning.interfaces import (
    AttackHypothesis,
    HypothesisSource,
    HypothesisStatus,
    VerificationResult,
)


@pytest.fixture
def engine():
    return HypothesisEngine()


# ── Data model tests ───────────────────────────────────────────


class TestInterfaces:
    def test_attack_hypothesis_defaults(self):
        h = AttackHypothesis()
        assert h.confidence == 0.5
        assert h.source == HypothesisSource.RULE
        assert h.status == HypothesisStatus.PENDING
        assert len(h.id) == 8

    def test_confidence_clamped(self):
        h = AttackHypothesis(confidence=1.5)
        assert h.confidence == 1.0
        h2 = AttackHypothesis(confidence=-0.5)
        assert h2.confidence == 0.0

    def test_hypothesis_source_values(self):
        assert HypothesisSource.RULE.value == "rule"
        assert HypothesisSource.RAG.value == "rag"
        assert HypothesisSource.LLM.value == "llm"
        assert HypothesisSource.PATTERN.value == "pattern"


# ── Catalog tests ──────────────────────────────────────────────


class TestCatalogs:
    def test_product_catalog_not_empty(self):
        assert len(PRODUCT_CATALOG) >= 17

    def test_product_catalog_has_mcpjam(self):
        assert "mcpjam" in PRODUCT_CATALOG
        mcpjam = PRODUCT_CATALOG["mcpjam"]
        assert "/api/mcp/connect" in mcpjam["paths"]
        assert mcpjam["rce_method"]

    def test_product_catalog_has_arcane(self):
        assert "arcane" in PRODUCT_CATALOG

    def test_product_catalog_has_privatebin(self):
        assert "privatebin" in PRODUCT_CATALOG

    def test_ssrf_patterns_not_empty(self):
        assert len(SSRF_HOSTNAME_PATTERNS) >= 9

    def test_ssrf_patterns_has_mcp(self):
        assert "mcp" in SSRF_HOSTNAME_PATTERNS
        assert "mcp" in SSRF_HOSTNAME_PATTERNS["mcp"]
        assert "mcpjam" in SSRF_HOSTNAME_PATTERNS["mcp"]

    def test_ssrf_patterns_has_container(self):
        assert "container" in SSRF_HOSTNAME_PATTERNS
        assert "docker" in SSRF_HOSTNAME_PATTERNS["container"]

    def test_product_signatures_has_mcpjam(self):
        assert "mcpjam" in PRODUCT_SIGNATURES


# ── Layer 1: Rule-based hypothesis generation ──────────────────


class TestRuleBasedGeneration:
    def test_port_80_generates_web_hypothesis(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [{"host": "10.0.0.1", "port": 80, "service": "http"}],
            "state_snapshot": {},
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        assert len(hyps) > 0
        assert any("web" in h.description.lower() or "http" in h.description.lower() for h in hyps)

    def test_port_8080_generates_hypothesis(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [{"host": "10.0.0.1", "port": 8080, "service": "http"}],
            "state_snapshot": {},
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        assert len(hyps) > 0

    def test_multiple_ports(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [
                {"host": "10.0.0.1", "port": 22, "service": "ssh"},
                {"host": "10.0.0.1", "port": 80, "service": "http"},
                {"host": "10.0.0.1", "port": 443, "service": "https"},
            ],
            "state_snapshot": {},
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        assert len(hyps) >= 1

    def test_no_services_empty_hypotheses(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [],
            "state_snapshot": {},
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        # May or may not generate hypotheses — just shouldn't crash
        assert isinstance(hyps, list)


# ── Subdomain → Product Catalog matching ───────────────────────


class TestSubdomainMatching:
    def test_mcp_subdomain_generates_mcpjam_hypothesis(self, engine):
        """kobold.htb F1/F4: mcp.kobold.htb → MCPJam Inspector hypothesis."""
        context = {
            "target": "10.129.245.50",
            "services": [{"host": "10.129.245.50", "port": 80, "service": "http"}],
            "state_snapshot": {
                "domains": [{"domain": "mcp.kobold.htb"}],
            },
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        mcpjam_hyps = [h for h in hyps if "mcp" in h.description.lower()]
        assert len(mcpjam_hyps) > 0
        # Should have high confidence
        assert any(h.confidence >= 0.65 for h in mcpjam_hyps)

    def test_bin_subdomain_generates_privatebin_hypothesis(self, engine):
        context = {
            "target": "10.129.245.50",
            "services": [{"host": "10.129.245.50", "port": 443, "service": "https"}],
            "state_snapshot": {
                "domains": [{"domain": "bin.kobold.htb"}],
            },
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        privatebin_hyps = [h for h in hyps if "privatebin" in h.description.lower() or "bin" in h.description.lower()]
        assert len(privatebin_hyps) > 0

    def test_admin_subdomain_matches_ssrf_pattern(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [{"host": "10.0.0.1", "port": 80, "service": "http"}],
            "state_snapshot": {
                "domains": [{"domain": "admin.target.htb"}],
            },
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        admin_hyps = [h for h in hyps if "admin" in h.description.lower()]
        assert len(admin_hyps) > 0

    def test_no_subdomains_no_product_hypotheses(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [{"host": "10.0.0.1", "port": 80, "service": "http"}],
            "state_snapshot": {},
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        # Should not contain subdomain-based product hypotheses
        subdomain_hyps = [h for h in hyps if "subdomain" in h.description.lower()]
        assert len(subdomain_hyps) == 0


# ── Hypothesis properties ──────────────────────────────────────


class TestHypothesisProperties:
    def test_all_hypotheses_have_valid_confidence(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [
                {"host": "10.0.0.1", "port": 80, "service": "http"},
                {"host": "10.0.0.1", "port": 8080, "service": "http"},
            ],
            "state_snapshot": {
                "domains": [{"domain": "mcp.target.htb"}],
            },
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        for h in hyps:
            assert 0.0 <= h.confidence <= 1.0
            assert isinstance(h.description, str)
            assert len(h.description) > 0
            assert isinstance(h.source, HypothesisSource)

    def test_hypotheses_sorted_by_confidence(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [
                {"host": "10.0.0.1", "port": 80, "service": "http"},
                {"host": "10.0.0.1", "port": 8080, "service": "http"},
            ],
            "state_snapshot": {
                "domains": [{"domain": "mcp.target.htb"}],
            },
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        if len(hyps) >= 2:
            for i in range(len(hyps) - 1):
                assert hyps[i].confidence >= hyps[i + 1].confidence

    def test_max_hypotheses_limit(self, engine):
        context = {
            "target": "10.0.0.1",
            "services": [
                {"host": "10.0.0.1", "port": p, "service": "http"}
                for p in [80, 443, 8080, 8443, 3000, 5000, 9443]
            ],
            "state_snapshot": {
                "domains": [
                    {"domain": "mcp.target.htb"},
                    {"domain": "admin.target.htb"},
                    {"domain": "jenkins.target.htb"},
                ],
            },
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        assert len(hyps) <= engine._max_hypotheses


# ── StateStore integration ─────────────────────────────────────


class TestStateStoreIntegration:
    def test_context_from_statestore(self, engine):
        """Simulate building context from StateStore data."""
        from memory.state_store import StateStore
        from memory.entity_models import HostEntity, ServiceEntity

        store = StateStore(db_path=":memory:")
        h_id = store.add_host(HostEntity(ip_address="10.129.16.19", hostname="devarea.htb"))
        store.add_service(ServiceEntity(host_id=h_id, port=21, service_name="ftp", version="vsftpd 3.0.5"))
        store.add_service(ServiceEntity(host_id=h_id, port=80, service_name="http", version="Apache 2.4.58"))
        store.add_service(ServiceEntity(host_id=h_id, port=8080, service_name="http", version="Jetty 9.4.27"))
        store.add_service(ServiceEntity(host_id=h_id, port=8888, service_name="http", version="Golang net/http"))

        # Build context from StateStore (same logic as mcp_bridge generate_hypotheses)
        hosts = store.get_hosts()
        services_list = []
        domains_list = []
        for host in hosts:
            for svc in store.get_services_for_host(host.id):
                services_list.append({
                    "host": host.ip_address,
                    "port": svc.port,
                    "service": svc.service_name or "",
                    "product": svc.version.split()[0] if svc.version else "",
                    "version": svc.version or "",
                })
            if host.hostname:
                domains_list.append({"domain": host.hostname})

        context = {
            "target": hosts[0].ip_address,
            "services": services_list,
            "state_snapshot": {"domains": domains_list},
            "findings": [],
            "phase": "recon",
        }

        hyps = engine.generate_hypotheses(context)
        assert len(hyps) > 0
        # Port 80 and 8080 should generate web hypotheses
        assert any("web" in h.description.lower() or "http" in h.description.lower() for h in hyps)

        store.close()


# ── Full scenario tests ────────────────────────────────────────


class TestKoboldScenario:
    """kobold.htb: verify MCPJam Inspector hypothesis generation."""

    def test_full_kobold_flow(self, engine):
        context = {
            "target": "10.129.245.50",
            "services": [
                {"host": "10.129.245.50", "port": 22, "service": "ssh", "product": "OpenSSH"},
                {"host": "10.129.245.50", "port": 80, "service": "http", "product": "nginx"},
                {"host": "10.129.245.50", "port": 443, "service": "https", "product": "nginx"},
                {"host": "10.129.245.50", "port": 3552, "service": "http", "product": "golang"},
            ],
            "state_snapshot": {
                "domains": [
                    {"domain": "mcp.kobold.htb"},
                    {"domain": "bin.kobold.htb"},
                ],
            },
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)

        # MCPJam hypothesis must be present
        mcpjam = [h for h in hyps if "mcp" in h.description.lower()]
        assert len(mcpjam) > 0, "MCPJam hypothesis not generated!"
        assert mcpjam[0].confidence >= 0.65

        # PrivateBin hypothesis should also be present
        privatebin = [h for h in hyps if "privatebin" in h.description.lower() or "bin" in h.description.lower()]
        assert len(privatebin) > 0


class TestDevAreaScenario:
    """devarea.htb: verify hypotheses for Jetty/Hoverfly/FTP target."""

    def test_full_devarea_flow(self, engine):
        context = {
            "target": "10.129.16.19",
            "services": [
                {"host": "10.129.16.19", "port": 21, "service": "ftp", "product": "vsftpd"},
                {"host": "10.129.16.19", "port": 80, "service": "http", "product": "Apache"},
                {"host": "10.129.16.19", "port": 8080, "service": "http", "product": "Jetty"},
                {"host": "10.129.16.19", "port": 8888, "service": "http", "product": "golang"},
            ],
            "state_snapshot": {},
            "findings": [],
            "phase": "recon",
        }
        hyps = engine.generate_hypotheses(context)
        assert len(hyps) > 0
        # Port 80 and 8080 should generate hypotheses
        descriptions = " ".join(h.description.lower() for h in hyps)
        assert "web" in descriptions or "http" in descriptions or "enumeration" in descriptions
