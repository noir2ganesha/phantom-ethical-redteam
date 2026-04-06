"""Tests for memory.state_store — Sprint 2."""

import json
import sys
from pathlib import Path

_AGENT = Path(__file__).resolve().parent.parent / "agent"
if str(_AGENT) not in sys.path:
    sys.path.insert(0, str(_AGENT))

import pytest
from memory.state_store import StateStore
from memory.entity_models import (
    CredentialEntity,
    HostEntity,
    ServiceEntity,
    SessionEntity,
    VulnerabilityEntity,
)


@pytest.fixture
def store():
    """In-memory StateStore for testing."""
    s = StateStore(db_path=":memory:")
    yield s
    s.close()


# ── Host CRUD ──────────────────────────────────────────────────


class TestHostCRUD:
    def test_add_and_get_host(self, store):
        host = HostEntity(ip_address="10.129.245.50", hostname="kobold.htb")
        host_id = store.add_host(host)
        assert host_id == host.id

        retrieved = store.get_host(host_id)
        assert retrieved is not None
        assert retrieved.ip_address == "10.129.245.50"
        assert retrieved.hostname == "kobold.htb"

    def test_get_host_not_found(self, store):
        assert store.get_host("nonexistent") is None

    def test_get_hosts_empty(self, store):
        assert store.get_hosts() == []

    def test_get_hosts_multiple(self, store):
        store.add_host(HostEntity(ip_address="10.0.0.1"))
        store.add_host(HostEntity(ip_address="10.0.0.2"))
        store.add_host(HostEntity(ip_address="10.0.0.3"))
        assert len(store.get_hosts()) == 3

    def test_get_host_by_ip(self, store):
        store.add_host(HostEntity(ip_address="10.129.245.50", hostname="kobold.htb"))
        store.add_host(HostEntity(ip_address="10.129.245.51", hostname="other.htb"))

        result = store.get_host_by_ip("10.129.245.50")
        assert result is not None
        assert result.hostname == "kobold.htb"

        assert store.get_host_by_ip("10.0.0.99") is None

    def test_get_host_by_hostname(self, store):
        store.add_host(HostEntity(ip_address="10.129.245.50", hostname="kobold.htb"))

        result = store.get_host_by_hostname("kobold.htb")
        assert result is not None
        assert result.ip_address == "10.129.245.50"

        assert store.get_host_by_hostname("nonexistent.htb") is None

    def test_host_with_os_fingerprint(self, store):
        host = HostEntity(ip_address="10.0.0.1", os_fingerprint="Ubuntu 24.04")
        store.add_host(host)
        retrieved = store.get_host(host.id)
        assert retrieved.os_fingerprint == "Ubuntu 24.04"

    def test_host_with_discovery_node_id(self, store):
        host = HostEntity(ip_address="10.0.0.1", discovery_node_id="node-abc")
        store.add_host(host)
        retrieved = store.get_host(host.id)
        assert retrieved.discovery_node_id == "node-abc"


# ── Service CRUD ───────────────────────────────────────────────


class TestServiceCRUD:
    def test_add_and_get_service(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.0.0.1"))
        svc = ServiceEntity(host_id=host_id, port=80, service_name="http", version="nginx 1.24.0")
        svc_id = store.add_service(svc)

        retrieved = store.get_service(svc_id)
        assert retrieved is not None
        assert retrieved.port == 80
        assert retrieved.service_name == "http"
        assert retrieved.version == "nginx 1.24.0"

    def test_get_services_for_host(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.129.245.50"))
        store.add_service(ServiceEntity(host_id=host_id, port=22, service_name="ssh"))
        store.add_service(ServiceEntity(host_id=host_id, port=80, service_name="http"))
        store.add_service(ServiceEntity(host_id=host_id, port=443, service_name="https"))
        store.add_service(ServiceEntity(host_id=host_id, port=3552, service_name="http"))

        services = store.get_services_for_host(host_id)
        assert len(services) == 4
        ports = {s.port for s in services}
        assert ports == {22, 80, 443, 3552}

    def test_get_services_for_host_empty(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.0.0.1"))
        assert store.get_services_for_host(host_id) == []

    def test_get_services_by_port(self, store):
        h1 = store.add_host(HostEntity(ip_address="10.0.0.1"))
        h2 = store.add_host(HostEntity(ip_address="10.0.0.2"))
        store.add_service(ServiceEntity(host_id=h1, port=80, service_name="http"))
        store.add_service(ServiceEntity(host_id=h2, port=80, service_name="http"))
        store.add_service(ServiceEntity(host_id=h1, port=22, service_name="ssh"))

        port_80 = store.get_services_by_port(80)
        assert len(port_80) == 2

        port_22 = store.get_services_by_port(22)
        assert len(port_22) == 1

    def test_service_foreign_key_enforced(self, store):
        """FOREIGN KEY constraint should prevent adding a service with invalid host_id."""
        with pytest.raises(Exception):
            store.add_service(ServiceEntity(host_id="nonexistent", port=80))


# ── Credential CRUD ────────────────────────────────────────────


class TestCredentialCRUD:
    def test_add_and_get_credential(self, store):
        cred = CredentialEntity(username="admin", credential_type="password", credential_value="P@ssw0rd")
        cred_id = store.add_credential(cred)

        retrieved = store.get_credential(cred_id)
        assert retrieved is not None
        assert retrieved.username == "admin"
        assert retrieved.credential_value == "P@ssw0rd"

    def test_get_credentials_empty(self, store):
        assert store.get_credentials() == []

    def test_credential_valid_for_json(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.0.0.1"))
        cred = CredentialEntity(username="root", valid_for=[host_id])
        store.add_credential(cred)

        retrieved = store.get_credential(cred.id)
        assert retrieved.valid_for == [host_id]

    def test_get_credentials_for_host(self, store):
        h1 = store.add_host(HostEntity(ip_address="10.0.0.1"))
        h2 = store.add_host(HostEntity(ip_address="10.0.0.2"))

        store.add_credential(CredentialEntity(username="admin", valid_for=[h1]))
        store.add_credential(CredentialEntity(username="root", valid_for=[h1, h2]))
        store.add_credential(CredentialEntity(username="guest", valid_for=[h2]))

        creds_h1 = store.get_credentials_for_host(h1)
        assert len(creds_h1) == 2
        assert {c.username for c in creds_h1} == {"admin", "root"}

        creds_h2 = store.get_credentials_for_host(h2)
        assert len(creds_h2) == 2
        assert {c.username for c in creds_h2} == {"root", "guest"}


# ── Session CRUD ───────────────────────────────────────────────


class TestSessionCRUD:
    def test_add_and_get_session(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.0.0.1"))
        session = SessionEntity(host_id=host_id, session_type="shell", privilege_level="user")
        session_id = store.add_session(session)

        retrieved = store.get_session(session_id)
        assert retrieved is not None
        assert retrieved.session_type == "shell"
        assert retrieved.privilege_level == "user"
        assert retrieved.active is True

    def test_get_active_sessions(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.0.0.1"))
        store.add_session(SessionEntity(host_id=host_id, active=True))
        store.add_session(SessionEntity(host_id=host_id, active=False))
        store.add_session(SessionEntity(host_id=host_id, active=True))

        active = store.get_active_sessions()
        assert len(active) == 2
        assert all(s.active for s in active)


# ── Vulnerability CRUD ─────────────────────────────────────────


class TestVulnerabilityCRUD:
    def test_add_and_get_vulnerability(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.0.0.1"))
        vuln = VulnerabilityEntity(
            host_id=host_id,
            cve_id="CVE-2026-23744",
            description="MCPJam Inspector RCE",
            exploitation_status="discovered",
        )
        vuln_id = store.add_vulnerability(vuln)

        retrieved = store.get_vulnerability(vuln_id)
        assert retrieved is not None
        assert retrieved.cve_id == "CVE-2026-23744"
        assert retrieved.description == "MCPJam Inspector RCE"

    def test_get_vulnerabilities_for_host(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.129.245.50"))
        store.add_vulnerability(VulnerabilityEntity(host_id=host_id, cve_id="CVE-2026-23744"))
        store.add_vulnerability(VulnerabilityEntity(host_id=host_id, cve_id="CVE-2026-23944"))
        store.add_vulnerability(VulnerabilityEntity(host_id=host_id, cve_id="CVE-2026-23520"))

        vulns = store.get_vulnerabilities_for_host(host_id)
        assert len(vulns) == 3
        cves = {v.cve_id for v in vulns}
        assert cves == {"CVE-2026-23744", "CVE-2026-23944", "CVE-2026-23520"}

    def test_vulnerability_with_service_id(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.0.0.1"))
        svc_id = store.add_service(ServiceEntity(host_id=host_id, port=3552))
        vuln = VulnerabilityEntity(host_id=host_id, service_id=svc_id, cve_id="CVE-2026-23520")
        store.add_vulnerability(vuln)

        retrieved = store.get_vulnerability(vuln.id)
        assert retrieved.service_id == svc_id


# ── Serialization ──────────────────────────────────────────────


class TestSerialization:
    def test_to_dict_and_from_dict(self, store):
        host_id = store.add_host(HostEntity(ip_address="10.129.245.50", hostname="kobold.htb"))
        store.add_service(ServiceEntity(host_id=host_id, port=22, service_name="ssh"))
        store.add_service(ServiceEntity(host_id=host_id, port=80, service_name="http"))
        store.add_credential(CredentialEntity(username="ben", valid_for=[host_id]))
        store.add_vulnerability(VulnerabilityEntity(host_id=host_id, cve_id="CVE-2026-23744"))

        data = store.to_dict()
        assert len(data["hosts"]) == 1
        assert len(data["services"]) == 2
        assert len(data["credentials"]) == 1
        assert len(data["vulnerabilities"]) == 1

        # Restore from dict into a new store
        store2 = StateStore.from_dict(data)
        assert len(store2.get_hosts()) == 1
        assert store2.get_host_by_ip("10.129.245.50").hostname == "kobold.htb"
        assert len(store2.get_services_for_host(host_id)) == 2
        assert len(store2.get_credentials()) == 1
        assert len(store2.get_vulnerabilities_for_host(host_id)) == 1
        store2.close()

    def test_to_dict_empty(self, store):
        data = store.to_dict()
        assert data == {
            "hosts": [],
            "services": [],
            "credentials": [],
            "sessions": [],
            "vulnerabilities": [],
        }


# ── Real-world scenario (kobold.htb) ──────────────────────────


class TestKoboldScenario:
    """End-to-end test simulating kobold.htb data flow."""

    def test_full_kobold_scenario(self, store):
        # 1. Nmap discovers host and 4 services
        host_id = store.add_host(HostEntity(ip_address="10.129.245.50", hostname="kobold.htb"))
        store.add_service(ServiceEntity(host_id=host_id, port=22, service_name="ssh", version="OpenSSH 9.6p1"))
        store.add_service(ServiceEntity(host_id=host_id, port=80, service_name="http", version="nginx 1.24.0"))
        store.add_service(ServiceEntity(host_id=host_id, port=443, service_name="ssl/https", version="nginx 1.24.0"))
        store.add_service(ServiceEntity(host_id=host_id, port=3552, service_name="http", version="Golang net/http"))

        assert len(store.get_services_for_host(host_id)) == 4

        # 2. Nuclei discovers vulnerabilities
        store.add_vulnerability(VulnerabilityEntity(
            host_id=host_id, cve_id="CVE-2026-23744",
            description="MCPJam Inspector RCE", exploitation_status="discovered",
        ))
        store.add_vulnerability(VulnerabilityEntity(
            host_id=host_id, cve_id="CVE-2026-23944",
            description="Arcane Auth Bypass", exploitation_status="discovered",
        ))

        vulns = store.get_vulnerabilities_for_host(host_id)
        assert len(vulns) == 2

        # 3. Verify state summary generation data
        hosts = store.get_hosts()
        assert len(hosts) == 1
        host = hosts[0]
        services = store.get_services_for_host(host.id)
        svc_str = ", ".join(f"{s.port}/{s.service_name}" for s in services)
        expected = "22/ssh, 80/http, 443/ssl/https, 3552/http"
        assert svc_str == expected

        # 4. Verify serialization roundtrip preserves all data
        data = store.to_dict()
        store2 = StateStore.from_dict(data)
        assert len(store2.get_hosts()) == 1
        assert len(store2.get_services_for_host(host_id)) == 4
        assert len(store2.get_vulnerabilities_for_host(host_id)) == 2
        store2.close()
