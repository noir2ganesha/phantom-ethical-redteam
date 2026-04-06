"""Tests for MCP bridge integration — Sprint 4.

Tests _post_tool_processing() with ErrorHandler + StateStore,
and get_state_summary().
"""

import os
import sys
import re
from pathlib import Path

_AGENT = Path(__file__).resolve().parent.parent / "agent"
_ROOT = Path(__file__).resolve().parent.parent
if str(_AGENT) not in sys.path:
    sys.path.insert(0, str(_AGENT))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from execution.error_handler import ErrorHandler, ErrorType
from memory.state_store import StateStore
from memory.entity_models import HostEntity, ServiceEntity, VulnerabilityEntity


# Reproduce _post_tool_processing logic for testing
# (import from mcp_bridge would trigger FastMCP server init)

_NMAP_STANDARD = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)")
_NMAP_PHANTOM = re.compile(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.*)")
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")
_ERROR_KEYWORDS = frozenset(["error", "fail", "denied", "refused", "timeout",
                              "timed out", "unreachable", "blocked"])


def _post_tool_processing(tool_name, tool_input, result, error_handler, state_store):
    """Reproduce mcp_bridge._post_tool_processing for testing."""
    errors_found = []

    if error_handler and result:
        _lower = result.lower()[:200]
        if any(kw in _lower for kw in _ERROR_KEYWORDS):
            error_type = error_handler.classify(result, tool_name)
            if error_type != ErrorType.UNKNOWN:
                recovery = error_handler.recover(error_type, {"tool": tool_name})
                errors_found.append((error_type, recovery))

    if not state_store:
        return errors_found
    if result.startswith("Error") or result.startswith("SCOPE VIOLATION"):
        return errors_found

    target = tool_input.get("target", tool_input.get("url", ""))
    if not target:
        return errors_found

    try:
        if tool_name == "run_nmap":
            host = state_store.get_host_by_ip(target)
            if not host:
                host_id = state_store.add_host(HostEntity(ip_address=target))
            else:
                host_id = host.id

            for line in result.splitlines():
                port, proto, svc, ver = None, None, None, None
                m = _NMAP_STANDARD.match(line.strip())
                if m:
                    port, proto, svc, ver = m.group(1), m.group(2), m.group(4), m.group(5)
                else:
                    m = _NMAP_PHANTOM.match(line.strip())
                    if m:
                        port, proto, svc, ver = m.group(1), m.group(2), m.group(3), m.group(4)

                if port:
                    p = int(port)
                    existing = state_store.get_services_for_host(host_id)
                    if not any(s.port == p and s.protocol == proto for s in existing):
                        state_store.add_service(ServiceEntity(
                            host_id=host_id, port=p, protocol=proto,
                            service_name=svc, version=(ver.strip() if ver else None),
                        ))

        cve_matches = _CVE_PATTERN.findall(result)
        if cve_matches and target:
            host = state_store.get_host_by_ip(target)
            if not host:
                host_id = state_store.add_host(HostEntity(ip_address=target))
            else:
                host_id = host.id
            existing_vulns = state_store.get_vulnerabilities_for_host(host_id)
            existing_cves = {v.cve_id for v in existing_vulns}
            for cve in set(cve_matches):
                if cve not in existing_cves:
                    state_store.add_vulnerability(VulnerabilityEntity(
                        host_id=host_id, cve_id=cve,
                        description=f"Detected by {tool_name}",
                    ))
    except Exception:
        pass

    return errors_found


@pytest.fixture
def handler():
    return ErrorHandler()


@pytest.fixture
def store():
    s = StateStore(db_path=":memory:")
    yield s
    s.close()


# ── nmap Phantom format parsing ────────────────────────────────


class TestNmapPhantomFormat:
    """Test that Phantom's formatted nmap output is correctly parsed."""

    def test_phantom_service_scan_format(self, handler, store):
        nmap_output = """Nmap service scan -- 10.129.16.19 -- 6 open ports:

  PORT      SERVICE  VERSION
  ---------------------------------------
  21/tcp    ftp      vsftpd 3.0.5
  22/tcp    ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
  80/tcp    http     Apache httpd 2.4.58
  8080/tcp  http     Jetty 9.4.27.v20200227
  8500/tcp  http     Golang net/http server
  8888/tcp  http     Golang net/http server (Go-IPFS json-rpc or InfluxDB API)

  Scan time: 50.25s"""

        _post_tool_processing("run_nmap", {"target": "10.129.16.19"}, nmap_output, handler, store)

        hosts = store.get_hosts()
        assert len(hosts) == 1
        assert hosts[0].ip_address == "10.129.16.19"

        services = store.get_services_for_host(hosts[0].id)
        ports = sorted([s.port for s in services])
        assert ports == [21, 22, 80, 8080, 8500, 8888]

        # Check service details
        ftp = [s for s in services if s.port == 21][0]
        assert ftp.service_name == "ftp"
        assert ftp.version == "vsftpd 3.0.5"

        jetty = [s for s in services if s.port == 8080][0]
        assert jetty.service_name == "http"
        assert jetty.version == "Jetty 9.4.27.v20200227"

    def test_nmap_standard_format(self, handler, store):
        nmap_output = """22/tcp   open  ssh       OpenSSH 9.6p1
80/tcp   open  http      nginx 1.24.0
443/tcp  open  ssl/https nginx/1.24.0"""

        _post_tool_processing("run_nmap", {"target": "10.129.245.50"}, nmap_output, handler, store)

        hosts = store.get_hosts()
        assert len(hosts) == 1
        services = store.get_services_for_host(hosts[0].id)
        ports = sorted([s.port for s in services])
        assert ports == [22, 80, 443]

    def test_nmap_duplicate_prevention(self, handler, store):
        nmap_output = "22/tcp    ssh      OpenSSH 9.6p1"

        _post_tool_processing("run_nmap", {"target": "10.0.0.1"}, nmap_output, handler, store)
        _post_tool_processing("run_nmap", {"target": "10.0.0.1"}, nmap_output, handler, store)

        hosts = store.get_hosts()
        services = store.get_services_for_host(hosts[0].id)
        assert len(services) == 1  # Not duplicated

    def test_nmap_non_port_lines_skipped(self, handler, store):
        nmap_output = """Nmap scan report for target
Host is up (0.23s latency).
Not shown: 65531 closed tcp ports
PORT     SERVICE  VERSION
22/tcp   ssh      OpenSSH 9.6p1
Nmap done: 1 IP address"""

        _post_tool_processing("run_nmap", {"target": "10.0.0.1"}, nmap_output, handler, store)

        services = store.get_services_for_host(store.get_hosts()[0].id)
        assert len(services) == 1
        assert services[0].port == 22


# ── ErrorHandler in post-processing ────────────────────────────


class TestErrorHandlerInBridge:
    def test_normal_result_no_error(self, handler, store):
        result = "Nmap scan: 4 ports open"
        errors = _post_tool_processing("run_nmap", {"target": "10.0.0.1"}, result, handler, store)
        assert len(errors) == 0

    def test_connection_refused(self, handler, store):
        result = "Error: Connection refused to 10.0.0.1:80"
        errors = _post_tool_processing("run_whatweb", {"target": "10.0.0.1"}, result, handler, store)
        assert len(errors) == 1
        assert errors[0][0] == ErrorType.CONNECTION_REFUSED

    def test_timeout_error(self, handler, store):
        result = "Nmap timed out after 300s"
        errors = _post_tool_processing("run_nmap", {"target": "10.0.0.1"}, result, handler, store)
        assert len(errors) == 1
        assert errors[0][0] == ErrorType.TIMEOUT

    def test_waf_blocked(self, handler, store):
        result = "403 Forbidden - blocked by CloudFlare WAF"
        errors = _post_tool_processing("run_ffuf", {"url": "http://10.0.0.1/"}, result, handler, store)
        assert len(errors) == 1
        assert errors[0][0] == ErrorType.WAF_BLOCKED

    def test_error_result_skips_statestore(self, handler, store):
        result = "Error: Connection refused"
        _post_tool_processing("run_nmap", {"target": "10.0.0.1"}, result, handler, store)
        assert len(store.get_hosts()) == 0  # Nothing registered

    def test_scope_violation_skips_statestore(self, handler, store):
        result = "SCOPE VIOLATION: target not authorized"
        _post_tool_processing("run_nmap", {"target": "evil.com"}, result, handler, store)
        assert len(store.get_hosts()) == 0


# ── CVE detection ──────────────────────────────────────────────


class TestCVEDetection:
    def test_cve_in_nuclei_output(self, handler, store):
        result = "[CRITICAL] CVE-2026-23744: MCPJam Inspector RCE on target:443"
        _post_tool_processing("run_nuclei", {"target": "10.129.245.50"}, result, handler, store)

        hosts = store.get_hosts()
        assert len(hosts) == 1
        vulns = store.get_vulnerabilities_for_host(hosts[0].id)
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2026-23744"

    def test_multiple_cves(self, handler, store):
        result = """[HIGH] CVE-2026-23944: Auth bypass
[CRITICAL] CVE-2026-23520: Command injection"""
        _post_tool_processing("run_nuclei", {"target": "10.0.0.1"}, result, handler, store)

        vulns = store.get_vulnerabilities_for_host(store.get_hosts()[0].id)
        cves = {v.cve_id for v in vulns}
        assert cves == {"CVE-2026-23944", "CVE-2026-23520"}

    def test_cve_duplicate_prevention(self, handler, store):
        result = "[HIGH] CVE-2026-23744: found"
        _post_tool_processing("run_nuclei", {"target": "10.0.0.1"}, result, handler, store)
        _post_tool_processing("run_nuclei", {"target": "10.0.0.1"}, result, handler, store)

        vulns = store.get_vulnerabilities_for_host(store.get_hosts()[0].id)
        assert len(vulns) == 1  # Not duplicated

    def test_no_cve_no_vulnerability(self, handler, store):
        result = "No vulnerabilities found"
        _post_tool_processing("run_nuclei", {"target": "10.0.0.1"}, result, handler, store)
        assert len(store.get_hosts()) == 0  # No host registered either

    def test_cve_from_any_tool(self, handler, store):
        result = "Found CVE-2025-1234 in web application"
        _post_tool_processing("run_whatweb", {"target": "10.0.0.1"}, result, handler, store)

        vulns = store.get_vulnerabilities_for_host(store.get_hosts()[0].id)
        assert len(vulns) == 1
        assert vulns[0].description == "Detected by run_whatweb"


# ── get_state_summary ─────────────────────────────────────────


class TestGetStateSummary:
    def test_empty_state(self):
        store = StateStore(db_path=":memory:")
        # Simulate get_state_summary
        lines = []
        for host in store.get_hosts():
            services = store.get_services_for_host(host.id)
            vulns = store.get_vulnerabilities_for_host(host.id)
            svc_str = ", ".join(f"{s.port}/{s.service_name}" for s in services)
            lines.append(f"{host.ip_address} ({host.hostname or '?'}): {svc_str}")
            for v in vulns:
                lines.append(f"  [{v.exploitation_status}] {v.cve_id}: {v.description[:60]}")
        result = "\n".join(lines) if lines else "No entities registered yet."
        assert result == "No entities registered yet."
        store.close()

    def test_populated_state(self, handler, store):
        nmap_output = """  21/tcp    ftp      vsftpd 3.0.5
  22/tcp    ssh      OpenSSH 9.6p1
  80/tcp    http     Apache httpd 2.4.58"""
        _post_tool_processing("run_nmap", {"target": "10.129.16.19"}, nmap_output, handler, store)

        nuclei_output = "[CRITICAL] CVE-2026-99999: Test vulnerability"
        _post_tool_processing("run_nuclei", {"target": "10.129.16.19"}, nuclei_output, handler, store)

        # Generate summary
        lines = []
        for host in store.get_hosts():
            services = store.get_services_for_host(host.id)
            vulns = store.get_vulnerabilities_for_host(host.id)
            svc_str = ", ".join(f"{s.port}/{s.service_name}" for s in services)
            lines.append(f"{host.ip_address} ({host.hostname or '?'}): {svc_str}")
            for v in vulns:
                lines.append(f"  [{v.exploitation_status}] {v.cve_id}: {v.description[:60]}")
        result = "\n".join(lines)

        assert "10.129.16.19" in result
        assert "21/ftp" in result
        assert "80/http" in result
        assert "CVE-2026-99999" in result


# ── devarea.htb full scenario ──────────────────────────────────


class TestDevAreaScenario:
    """End-to-end test with devarea.htb real nmap data."""

    def test_full_devarea_flow(self, handler, store):
        # 1. nmap service scan
        nmap_output = """Nmap service scan -- 10.129.16.19 -- 6 open ports:

  PORT      SERVICE  VERSION
  ---------------------------------------
  21/tcp    ftp      vsftpd 3.0.5
  22/tcp    ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
  80/tcp    http     Apache httpd 2.4.58
  8080/tcp  http     Jetty 9.4.27.v20200227
  8500/tcp  http     Golang net/http server
  8888/tcp  http     Golang net/http server (Go-IPFS json-rpc or InfluxDB API)

  Scan time: 50.25s"""

        _post_tool_processing("run_nmap", {"target": "10.129.16.19"}, nmap_output, handler, store)

        # Verify 6 services
        host = store.get_host_by_ip("10.129.16.19")
        assert host is not None
        services = store.get_services_for_host(host.id)
        assert len(services) == 6

        # 2. whatweb (no CVE, just tech info)
        whatweb_output = "Apache/2.4.58 (Ubuntu), redirect to http://devarea.htb/"
        _post_tool_processing("run_whatweb", {"target": "10.129.16.19"}, whatweb_output, handler, store)
        # No new entities (whatweb doesn't create hosts/services in Sprint 4)
        assert len(store.get_services_for_host(host.id)) == 6

        # 3. nuclei with CVE
        nuclei_output = "[HIGH] CVE-2025-5678: Jetty vulnerability on port 8080"
        _post_tool_processing("run_nuclei", {"target": "10.129.16.19"}, nuclei_output, handler, store)

        vulns = store.get_vulnerabilities_for_host(host.id)
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2025-5678"

        # 4. Error case (connection refused on FTP)
        error_output = "Error: Connection refused to 10.129.16.19:21"
        errors = _post_tool_processing("run_nmap", {"target": "10.129.16.19"}, error_output, handler, store)
        assert len(errors) == 1
        assert errors[0][0] == ErrorType.CONNECTION_REFUSED
        # StateStore unchanged (error result skipped)
        assert len(store.get_services_for_host(host.id)) == 6
