#!/usr/bin/env python3
"""Phantom MCP Bridge — routes Claude Code CLI tool calls through Phantom's
tool suite with ErrorHandler classification and StateStore entity registration.

Sprint 4: Integrated ErrorHandler (Sprint 1) and StateStore (Sprint 2) into
the MCP bridge so that every tool execution is automatically:
  1. Classified by ErrorHandler (error type + recovery suggestion logged)
  2. Registered to StateStore (Host/Service/Vulnerability entities)

The bridge remains a thin layer — all tool logic stays in Phantom's tools/.
"""

import functools
import inspect
import logging
import os
import re
import sys

# Ensure Phantom's agent/ directory is importable
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "agent"))
sys.path.insert(0, _PROJECT_ROOT)

from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("phantom.mcp_bridge")

# Import Phantom tool registry
from tools import TOOL_REGISTRY, TOOL_SPECS

# ---------------------------------------------------------------------------
# ErrorHandler (Sprint 1) — classify tool errors automatically
# ---------------------------------------------------------------------------
try:
    from execution.error_handler import ErrorHandler, ErrorType

    _error_handler = ErrorHandler()
    logger.info("ErrorHandler loaded")
except Exception as exc:
    logger.warning("ErrorHandler not available: %s", exc)
    _error_handler = None
    ErrorType = None

# ---------------------------------------------------------------------------
# StateStore (Sprint 2) — register discovered entities automatically
# ---------------------------------------------------------------------------
try:
    from memory.state_store import StateStore
    from memory.entity_models import HostEntity, ServiceEntity, VulnerabilityEntity

    PHANTOM_DIR = os.path.expanduser("~/.phantom")
    os.makedirs(PHANTOM_DIR, exist_ok=True)
    _state_store = StateStore(db_path=os.path.join(PHANTOM_DIR, "state_store.db"))
    logger.info("StateStore loaded: %s", os.path.join(PHANTOM_DIR, "state_store.db"))
except Exception as exc:
    logger.warning("StateStore not available: %s", exc)
    _state_store = None

# ---------------------------------------------------------------------------
# EGATS Planner (Sprint 7) — attack tree management in MCP bridge
# ---------------------------------------------------------------------------
try:
    from planner.egats import EGATSPlanner
    from planner.models import ActionOutcome, AttackTree, AttackNode

    _egats_planner = EGATSPlanner()
    _egats_tree: AttackTree | None = None  # initialized on first tool call with a target
    _egats_current_node: AttackNode | None = None
    logger.info("EGATSPlanner loaded")
except Exception as exc:
    logger.warning("EGATSPlanner not available: %s", exc)
    _egats_planner = None
    _egats_tree = None
    _egats_current_node = None
    ActionOutcome = None

# ErrorType → ActionOutcome mapping
_ERROR_TO_OUTCOME: dict = {}
if ErrorType and ActionOutcome:
    _ERROR_TO_OUTCOME = {
        ErrorType.TIMEOUT: ActionOutcome.PARTIAL,
        ErrorType.AUTHENTICATION_FAILED: ActionOutcome.FAILURE,
        ErrorType.WAF_BLOCKED: ActionOutcome.FAILURE,
        ErrorType.CONNECTION_REFUSED: ActionOutcome.FAILURE,
        ErrorType.TOOL_NOT_FOUND: ActionOutcome.FAILURE,
        ErrorType.PERMISSION_DENIED: ActionOutcome.FAILURE,
        ErrorType.DNS_RESOLUTION_FAILED: ActionOutcome.FAILURE,
        ErrorType.SSL_CERTIFICATE_ERROR: ActionOutcome.PARTIAL,
        ErrorType.RATE_LIMITED: ActionOutcome.PARTIAL,
        ErrorType.SERVICE_UNAVAILABLE: ActionOutcome.PARTIAL,
        ErrorType.AD_KERBEROS_ERROR: ActionOutcome.FAILURE,
        ErrorType.AMSI_DETECTED: ActionOutcome.FAILURE,
    }


def _ensure_egats_tree(target: str) -> None:
    """Initialize EGATS tree on first tool call with a target."""
    global _egats_tree, _egats_current_node
    if not _egats_planner:
        return
    if _egats_tree is None:
        _egats_tree = _egats_planner.init_tree(target)
        _egats_current_node = _egats_planner.select_next_node(_egats_tree)
        logger.info("EGATS tree initialized for target: %s", target)


def _egats_backpropagate(tool_name: str, result: str, error_type=None) -> None:
    """Backpropagate tool execution outcome to EGATS tree."""
    global _egats_current_node
    if not _egats_planner or not _egats_tree or not _egats_current_node:
        return

    # Determine outcome
    if error_type and error_type in _ERROR_TO_OUTCOME:
        outcome = _ERROR_TO_OUTCOME[error_type]
    elif result.startswith("Error") or result.startswith("SCOPE VIOLATION"):
        outcome = ActionOutcome.FAILURE
    else:
        outcome = ActionOutcome.SUCCESS

    # Backpropagate
    _egats_planner.backpropagate(_egats_tree, _egats_current_node, outcome)
    _egats_tree.total_actions += 1

    # Compute TDI and check pruning
    tdi = _egats_planner.compute_tdi(_egats_current_node, _egats_tree, 0.0)
    _egats_current_node.tdi = tdi
    pruned = _egats_planner.check_pruning(_egats_tree)
    if pruned:
        logger.info("EGATS pruned %d nodes: %s", len(pruned), pruned)

    # Select next node for future tool calls
    _egats_current_node = _egats_planner.select_next_node(_egats_tree)
    if _egats_current_node:
        mode = _egats_planner.select_mode(tdi)
        logger.info(
            "EGATS: %s → %s (promise=%.3f, TDI=%.3f, mode=%s)",
            tool_name,
            outcome.name,
            _egats_current_node.promise_score,
            tdi.value,
            mode,
        )


# ---------------------------------------------------------------------------
# Post-tool processing: ErrorHandler + StateStore (3-layer extraction)
# ---------------------------------------------------------------------------

# Layer 1: Universal patterns (applied to ALL tool outputs)
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")
_FQDN_PATTERN = re.compile(r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z0-9-]+\.)*[a-zA-Z]{2,})\b")

_ERROR_KEYWORDS = frozenset(["error", "fail", "denied", "refused", "timeout",
                              "timed out", "unreachable", "blocked"])

# Layer 2: Tool-specific rules (declarative — add entry for new tools)
_STATESTORE_RULES: dict[str, dict] = {
    "run_nmap": {
        "register_host": True,
        "service_patterns": [
            re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)"),   # nmap standard
            re.compile(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.*)"),                      # Phantom formatted
        ],
    },
    "run_ffuf": {
        "register_host": True,
        "vhost_extraction": True,
    },
    "run_whatweb": {
        "register_host": True,
    },
    "run_nuclei": {
        "register_host": True,
    },
    "run_recon": {
        "register_host": True,
        "fqdn_as_hosts": True,
    },
    "run_sqlmap": {
        "register_host": True,
    },
    "run_wpscan": {
        "register_host": True,
    },
    "run_graphql_enum": {
        "register_host": True,
    },
    "run_hydra": {
        "register_host": True,
        "credential_pattern": re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)"),
    },
    # Tools not listed here → Layer 1 only (CVE + FQDN universal extraction)
}


def _ensure_host(target: str) -> str:
    """Ensure a host exists in StateStore, return host_id."""
    host = _state_store.get_host_by_ip(target)
    if host:
        return host.id
    host = _state_store.get_host_by_hostname(target)
    if host:
        return host.id
    # Determine if target is IP or hostname
    if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", target):
        return _state_store.add_host(HostEntity(ip_address=target))
    else:
        return _state_store.add_host(HostEntity(ip_address="", hostname=target))


def _extract_services(result: str, host_id: str, patterns: list) -> None:
    """Extract services from tool output using pattern list."""
    for line in result.splitlines():
        stripped = line.strip()
        for pattern in patterns:
            m = pattern.match(stripped)
            if m:
                groups = m.groups()
                if len(groups) >= 4:
                    # Standard: port, proto, state, svc, ver
                    port, proto, svc, ver = int(groups[0]), groups[1], groups[3], groups[4] if len(groups) > 4 else ""
                elif len(groups) >= 3:
                    # Phantom: port, proto, svc, ver
                    port, proto, svc, ver = int(groups[0]), groups[1], groups[2], groups[3] if len(groups) > 3 else ""
                else:
                    continue
                existing = _state_store.get_services_for_host(host_id)
                if not any(s.port == port and s.protocol == proto for s in existing):
                    _state_store.add_service(ServiceEntity(
                        host_id=host_id, port=port, protocol=proto,
                        service_name=svc, version=(ver.strip() if ver else None),
                    ))
                break  # First matching pattern wins


def _extract_vhosts(result: str, tool_input: dict) -> None:
    """Extract vhost subdomains from ffuf output and register as Hosts."""
    url = tool_input.get("url", "")
    # Extract base domain from FUZZ URL (e.g., "https://FUZZ.kobold.htb/" → "kobold.htb")
    base_match = re.search(r"FUZZ\.([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", url)
    if not base_match:
        return
    base_domain = base_match.group(1)

    # ffuf output lines: "subdomain [Status: 200, Size: 1234]"
    for line in result.splitlines():
        vhost_match = re.match(r"\s*(\S+)\s+\[Status:\s*(\d+)", line.strip())
        if vhost_match:
            label = vhost_match.group(1)
            status = int(vhost_match.group(2))
            if status < 400:
                fqdn = f"{label}.{base_domain}"
                if not _state_store.get_host_by_hostname(fqdn):
                    _state_store.add_host(HostEntity(ip_address="", hostname=fqdn))
                    logger.info("StateStore: vhost registered: %s", fqdn)


def _extract_cves(result: str, host_id: str) -> None:
    """Layer 1: Extract CVE IDs from any tool output."""
    cve_matches = _CVE_PATTERN.findall(result)
    if not cve_matches:
        return
    existing_vulns = _state_store.get_vulnerabilities_for_host(host_id)
    existing_cves = {v.cve_id for v in existing_vulns}
    for cve in set(cve_matches):
        if cve not in existing_cves:
            _state_store.add_vulnerability(VulnerabilityEntity(
                host_id=host_id, cve_id=cve, description=f"Detected in tool output",
            ))


def _extract_fqdns(result: str) -> None:
    """Layer 1: Extract FQDNs from any tool output and register as Hosts."""
    fqdns = _FQDN_PATTERN.findall(result)
    # Filter out common false positives (tool names, doc sites, etc.)
    skip = {"example.com", "localhost", "nmap.org", "github.com", "exploit-db.com",
            "crt.sh", "hackertarget.com", "securitytrails.com", "shodan.io",
            "owasp.org", "wikipedia.org", "google.com", "anthropic.com"}
    for fqdn in set(fqdns):
        if fqdn.lower() in skip:
            continue
        if not _state_store.get_host_by_hostname(fqdn):
            _state_store.add_host(HostEntity(ip_address="", hostname=fqdn))


def _extract_credentials(result: str, host_id: str, pattern: re.Pattern) -> None:
    """Extract credentials from tool output."""
    from memory.entity_models import CredentialEntity
    for m in pattern.finditer(result):
        username, password = m.group(1), m.group(2)
        _state_store.add_credential(CredentialEntity(
            username=username, credential_type="password",
            credential_value=password, valid_for=[host_id],
        ))


def _post_tool_processing(tool_name: str, tool_input: dict, result: str) -> None:
    """Run ErrorHandler classification and StateStore registration after tool execution.

    Uses 3-layer extraction architecture:
    Layer 1: Universal (CVE + FQDN) — applied to all tools
    Layer 2: Tool-specific rules from _STATESTORE_RULES
    Layer 3: Findings-based (handled upstream by existing code)
    """

    # --- ErrorHandler ---
    _detected_error_type = None
    if _error_handler and result:
        _lower = result.lower()[:200]
        if any(kw in _lower for kw in _ERROR_KEYWORDS):
            _detected_error_type = _error_handler.classify(result, tool_name)
            if _detected_error_type != ErrorType.UNKNOWN:
                recovery = _error_handler.recover(_detected_error_type, {"tool": tool_name})
                logger.info(
                    "ErrorHandler: %s -> %s: %s",
                    _detected_error_type.value,
                    recovery.action.value,
                    recovery.suggestion,
                )
            else:
                _detected_error_type = None  # UNKNOWN means no real error

    # --- EGATS backpropagation (Sprint 7) ---
    target = tool_input.get("target", tool_input.get("url", ""))
    if target:
        _ensure_egats_tree(target)
    _egats_backpropagate(tool_name, result, _detected_error_type)

    # --- StateStore (3-layer extraction) ---
    if not _state_store:
        return
    if result.startswith("Error") or result.startswith("SCOPE VIOLATION"):
        return

    target = tool_input.get("target", tool_input.get("url", ""))

    try:
        rules = _STATESTORE_RULES.get(tool_name, {})

        # Layer 2: register_host
        host_id = None
        if target and rules.get("register_host"):
            host_id = _ensure_host(target)

        # Layer 2: service_patterns (nmap etc.)
        if host_id and rules.get("service_patterns"):
            _extract_services(result, host_id, rules["service_patterns"])

        # Layer 2: vhost_extraction (ffuf)
        if rules.get("vhost_extraction"):
            _extract_vhosts(result, tool_input)

        # Layer 2: credential_pattern (hydra etc.)
        if host_id and rules.get("credential_pattern"):
            _extract_credentials(result, host_id, rules["credential_pattern"])

        # Layer 2: fqdn_as_hosts (recon — register all FQDNs as hosts)
        if rules.get("fqdn_as_hosts"):
            _extract_fqdns(result)

        # Layer 1: Universal CVE extraction (all tools)
        if target:
            if not host_id:
                host_id = _ensure_host(target)
            _extract_cves(result, host_id)

    except Exception as exc:
        logger.debug("StateStore registration failed: %s", exc)


# ---------------------------------------------------------------------------
# get_state_summary — new MCP tool for querying StateStore
# ---------------------------------------------------------------------------

def get_state_summary() -> str:
    """Return current StateStore state: hosts, services, vulnerabilities discovered so far."""
    if not _state_store:
        return "StateStore is not available."
    lines = []
    for host in _state_store.get_hosts():
        services = _state_store.get_services_for_host(host.id)
        vulns = _state_store.get_vulnerabilities_for_host(host.id)
        svc_str = ", ".join(f"{s.port}/{s.service_name}" for s in services)
        lines.append(f"{host.ip_address} ({host.hostname or '?'}): {svc_str}")
        for v in vulns:
            lines.append(f"  [{v.exploitation_status}] {v.cve_id}: {v.description[:60]}")
    return "\n".join(lines) if lines else "No entities registered yet."


# ---------------------------------------------------------------------------
# generate_hypotheses — 4-layer hypothesis generation (Sprint 6)
# ---------------------------------------------------------------------------

try:
    from reasoning.hypothesis_engine import HypothesisEngine as _HypothesisEngine

    _hypothesis_engine = _HypothesisEngine()
    logger.info("HypothesisEngine loaded (4-layer: rule/output/rag/llm)")
except Exception as exc:
    logger.warning("HypothesisEngine not available: %s", exc)
    _hypothesis_engine = None


def generate_hypotheses() -> str:
    """Generate attack hypotheses based on current StateStore state.

    Uses 4-layer hypothesis generation:
    Layer 1 (Rule): port/service rules + PRODUCT_CATALOG (18+ products)
                    + SSRF_HOSTNAME_PATTERNS (9 categories, 70+ patterns)
    Layer 2 (Output): tool output pattern matching
    Layer 3 (RAG): stub (future Sprint 11)
    Layer 4 (LLM): stub (not available in MCP bridge mode)
    """
    if not _hypothesis_engine:
        return "HypothesisEngine is not available."
    if not _state_store:
        return "StateStore is empty. Run reconnaissance tools first."

    hosts = _state_store.get_hosts()
    if not hosts:
        return "No hosts discovered yet. Run run_nmap first."

    # Build context from StateStore
    services_list = []
    domains_list = []
    for host in hosts:
        for svc in _state_store.get_services_for_host(host.id):
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

    try:
        hypotheses = _hypothesis_engine.generate_hypotheses(context)
    except Exception as exc:
        logger.error("Hypothesis generation failed: %s", exc)
        return f"Hypothesis generation failed: {exc}"

    if not hypotheses:
        return "No hypotheses generated. More reconnaissance data may be needed."

    lines = [f"Generated {len(hypotheses)} hypotheses:"]
    for i, h in enumerate(hypotheses, 1):
        lines.append(f"  {i}. [{h.confidence:.2f}] {h.description}")
        if h.verification_method:
            lines.append(f"     verify: {h.verification_method[:80]}")

    # Append EGATS attack tree status (Sprint 7)
    if _egats_tree and _egats_planner:
        lines.append("")
        lines.append("EGATS attack tree status:")
        total = len(_egats_tree.nodes)
        from planner.models import NodeStatus
        active = sum(1 for n in _egats_tree.nodes.values() if n.status not in (NodeStatus.PRUNED, NodeStatus.FAILED))
        pruned = sum(1 for n in _egats_tree.nodes.values() if n.status == NodeStatus.PRUNED)
        lines.append(f"  Nodes: {total} total, {active} active, {pruned} pruned")
        lines.append(f"  Actions: {_egats_tree.total_actions}")
        if _egats_current_node:
            tdi = _egats_planner.compute_tdi(_egats_current_node, _egats_tree, 0.0)
            mode = _egats_planner.select_mode(tdi)
            lines.append(f"  Current: {_egats_current_node.description[:60]}")
            lines.append(f"  TDI: {tdi.value:.3f}, Mode: {mode}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# FastMCP server setup
# ---------------------------------------------------------------------------

mcp = FastMCP("Phantom Security Tools")

# Build a name→spec lookup (deduplicated)
_spec_by_name: dict[str, dict] = {}
for spec in TOOL_SPECS:
    _spec_by_name.setdefault(spec["name"], spec)


def _needs_kwargs_wrapper(func) -> bool:
    """Check if function has **kwargs (unsupported by FastMCP)."""
    sig = inspect.signature(func)
    return any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
    )


def _strip_kwargs(func):
    """Create a wrapper that accepts only the explicit parameters (no **kwargs)."""
    sig = inspect.signature(func)
    explicit_params = [
        p
        for p in sig.parameters.values()
        if p.kind not in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL)
    ]
    new_sig = sig.replace(parameters=explicit_params)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    wrapper.__signature__ = new_sig
    return wrapper


def _make_tool_wrapper(original_func, tool_name: str):
    """Wrap a tool function with post-processing (ErrorHandler + StateStore)."""

    @functools.wraps(original_func)
    def wrapper(**kwargs):
        result = original_func(**kwargs)
        result_str = str(result)
        _post_tool_processing(tool_name, kwargs, result_str)
        return result_str

    return wrapper


# Register all Phantom tools with FastMCP
_registered = set()
for tool_name, tool_func in TOOL_REGISTRY.items():
    if tool_name in _registered:
        continue

    spec = _spec_by_name.get(tool_name, {})
    description = spec.get("description", tool_func.__doc__ or tool_name)

    # Prepare the function for FastMCP registration
    fn = tool_func
    if _needs_kwargs_wrapper(fn):
        fn = _strip_kwargs(fn)

    # Wrap with post-processing (ErrorHandler + StateStore)
    fn = _make_tool_wrapper(fn, tool_name)

    # Set metadata that FastMCP reads
    fn.__name__ = tool_name
    fn.__qualname__ = tool_name
    fn.__doc__ = description

    try:
        mcp.add_tool(fn)
        _registered.add(tool_name)
        logger.info("Registered: %s", tool_name)
    except Exception as exc:
        logger.error("Failed to register %s: %s", tool_name, exc)

# Register get_state_summary as an additional MCP tool
get_state_summary.__name__ = "get_state_summary"
get_state_summary.__qualname__ = "get_state_summary"
mcp.add_tool(get_state_summary)
_registered.add("get_state_summary")

# Register generate_hypotheses (Sprint 6)
generate_hypotheses.__name__ = "generate_hypotheses"
generate_hypotheses.__qualname__ = "generate_hypotheses"
mcp.add_tool(generate_hypotheses)
_registered.add("generate_hypotheses")

logger.info("MCP bridge ready: %d tools registered", len(_registered))

if __name__ == "__main__":
    mcp.run(transport="stdio")
