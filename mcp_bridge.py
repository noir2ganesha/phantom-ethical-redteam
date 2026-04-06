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
# Post-tool processing: ErrorHandler + StateStore
# ---------------------------------------------------------------------------

# nmap output parsing patterns
_NMAP_STANDARD = re.compile(r"(\d+)/(tcp|udp)\s+(open|filtered)\s+(\S+)\s*(.*)")
_NMAP_PHANTOM = re.compile(r"(\d+)/(tcp|udp)\s+(\S+)\s+(.*)")
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+")

_ERROR_KEYWORDS = frozenset(["error", "fail", "denied", "refused", "timeout",
                              "timed out", "unreachable", "blocked"])


def _post_tool_processing(tool_name: str, tool_input: dict, result: str) -> None:
    """Run ErrorHandler classification and StateStore registration after tool execution."""

    # --- ErrorHandler ---
    if _error_handler and result:
        _lower = result.lower()[:200]
        if any(kw in _lower for kw in _ERROR_KEYWORDS):
            error_type = _error_handler.classify(result, tool_name)
            if error_type != ErrorType.UNKNOWN:
                recovery = _error_handler.recover(error_type, {"tool": tool_name})
                logger.info(
                    "ErrorHandler: %s -> %s: %s",
                    error_type.value,
                    recovery.action.value,
                    recovery.suggestion,
                )

    # --- StateStore ---
    if not _state_store:
        return
    if result.startswith("Error") or result.startswith("SCOPE VIOLATION"):
        return

    target = tool_input.get("target", tool_input.get("url", ""))
    if not target:
        return

    try:
        # nmap → Host + Service
        if tool_name == "run_nmap":
            host = _state_store.get_host_by_ip(target)
            if not host:
                host_id = _state_store.add_host(HostEntity(ip_address=target))
            else:
                host_id = host.id

            for line in result.splitlines():
                port, proto, svc, ver = None, None, None, None
                # Pattern 1: nmap standard (port/tcp open service version)
                m = _NMAP_STANDARD.match(line.strip())
                if m:
                    port, proto, svc, ver = m.group(1), m.group(2), m.group(4), m.group(5)
                else:
                    # Pattern 2: Phantom formatted (port/tcp service version)
                    m = _NMAP_PHANTOM.match(line.strip())
                    if m:
                        port, proto, svc, ver = m.group(1), m.group(2), m.group(3), m.group(4)

                if port:
                    p = int(port)
                    existing = _state_store.get_services_for_host(host_id)
                    if not any(s.port == p and s.protocol == proto for s in existing):
                        _state_store.add_service(ServiceEntity(
                            host_id=host_id,
                            port=p,
                            protocol=proto,
                            service_name=svc,
                            version=(ver.strip() if ver else None),
                        ))

        # All tools: CVE ID detection → Vulnerability registration
        cve_matches = _CVE_PATTERN.findall(result)
        if cve_matches and target:
            host = _state_store.get_host_by_ip(target)
            if not host:
                host_id = _state_store.add_host(HostEntity(ip_address=target))
            else:
                host_id = host.id
            existing_vulns = _state_store.get_vulnerabilities_for_host(host_id)
            existing_cves = {v.cve_id for v in existing_vulns}
            for cve in set(cve_matches):
                if cve not in existing_cves:
                    _state_store.add_vulnerability(VulnerabilityEntity(
                        host_id=host_id,
                        cve_id=cve,
                        description=f"Detected by {tool_name}",
                    ))

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
