#!/usr/bin/env python3
"""Phantom MCP Bridge — thin router between Claude Code CLI and Phantom tool suite.

This bridge does NOT contain any logic. It:
  1. Imports Phantom's TOOL_REGISTRY and TOOL_SPECS
  2. Registers each tool function with FastMCP (auto-generates MCP schema from type annotations)
  3. Forwards calls directly to Phantom's existing tool functions
  4. Returns results as-is

All scope checking, validation, and error handling remains in Phantom's tool layer.
"""

import functools
import inspect
import logging
import os
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
    """Create a wrapper that accepts only the explicit parameters (no **kwargs).

    FastMCP cannot handle **kwargs. We build a wrapper with a fixed signature
    that mirrors the original's typed parameters, dropping **kwargs.
    """
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

logger.info("MCP bridge ready: %d tools registered", len(_registered))

if __name__ == "__main__":
    mcp.run(transport="stdio")
