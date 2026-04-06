"""Pre-execution validation for tool calls (Sprint 5).

Validates tool parameters before execution:
1. Scope re-check (defense in depth with per-tool scope_guard)
2. StateStore consistency (warn if target host not yet discovered)
3. Parameter type validation
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class PreValidator:
    """Validate tool inputs before execution."""

    def __init__(self, state_store: Any = None, scope_checker: Any = None) -> None:
        self._store = state_store
        self._scope = scope_checker

    def validate(self, tool_name: str, tool_input: dict) -> tuple[bool, str]:
        """Validate tool input. Returns (ok, message).

        ok=True: proceed with execution.
        ok=False: skip execution, return message as tool result.
        """
        target = tool_input.get("target", tool_input.get("url", ""))

        # 1. Scope re-check (defense in depth)
        if target and self._scope:
            from tools.scope_checker import scope_guard
            guard = scope_guard(target)
            if guard is not None:
                logger.warning("PreValidator scope violation: %s", target)
                return False, guard

        # 2. Parameter validation
        if tool_name == "run_nmap":
            t = tool_input.get("target", "")
            if not t:
                return False, "run_nmap requires 'target' parameter"
            if not re.match(r"^[A-Za-z0-9._:\-/]+$", t):
                return False, f"Invalid target format: {t}"
            scan_type = tool_input.get("scan_type", "service")
            if scan_type not in ("quick", "service", "full", "vuln"):
                return False, f"Invalid scan_type: {scan_type}"

        if tool_name == "run_sqlmap":
            url = tool_input.get("url", "")
            if not url:
                return False, "run_sqlmap requires 'url' parameter"
            level = tool_input.get("level", 3)
            if not isinstance(level, int) or not (1 <= level <= 5):
                return False, f"run_sqlmap level must be 1-5, got {level}"

        if tool_name == "run_ffuf":
            url = tool_input.get("url", "")
            if not url:
                return False, "run_ffuf requires 'url' parameter"

        # 3. StateStore consistency warning (non-blocking)
        if self._store and target:
            host = self._store.get_host_by_ip(target)
            if not host:
                host = self._store.get_host_by_hostname(target)
            if not host and tool_name not in ("run_nmap", "check_scope", "run_recon"):
                logger.info(
                    "PreValidator: target %s not in StateStore (consider running nmap first)",
                    target,
                )

        return True, ""
