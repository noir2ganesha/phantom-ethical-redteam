"""Error classification and recovery strategy for tool execution failures.

Classifies tool output errors via regex pattern matching, then suggests
recovery actions. Integrates with StrategyMemory for RAG-based recovery
when pattern-based recovery fails.

Ported from Nirvana execution/error_handler.py for Phantom v4 integration.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


class ErrorType(Enum):
    """Tool execution error categories."""

    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    CONNECTION_REFUSED = "connection_refused"
    AUTHENTICATION_FAILED = "auth_failed"
    WAF_BLOCKED = "waf_blocked"
    TOOL_NOT_FOUND = "tool_not_found"
    RATE_LIMITED = "rate_limited"
    PARSE_ERROR = "parse_error"
    DNS_RESOLUTION_FAILED = "dns_failed"
    SSL_CERTIFICATE_ERROR = "ssl_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    AD_KERBEROS_ERROR = "ad_kerberos_error"
    AMSI_DETECTED = "amsi_detected"
    UNKNOWN = "unknown"


class RecoveryAction(Enum):
    """Recovery strategy identifiers."""

    RETRY_WITH_DELAY = "retry_delay"
    RETRY_WITH_ALT_PARAMS = "retry_alt_params"
    SWITCH_TOOL = "switch_tool"
    REDUCE_AGGRESSION = "reduce_aggression"
    SKIP = "skip"
    ESCALATE = "escalate"


@dataclass
class RecoveryResult:
    """Result of a recovery attempt."""

    success: bool
    action: RecoveryAction
    suggestion: str = ""
    alt_params: dict | None = None


# Default recovery mapping: ErrorType -> (RecoveryAction, suggestion)
_DEFAULT_RECOVERY: dict[ErrorType, tuple[RecoveryAction, str]] = {
    ErrorType.TIMEOUT: (
        RecoveryAction.RETRY_WITH_DELAY,
        "Increase timeout or reduce scan scope",
    ),
    ErrorType.PERMISSION_DENIED: (
        RecoveryAction.SWITCH_TOOL,
        "Try alternative tool or escalate privileges first",
    ),
    ErrorType.CONNECTION_REFUSED: (
        RecoveryAction.RETRY_WITH_DELAY,
        "Service may be starting up; retry after short delay",
    ),
    ErrorType.AUTHENTICATION_FAILED: (
        RecoveryAction.RETRY_WITH_ALT_PARAMS,
        "Try different credentials or authentication method",
    ),
    ErrorType.WAF_BLOCKED: (
        RecoveryAction.REDUCE_AGGRESSION,
        "WAF detected; switch to stealth profile",
    ),
    ErrorType.TOOL_NOT_FOUND: (
        RecoveryAction.SWITCH_TOOL,
        "Tool not installed; use alternative",
    ),
    ErrorType.RATE_LIMITED: (
        RecoveryAction.RETRY_WITH_DELAY,
        "Rate limited; wait before retrying",
    ),
    ErrorType.PARSE_ERROR: (
        RecoveryAction.RETRY_WITH_ALT_PARAMS,
        "Output parsing failed; try different output format",
    ),
    ErrorType.DNS_RESOLUTION_FAILED: (
        RecoveryAction.RETRY_WITH_ALT_PARAMS,
        "DNS failed; try IP address directly",
    ),
    ErrorType.SSL_CERTIFICATE_ERROR: (
        RecoveryAction.RETRY_WITH_ALT_PARAMS,
        "SSL error; try --no-check-certificate or -k flag",
    ),
    ErrorType.SERVICE_UNAVAILABLE: (
        RecoveryAction.RETRY_WITH_DELAY,
        "Service temporarily unavailable; retry after delay",
    ),
    ErrorType.AD_KERBEROS_ERROR: (
        RecoveryAction.RETRY_WITH_ALT_PARAMS,
        "Kerberos error; check clock skew, SPN, or try NTLM auth",
    ),
    ErrorType.AMSI_DETECTED: (
        RecoveryAction.RETRY_WITH_ALT_PARAMS,
        "AMSI detected payload; apply obfuscation or use bypass",
    ),
    ErrorType.UNKNOWN: (
        RecoveryAction.ESCALATE,
        "Unknown error; re-evaluate approach",
    ),
}


class ErrorHandler:
    """Classify tool errors and suggest recovery strategies."""

    # Pattern order = priority (first-match-wins).
    # Specific detections (WAF/AMSI/Kerberos) MUST precede generic
    # "permission denied/forbidden" to avoid misclassification.
    ERROR_PATTERNS: ClassVar[list[tuple[re.Pattern[str], ErrorType]]] = [
        (re.compile(r"timeout|timed out|connection timeout", re.IGNORECASE), ErrorType.TIMEOUT),
        (re.compile(r"KDC_ERR|STATUS_LOGON_FAILURE|Kerberos.*error", re.IGNORECASE), ErrorType.AD_KERBEROS_ERROR),
        (re.compile(r"AMSI|malware detected|blocked by.*security", re.IGNORECASE), ErrorType.AMSI_DETECTED),
        (re.compile(r"WAF|blocked by.*WAF|cloudflare|ModSecurity|403 Forbidden", re.IGNORECASE), ErrorType.WAF_BLOCKED),
        (re.compile(r"rate limit|429|too many requests", re.IGNORECASE), ErrorType.RATE_LIMITED),
        (re.compile(r"cannot resolve|Name or service not known|NXDOMAIN", re.IGNORECASE), ErrorType.DNS_RESOLUTION_FAILED),
        (re.compile(r"SSL|certificate verify failed|CERTIFICATE_VERIFY_FAILED", re.IGNORECASE), ErrorType.SSL_CERTIFICATE_ERROR),
        (re.compile(r"502 Bad Gateway|503 Service Unavailable|service unavailable", re.IGNORECASE), ErrorType.SERVICE_UNAVAILABLE),
        (re.compile(r"command not found|No such file", re.IGNORECASE), ErrorType.TOOL_NOT_FOUND),
        (re.compile(r"connection refused|ECONNREFUSED", re.IGNORECASE), ErrorType.CONNECTION_REFUSED),
        (re.compile(r"authentication failed|login failed|invalid credentials|invalid.*password|invalid.*username", re.IGNORECASE), ErrorType.AUTHENTICATION_FAILED),
        # Generic "permission denied/forbidden" LAST among access-control patterns
        (re.compile(r"permission denied|access denied|forbidden", re.IGNORECASE), ErrorType.PERMISSION_DENIED),
    ]

    def __init__(self, strategy_memory: Any = None) -> None:
        self._strategy_memory = strategy_memory

    def classify(self, error_output: str, tool_name: str = "") -> ErrorType:
        """Classify error by matching output against ERROR_PATTERNS.

        First match wins (pattern order = priority).
        No match -> ErrorType.UNKNOWN.
        """
        if not error_output:
            return ErrorType.UNKNOWN

        for pattern, error_type in self.ERROR_PATTERNS:
            if pattern.search(error_output):
                logger.debug(
                    "Classified error for %s as %s",
                    tool_name or "unknown_tool",
                    error_type.value,
                )
                return error_type

        return ErrorType.UNKNOWN

    def recover(
        self, error_type: ErrorType, context: dict | None = None
    ) -> RecoveryResult:
        """Suggest a recovery strategy for the given error type.

        1. Pattern-based default recovery
        2. RAG-based recovery via StrategyMemory (if available)
        3. ESCALATE as fallback
        """
        context = context or {}

        # Step 1: Default recovery
        action, suggestion = _DEFAULT_RECOVERY.get(
            error_type,
            (RecoveryAction.ESCALATE, "Unknown error"),
        )

        # Step 2: Try RAG-based recovery for richer suggestions
        if self._strategy_memory and error_type != ErrorType.UNKNOWN:
            try:
                rag_suggestion = self._strategy_memory.get_failure_recovery(
                    tool=context.get("tool", ""),
                    error_type=error_type.value,
                )
                if rag_suggestion:
                    suggestion = f"{suggestion}. RAG: {rag_suggestion}"
            except Exception:
                logger.debug("RAG recovery lookup failed", exc_info=True)

        alt_params = None
        if action == RecoveryAction.REDUCE_AGGRESSION:
            alt_params = {"profile": "stealth"}

        return RecoveryResult(
            success=action != RecoveryAction.ESCALATE,
            action=action,
            suggestion=suggestion,
            alt_params=alt_params,
        )
