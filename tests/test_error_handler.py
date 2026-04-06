"""Tests for execution.error_handler — Sprint 1."""

import sys
from pathlib import Path

# Ensure agent/ is on sys.path
_AGENT = Path(__file__).resolve().parent.parent / "agent"
if str(_AGENT) not in sys.path:
    sys.path.insert(0, str(_AGENT))

import pytest
from execution.error_handler import (
    ErrorHandler,
    ErrorType,
    RecoveryAction,
    RecoveryResult,
)


@pytest.fixture
def handler():
    return ErrorHandler()


# ── Classification tests ──────────────────────────────────────


class TestClassify:
    """Verify that each ErrorType is correctly matched by its patterns."""

    def test_empty_input_returns_unknown(self, handler):
        assert handler.classify("") == ErrorType.UNKNOWN
        assert handler.classify(None) == ErrorType.UNKNOWN

    def test_timeout(self, handler):
        assert handler.classify("Connection timed out") == ErrorType.TIMEOUT
        assert handler.classify("nmap: timeout reached") == ErrorType.TIMEOUT
        assert handler.classify("connection timeout after 30s") == ErrorType.TIMEOUT

    def test_connection_refused(self, handler):
        assert handler.classify("Connection refused") == ErrorType.CONNECTION_REFUSED
        assert handler.classify("ECONNREFUSED 10.0.0.1:80") == ErrorType.CONNECTION_REFUSED

    def test_authentication_failed(self, handler):
        assert handler.classify("Authentication failed for user admin") == ErrorType.AUTHENTICATION_FAILED
        assert handler.classify("Login failed: invalid credentials") == ErrorType.AUTHENTICATION_FAILED
        assert handler.classify("Invalid credentials provided") == ErrorType.AUTHENTICATION_FAILED
        assert handler.classify("Invalid username or password") == ErrorType.AUTHENTICATION_FAILED
        assert handler.classify('{"detail":"Invalid username or password"}') == ErrorType.AUTHENTICATION_FAILED

    def test_waf_blocked(self, handler):
        assert handler.classify("403 Forbidden - blocked by WAF") == ErrorType.WAF_BLOCKED
        assert handler.classify("Cloudflare protection detected") == ErrorType.WAF_BLOCKED
        assert handler.classify("ModSecurity: Access denied") == ErrorType.WAF_BLOCKED

    def test_rate_limited(self, handler):
        assert handler.classify("429 Too Many Requests") == ErrorType.RATE_LIMITED
        assert handler.classify("Rate limit exceeded") == ErrorType.RATE_LIMITED

    def test_dns_failed(self, handler):
        assert handler.classify("cannot resolve hostname") == ErrorType.DNS_RESOLUTION_FAILED
        assert handler.classify("Name or service not known") == ErrorType.DNS_RESOLUTION_FAILED
        assert handler.classify("NXDOMAIN for target.htb") == ErrorType.DNS_RESOLUTION_FAILED

    def test_ssl_error(self, handler):
        assert handler.classify("SSL certificate verify failed") == ErrorType.SSL_CERTIFICATE_ERROR
        assert handler.classify("CERTIFICATE_VERIFY_FAILED") == ErrorType.SSL_CERTIFICATE_ERROR
        assert handler.classify("SSL handshake error") == ErrorType.SSL_CERTIFICATE_ERROR

    def test_service_unavailable(self, handler):
        assert handler.classify("503 Service Unavailable") == ErrorType.SERVICE_UNAVAILABLE
        assert handler.classify("502 Bad Gateway") == ErrorType.SERVICE_UNAVAILABLE

    def test_tool_not_found(self, handler):
        assert handler.classify("bash: nmap: command not found") == ErrorType.TOOL_NOT_FOUND
        assert handler.classify("No such file or directory") == ErrorType.TOOL_NOT_FOUND

    def test_permission_denied(self, handler):
        assert handler.classify("Permission denied (publickey)") == ErrorType.PERMISSION_DENIED
        assert handler.classify("Access denied for user") == ErrorType.PERMISSION_DENIED

    def test_ad_kerberos(self, handler):
        assert handler.classify("KDC_ERR_PREAUTH_FAILED") == ErrorType.AD_KERBEROS_ERROR
        assert handler.classify("STATUS_LOGON_FAILURE") == ErrorType.AD_KERBEROS_ERROR
        assert handler.classify("Kerberos authentication error") == ErrorType.AD_KERBEROS_ERROR

    def test_amsi_detected(self, handler):
        assert handler.classify("AMSI blocked execution") == ErrorType.AMSI_DETECTED
        assert handler.classify("malware detected by AV") == ErrorType.AMSI_DETECTED

    def test_unknown_for_unrecognized(self, handler):
        assert handler.classify("Something completely unexpected happened") == ErrorType.UNKNOWN
        assert handler.classify("Scan completed successfully") == ErrorType.UNKNOWN


class TestClassifyPriority:
    """Verify that pattern priority (first-match-wins) is correct.
    Specific patterns (WAF/AMSI/Kerberos) must match before generic ones."""

    def test_waf_403_before_permission_denied(self, handler):
        # "403 Forbidden" should match WAF_BLOCKED, not PERMISSION_DENIED
        assert handler.classify("403 Forbidden") == ErrorType.WAF_BLOCKED

    def test_kerberos_before_auth_failed(self, handler):
        # Kerberos-specific error should not fall through to generic auth_failed
        assert handler.classify("KDC_ERR_PREAUTH_FAILED") == ErrorType.AD_KERBEROS_ERROR

    def test_amsi_before_permission_denied(self, handler):
        # "blocked by security" should match AMSI, not PERMISSION_DENIED
        assert handler.classify("blocked by security software") == ErrorType.AMSI_DETECTED

    def test_timeout_before_ssl(self, handler):
        # "connection timeout" should match TIMEOUT, not CONNECTION_REFUSED
        assert handler.classify("connection timeout") == ErrorType.TIMEOUT


class TestClassifyWithToolName:
    """Verify tool_name parameter is accepted (used for logging)."""

    def test_tool_name_does_not_affect_classification(self, handler):
        assert handler.classify("Connection refused", "nmap") == ErrorType.CONNECTION_REFUSED
        assert handler.classify("Connection refused", "curl") == ErrorType.CONNECTION_REFUSED
        assert handler.classify("Connection refused", "") == ErrorType.CONNECTION_REFUSED


# ── Recovery tests ─────────────────────────────────────────────


class TestRecover:
    """Verify that each ErrorType maps to the correct RecoveryAction."""

    def test_timeout_recovery(self, handler):
        result = handler.recover(ErrorType.TIMEOUT)
        assert result.action == RecoveryAction.RETRY_WITH_DELAY
        assert result.success is True
        assert "timeout" in result.suggestion.lower() or "scope" in result.suggestion.lower()

    def test_waf_blocked_recovery(self, handler):
        result = handler.recover(ErrorType.WAF_BLOCKED)
        assert result.action == RecoveryAction.REDUCE_AGGRESSION
        assert result.alt_params == {"profile": "stealth"}
        assert result.success is True

    def test_auth_failed_recovery(self, handler):
        result = handler.recover(ErrorType.AUTHENTICATION_FAILED)
        assert result.action == RecoveryAction.RETRY_WITH_ALT_PARAMS
        assert result.success is True

    def test_ssl_error_recovery(self, handler):
        result = handler.recover(ErrorType.SSL_CERTIFICATE_ERROR)
        assert result.action == RecoveryAction.RETRY_WITH_ALT_PARAMS
        assert result.success is True

    def test_tool_not_found_recovery(self, handler):
        result = handler.recover(ErrorType.TOOL_NOT_FOUND)
        assert result.action == RecoveryAction.SWITCH_TOOL
        assert result.success is True

    def test_unknown_recovery_escalates(self, handler):
        result = handler.recover(ErrorType.UNKNOWN)
        assert result.action == RecoveryAction.ESCALATE
        assert result.success is False

    def test_ad_kerberos_recovery(self, handler):
        result = handler.recover(ErrorType.AD_KERBEROS_ERROR)
        assert result.action == RecoveryAction.RETRY_WITH_ALT_PARAMS
        assert "kerberos" in result.suggestion.lower() or "ntlm" in result.suggestion.lower()

    def test_amsi_recovery(self, handler):
        result = handler.recover(ErrorType.AMSI_DETECTED)
        assert result.action == RecoveryAction.RETRY_WITH_ALT_PARAMS
        assert "obfuscation" in result.suggestion.lower() or "bypass" in result.suggestion.lower()

    def test_recover_with_context(self, handler):
        result = handler.recover(ErrorType.TIMEOUT, {"tool": "nmap", "input": {"target": "10.0.0.1"}})
        assert result.action == RecoveryAction.RETRY_WITH_DELAY

    def test_recover_with_empty_context(self, handler):
        result = handler.recover(ErrorType.TIMEOUT, {})
        assert result.action == RecoveryAction.RETRY_WITH_DELAY

    def test_recover_with_none_context(self, handler):
        result = handler.recover(ErrorType.TIMEOUT, None)
        assert result.action == RecoveryAction.RETRY_WITH_DELAY

    def test_all_error_types_have_recovery(self, handler):
        """Every ErrorType must have a defined recovery action."""
        for error_type in ErrorType:
            result = handler.recover(error_type)
            assert isinstance(result, RecoveryResult)
            assert isinstance(result.action, RecoveryAction)

    def test_only_reduce_aggression_has_alt_params(self, handler):
        """Only REDUCE_AGGRESSION should set alt_params."""
        for error_type in ErrorType:
            result = handler.recover(error_type)
            if result.action == RecoveryAction.REDUCE_AGGRESSION:
                assert result.alt_params is not None
            else:
                assert result.alt_params is None


# ── Real-world scenario tests (kobold.htb) ─────────────────────


class TestKoboldScenarios:
    """Verify ErrorHandler handles actual errors from kobold.htb attack."""

    def test_tls_handshake_timeout(self, handler):
        # kobold.htb F2: mcp.kobold.htb TLS 1.3 timeout
        error = "TLSv1.3 (OUT), TLS handshake, Client hello: connection timed out"
        assert handler.classify(error) == ErrorType.TIMEOUT
        recovery = handler.recover(ErrorType.TIMEOUT)
        assert recovery.success is True

    def test_arcane_invalid_password(self, handler):
        # kobold.htb F3: Arcane default credential changed
        error = '{"title":"Unauthorized","status":401,"detail":"Invalid username or password"}'
        assert handler.classify(error) == ErrorType.AUTHENTICATION_FAILED
        recovery = handler.recover(ErrorType.AUTHENTICATION_FAILED)
        assert recovery.action == RecoveryAction.RETRY_WITH_ALT_PARAMS

    def test_scope_violation_not_classified_as_error(self, handler):
        # Scope violations are normal operation, not errors
        error = "SCOPE VIOLATION: 'evil.com' is not in the authorized scope."
        assert handler.classify(error) == ErrorType.UNKNOWN

    def test_connection_refused_on_closed_port(self, handler):
        error = "connect to 10.129.245.50 port 8443: Connection refused"
        assert handler.classify(error) == ErrorType.CONNECTION_REFUSED


# ── End-to-end classify → recover flow ──────────────────────────


class TestEndToEnd:
    """Full classify → recover pipeline."""

    def test_full_flow_waf(self, handler):
        error = "ModSecurity: Access denied with code 403"
        error_type = handler.classify(error, "curl")
        assert error_type == ErrorType.WAF_BLOCKED
        recovery = handler.recover(error_type, {"tool": "curl"})
        assert recovery.action == RecoveryAction.REDUCE_AGGRESSION
        assert recovery.alt_params == {"profile": "stealth"}
        assert recovery.success is True

    def test_full_flow_timeout(self, handler):
        error = "nmap: timeout reached after 300s"
        error_type = handler.classify(error, "run_nmap")
        assert error_type == ErrorType.TIMEOUT
        recovery = handler.recover(error_type, {"tool": "run_nmap"})
        assert recovery.action == RecoveryAction.RETRY_WITH_DELAY
        assert recovery.success is True

    def test_full_flow_ssl(self, handler):
        error = "SSL: CERTIFICATE_VERIFY_FAILED"
        error_type = handler.classify(error, "run_whatweb")
        assert error_type == ErrorType.SSL_CERTIFICATE_ERROR
        recovery = handler.recover(error_type, {"tool": "run_whatweb"})
        assert recovery.action == RecoveryAction.RETRY_WITH_ALT_PARAMS
        assert recovery.success is True
