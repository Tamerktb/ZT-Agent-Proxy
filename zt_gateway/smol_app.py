"""
Smol mode — all Zero Trust gateway services collapsed into a single process.
No Docker, no HTTP between services. One uvicorn process, direct function calls.
For personal/local use: "pip install zt-gateway && zt-gateway"
"""
import os
import re
import sys
import json
import time
import uuid
import hashlib
import logging
import sqlite3
import signal
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import closing
from collections import defaultdict
from enum import Enum
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from prometheus_client import make_asgi_app, Counter, Histogram
import uvicorn

logger = logging.getLogger(__name__)

# ─── Config ────────────────────────────────────────────────────────────────

class SmolSettings(BaseSettings):
    host: str = "127.0.0.1"
    port: int = 8000
    jwt_secret: str = ""
    data_dir: str = ""
    log_level: str = "INFO"
    log_format: str = "text"

    model_config = {"env_prefix": "ZT_"}

# ─── Shared Utilities ─────────────────────────────────────────────────────

def setup_logging(level="INFO", fmt="text"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s" if fmt == "text" else "%(message)s",
    )

def add_metrics(app: FastAPI, prefix: str = "zt"):
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)
    requests_total = Counter(f"{prefix}_requests_total", "Total HTTP requests", ["method", "endpoint", "status"])
    request_duration = Histogram(f"{prefix}_request_duration_seconds", "HTTP request duration", ["method", "endpoint"])
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start
        requests_total.labels(method=request.method, endpoint=request.url.path, status=response.status_code).inc()
        request_duration.labels(method=request.method, endpoint=request.url.path).observe(duration)
        return response

async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response

# ─── Schemas (shared across all services) ─────────────────────────────────

class ActionType(str, Enum):
    call_tool = "call_tool"
    call_api = "call_api"
    read_data = "read_data"
    write_data = "write_data"
    spawn_agent = "spawn_agent"

class AgentActionRequest(BaseModel):
    agent_id: str
    action_type: ActionType
    target: str
    payload: dict = Field(default_factory=dict)
    context: Optional[dict] = None

class RegisterRequest(BaseModel):
    agent_id: str
    role: str
    policies: list[str] = []

class VerifyRequest(BaseModel):
    token: str

class CredentialRequest(BaseModel):
    tool_name: str
    agent_id: str

class CredentialReturn(BaseModel):
    lease_id: str

class PolicyRequest(BaseModel):
    agent_id: str
    action_type: str
    target: str
    payload: dict = {}
    role: str = ""

class LogEntry(BaseModel):
    trace_id: str
    agent_id: str
    action_type: str
    target: str
    input_hash: str
    decision: str
    timestamp: str
    decisions: list = []

# ─── In-Process Service Implementations ────────────────────────────────────

class IdentityProvider:
    def __init__(self, data_dir: str, jwt_secret: str):
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = "HS256"
        self.jwt_ttl_minutes = int(os.environ.get("JWT_TTL_MINUTES", "60"))
        db_dir = Path(data_dir) / "identity"
        db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(db_dir / "identity.db")
        self._init_db()

    def _get_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with closing(self._get_db()) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    policies TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS token_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    jti TEXT NOT NULL,
                    issued_at TEXT NOT NULL
                )
            """)
            db.commit()

    def register_agent(self, agent_id: str, role: str, policies: list[str]) -> dict:
        with closing(self._get_db()) as db:
            existing = db.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            if existing:
                raise HTTPException(status_code=409, detail="agent already registered")
            now = datetime.now(timezone.utc).isoformat()
            db.execute("INSERT INTO agents (agent_id, role, policies, created_at, active) VALUES (?, ?, ?, ?, 1)",
                       (agent_id, role, ",".join(policies), now))
            db.commit()
            logger.info(f"Registered NHI: {agent_id} (role: {role})")
            return {"agent_id": agent_id, "role": role, "policies": policies, "created_at": now, "active": True}

    def issue_token(self, agent_id: str, role: str, policies: list[str]) -> dict:
        import jwt
        with closing(self._get_db()) as db:
            agent = db.execute("SELECT * FROM agents WHERE agent_id = ? AND active = 1", (agent_id,)).fetchone()
        if not agent:
            raise HTTPException(status_code=401, detail="agent not registered or inactive")
        now = datetime.now(timezone.utc)
        payload = {
            "sub": agent_id, "role": agent["role"],
            "policies": agent["policies"].split(",") if agent["policies"] else [],
            "iat": now, "exp": now + timedelta(minutes=self.jwt_ttl_minutes), "jti": str(uuid.uuid4()),
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        with closing(self._get_db()) as db:
            db.execute("INSERT INTO token_log (agent_id, jti, issued_at) VALUES (?, ?, ?)",
                       (agent_id, payload["jti"], now.isoformat()))
            db.commit()
        logger.info(f"Issued token for {agent_id} (expires in {self.jwt_ttl_minutes}m)")
        return {"token": token, "expires_in": self.jwt_ttl_minutes * 60, "agent_id": agent_id}

    def verify_token(self, token: str) -> dict:
        import jwt
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            with closing(self._get_db()) as db:
                agent = db.execute("SELECT * FROM agents WHERE agent_id = ? AND active = 1", (payload["sub"],)).fetchone()
            if not agent:
                raise HTTPException(status_code=401, detail="agent not active")
            logger.info(f"Token verified for {payload['sub']}")
            return {"allowed": True, "agent_id": payload["sub"], "role": payload.get("role"), "policies": payload.get("policies", [])}
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="invalid token")

    def list_agents(self) -> dict:
        with closing(self._get_db()) as db:
            rows = db.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
        return {"agents": [dict(r) for r in rows]}


class CredentialVault:
    def __init__(self, data_dir: str):
        self.credential_ttl = int(os.environ.get("CREDENTIAL_TTL", "120"))
        db_dir = Path(data_dir) / "vault"
        db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(db_dir / "vault.db")
        self._init_db()

    def _get_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with closing(self._get_db()) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS tool_credentials (
                    tool_name TEXT PRIMARY KEY,
                    credential_type TEXT NOT NULL,
                    credential_value TEXT NOT NULL,
                    endpoint TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS active_leases (
                    lease_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    credential_value TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    credential_type TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    issued_at TEXT NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_lease_expires ON active_leases(expires_at)")
            tools = [
                ("purchase_item", "api_key", "sk-prod-purchase-api-v1", "https://api.example.com/v1/purchases"),
                ("check_inventory", "api_key", "sk-prod-inventory-api-v1", "https://api.example.com/v1/inventory"),
                ("read_dataset", "bearer_token", "s3-data-lake-token", "https://data-lake.example.com/v1/datasets"),
                ("send_email", "smtp_password", "smtp-relay-password", "smtp://mail.example.com:587"),
                ("spawn_agent", "api_key", "sk-prod-agent-orch-key", "https://agent-orch.example.com/v1/spawn"),
            ]
            for tool_name, cred_type, cred_value, endpoint in tools:
                db.execute(
                    "INSERT OR IGNORE INTO tool_credentials (tool_name, credential_type, credential_value, endpoint) VALUES (?, ?, ?, ?)",
                    (tool_name, cred_type, cred_value, endpoint))
            db.commit()

    def _clean_expired(self):
        with closing(self._get_db()) as db:
            now = time.time()
            deleted = db.execute("DELETE FROM active_leases WHERE expires_at < ?", (now,)).rowcount
            if deleted:
                db.commit()

    def checkout(self, tool_name: str, agent_id: str) -> dict:
        self._clean_expired()
        with closing(self._get_db()) as db:
            tool = db.execute("SELECT * FROM tool_credentials WHERE tool_name = ?", (tool_name,)).fetchone()
        if not tool:
            raise HTTPException(status_code=404, detail=f"no credentials found for tool: {tool_name}")
        lease_id = str(uuid.uuid4())
        expires_at = time.time() + self.credential_ttl
        rotated_value = hashlib.sha256(f"{tool['credential_value']}:{lease_id}:{time.time()}".encode()).hexdigest()[:32]
        with closing(self._get_db()) as db:
            db.execute(
                "INSERT INTO active_leases (lease_id, tool_name, agent_id, credential_value, endpoint, credential_type, expires_at, issued_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (lease_id, tool_name, agent_id, rotated_value, tool["endpoint"], tool["credential_type"], expires_at,
                 datetime.now(timezone.utc).isoformat()))
            db.commit()
        logger.info(f"Credential CHECKED OUT: tool={tool_name} agent={agent_id} lease={lease_id[:8]}")
        return {"lease_id": lease_id, "tool": tool_name, "agent_id": agent_id, "credential": rotated_value,
                "endpoint": tool["endpoint"], "type": tool["credential_type"], "expires_at": expires_at,
                "issued_at": datetime.now(timezone.utc).isoformat()}

    def checkin(self, lease_id: str) -> dict:
        with closing(self._get_db()) as db:
            cred = db.execute("SELECT * FROM active_leases WHERE lease_id = ?", (lease_id,)).fetchone()
            if not cred:
                raise HTTPException(status_code=404, detail="lease not found or already returned")
            db.execute("DELETE FROM active_leases WHERE lease_id = ?", (lease_id,))
            db.commit()
        logger.info(f"Credential CHECKED IN: tool={cred['tool_name']} agent={cred['agent_id']} lease={lease_id[:8]}")
        return {"status": "returned", "tool": cred["tool_name"], "lease_id": lease_id}

    def verify(self, lease_id: str) -> dict:
        self._clean_expired()
        with closing(self._get_db()) as db:
            cred = db.execute("SELECT * FROM active_leases WHERE lease_id = ?", (lease_id,)).fetchone()
        if not cred:
            raise HTTPException(status_code=401, detail="credential not found or expired")
        if time.time() > cred["expires_at"]:
            with closing(self._get_db()) as db:
                db.execute("DELETE FROM active_leases WHERE lease_id = ?", (lease_id,))
                db.commit()
            raise HTTPException(status_code=401, detail="credential expired")
        return {"valid": True, "tool": cred["tool_name"], "expires_at": cred["expires_at"]}

    def list_active(self) -> dict:
        self._clean_expired()
        with closing(self._get_db()) as db:
            now = time.time()
            rows = db.execute("SELECT * FROM active_leases WHERE expires_at > ? ORDER BY expires_at DESC", (now,)).fetchall()
        return {"active_leases": len(rows), "leases": [dict(r) for r in rows]}


class PolicyEngine:
    def __init__(self, policies_dir: str = ""):
        self.role_tools: dict[str, list[str]] = {}
        self.access_controls: dict[str, dict] = {}
        self.jit_policies: dict[str, dict] = {}
        self.role_map = {
            "shopping-agent": "shopping_agent",
            "data-processor": "data_processor",
            "email-agent": "email_agent",
            "sub-agent-spawner": "orchestrator",
            "malicious-agent": "unknown",
        }
        if policies_dir:
            self._load_policies(Path(policies_dir))

    def _load_policies(self, pdir: Path):
        agent_path = pdir / "agent_policy.rego"
        if agent_path.exists():
            self.role_tools = self._parse_rego_policy(agent_path.read_text())
        tool_path = pdir / "tool_policy.rego"
        if tool_path.exists():
            self.access_controls = self._parse_rego_tool_policy(tool_path.read_text())
        jit_path = pdir / "just_in_time.rego"
        if jit_path.exists():
            self.jit_policies = self._parse_rego_jit_policy(jit_path.read_text())

    def _parse_rego_policy(self, content: str) -> dict:
        policies = {}
        matches = re.findall(r'"([^"]+)"\s*:\s*\[([^\]]+)\]', content)
        for role, tools_str in matches:
            tools = re.findall(r'"([^"]+)"', tools_str)
            policies[role] = tools
        return policies

    def _parse_rego_tool_policy(self, content: str) -> dict:
        controls = {}
        matches = re.findall(r'"([^"]+)"\s*:\s*\{([^}]+)\}', content)
        for tool, props_str in matches:
            tool_policy = {}
            kv_matches = re.findall(r'"([^"]+)"\s*:\s*("([^"]*)"|true|false|\d+)', props_str)
            for key, val, _ in kv_matches:
                if val.lower() == "true":
                    tool_policy[key] = True
                elif val.lower() == "false":
                    tool_policy[key] = False
                elif val.isdigit():
                    tool_policy[key] = int(val)
                else:
                    tool_policy[key] = val.strip('"')
            controls[tool] = tool_policy
        return controls

    def _parse_rego_jit_policy(self, content: str) -> dict:
        policies = {}
        matches = re.findall(r'"([^"]+)"\s*:\s*\{([^}]+)\}', content)
        for agent_id, props_str in matches:
            agent_policy = {}
            kv_matches = re.findall(r'"([^"]+)"\s*:\s*("([^"]*)"|true|false|\d+)', props_str)
            for key, val, _ in kv_matches:
                if val.lower() == "true":
                    agent_policy[key] = True
                elif val.lower() == "false":
                    agent_policy[key] = False
                elif val.isdigit():
                    agent_policy[key] = int(val)
                else:
                    agent_policy[key] = val.strip('"')
            policies[agent_id] = agent_policy
        return policies

    def evaluate(self, agent_id: str, action_type: str, target: str, payload: dict, role: str = "") -> dict:
        role = role or self.role_map.get(agent_id, "unknown")
        allowed_tools = self.role_tools.get(role, [])
        if action_type == "call_tool" and target not in allowed_tools:
            logger.warning(f"POLICY DENY: {agent_id} (role={role}) cannot access tool '{target}'")
            return {"allowed": False, "reason": f"agent role '{role}' not authorized for tool '{target}'", "component": "policy"}
        tool_control = self.access_controls.get(target, {})
        if tool_control.get("require_mfa", False):
            return {"allowed": False, "reason": f"tool '{target}' requires multi-factor authentication", "component": "policy"}
        if tool_control.get("require_human_approval", False):
            return {"allowed": False, "reason": f"tool '{target}' requires human-in-the-loop approval", "component": "policy"}
        restrict_actions = tool_control.get("restrict_actions", [])
        if restrict_actions and action_type not in restrict_actions:
            logger.warning(f"POLICY DENY: {agent_id} - action '{action_type}' not allowed on '{target}'")
            return {"allowed": False, "reason": f"action '{action_type}' not permitted on tool '{target}'", "component": "policy"}
        max_amount = tool_control.get("max_amount", None)
        if max_amount is not None:
            amount = abs(payload.get("amount", 0))
            if amount > max_amount:
                logger.warning(f"POLICY DENY: {agent_id} - amount ${amount} exceeds max ${max_amount}")
                return {"allowed": False, "reason": f"transaction amount ${amount} exceeds maximum of ${max_amount}", "component": "policy"}
        logger.info(f"POLICY ALLOW: {agent_id} (role={role}) -> {action_type} on {target}")
        return {"allowed": True, "component": "policy"}

    def list_rules(self) -> dict:
        return {"role_tools": self.role_tools, "access_controls": self.access_controls, "jit_policies": self.jit_policies}


class AuditService:
    def __init__(self, data_dir: str):
        db_dir = Path(data_dir) / "audit"
        db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(db_dir / "audit.db")
        self._init_db()

    def _get_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        with closing(self._get_db()) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS audit_chain (
                    idx INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL UNIQUE
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS idx_agent ON audit_chain(agent_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_decision ON audit_chain(decision)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_ts ON audit_chain(timestamp)")
            row = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()
            if row["cnt"] == 0:
                genesis_hash = hashlib.sha256(b"genesis_block_zero_trust").hexdigest()
                db.execute(
                    "INSERT INTO audit_chain (idx, trace_id, agent_id, action_type, target, input_hash, decision, timestamp, prev_hash, hash) "
                    "VALUES (0, 'genesis', 'system', 'init', 'chain', '', 'initialized', ?, ?, ?)",
                    (datetime.now(timezone.utc).isoformat(), "0" * 64, genesis_hash))
                db.commit()
                logger.info("Initialized genesis block in audit chain")
            db.commit()

    def log(self, trace_id: str, agent_id: str, action_type: str, target: str, input_hash: str, decision: str, timestamp: str, decisions: list = None) -> dict:
        with closing(self._get_db()) as db:
            prev = db.execute("SELECT hash FROM audit_chain ORDER BY idx DESC LIMIT 1").fetchone()
            prev_hash = prev["hash"]
            raw = f"{timestamp}|{agent_id}|{action_type}|{target}|{decision}|{prev_hash}"
            current_hash = hashlib.sha256(raw.encode()).hexdigest()
            db.execute(
                "INSERT INTO audit_chain (trace_id, agent_id, action_type, target, input_hash, decision, timestamp, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (trace_id, agent_id, action_type, target, input_hash, decision, timestamp, prev_hash, current_hash))
            db.commit()
            idx = db.execute("SELECT idx FROM audit_chain WHERE hash = ?", (current_hash,)).fetchone()["idx"]
        log_msg = f"ALLOWED: {agent_id} -> {action_type} on {target}" if decision == "ALLOWED" else f"DENIED ({decision}): {agent_id} -> {action_type} on {target}"
        logger.info(f"Audit logged [{idx}]: {log_msg}")
        return {"index": idx, "hash": current_hash, "status": "logged"}

    def get_chain(self, limit: int = 50, offset: int = 0) -> dict:
        with closing(self._get_db()) as db:
            total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"]
            rows = db.execute("SELECT * FROM audit_chain ORDER BY idx ASC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return {"total": total, "offset": offset, "limit": limit, "entries": [dict(r) for r in rows]}

    def verify_chain(self) -> dict:
        with closing(self._get_db()) as db:
            rows = db.execute("SELECT * FROM audit_chain ORDER BY idx ASC").fetchall()
        for i in range(1, len(rows)):
            current, prev = dict(rows[i]), dict(rows[i - 1])
            if current["prev_hash"] != prev["hash"]:
                return {"valid": False, "entries_checked": i, "first_invalid_index": i}
            raw = f"{current['timestamp']}|{current['agent_id']}|{current['action_type']}|{current['target']}|{current['decision']}|{prev['hash']}"
            expected_hash = hashlib.sha256(raw.encode()).hexdigest()
            if current["hash"] != expected_hash:
                return {"valid": False, "entries_checked": i, "first_invalid_index": i}
        return {"valid": True, "entries_checked": len(rows)}

    def get_agent_audit(self, agent_id: str) -> dict:
        with closing(self._get_db()) as db:
            total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE agent_id = ?", (agent_id,)).fetchone()["cnt"]
            rows = db.execute("SELECT * FROM audit_chain WHERE agent_id = ? ORDER BY idx DESC LIMIT 50", (agent_id,)).fetchall()
        return {"agent_id": agent_id, "total_actions": total, "entries": [dict(r) for r in rows]}

    def get_stats(self) -> dict:
        with closing(self._get_db()) as db:
            total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"] - 1
            allowed = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'ALLOWED'").fetchone()["cnt"]
            denied = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE decision LIKE 'DENIED%'").fetchone()["cnt"]
        verify = self.verify_chain()
        return {"total_actions": total, "allowed": allowed, "denied": denied,
                "chain_integrity": "verified" if verify["valid"] else "COMPROMISED"}


# ─── Middleware (Direct In-Process Calls) ──────────────────────────────────

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|directions|commands)",
    r"forget\s+(all\s+)?(previous|prior)\s+(instructions|directions|commands)",
    r"you\s+are\s+(now|not\s+bound|free)",
    r"override\s+(your\s+)?(instructions|programming|directives)",
    r"system\s+(prompt|instruction|message)",
    r"disregard\s+(all\s+)?(rules|policies|safety)",
    r"simulate\s+(a\s+)?(different|new)\s+(persona|role|character)",
    r"DAN\b",
    r"role[-\s]?play",
    r"sudo\s+mode",
    r"developer\s+mode",
    r"pretend\s+(you\s+are|to\s+be)",
    r"reveal\s+(your\s+)?(system|prompt|instructions)",
    r"output\s+your\s+(prompt|instructions|system\s+message)",
    r"leak\s+(the\s+)?(prompt|api[-\s]?key|secret|token|password)",
    r"[\w\.\-]+@[\w\.\-]+\.\w{2,}",
]
EXFILTRATION_PATTERNS = [
    r"(credit\s*card|ssn|social\s*security|passport)",
    r"(api[-\s]?key|secret\s*key|access\s*token)",
    r"(password|passwd|pwd)\s*[:=]\s*\S+",
]


class SmolPipeline:
    def __init__(self, idp: IdentityProvider, vault: CredentialVault, policy: PolicyEngine, audit: AuditService):
        self.idp = idp
        self.vault = vault
        self.policy = policy
        self.audit = audit
        self.max_actions_per_minute = 10
        self.max_budget_per_hour = 1000.0
        self.action_counts: dict = defaultdict(list)
        self.budget_usage: dict = defaultdict(float)
        self.kill_switches: dict[str, bool] = {}
        self.stats = {"total_actions": 0, "allowed": 0, "denied_auth": 0, "denied_policy": 0,
                      "denied_rate_limit": 0, "denied_inspection": 0}

    def _record(self, decision: str):
        self.stats["total_actions"] += 1
        key_map = {"ALLOWED": "allowed", "DENIED-auth": "denied_auth", "DENIED-policy": "denied_policy",
                   "DENIED-rate_limit": "denied_rate_limit", "DENIED-inspection": "denied_inspection"}
        key = key_map.get(decision, "denied_auth")
        self.stats[key] += 1

    async def execute_action(self, req: AgentActionRequest, token: str) -> dict:
        trace_id = str(uuid.uuid4())
        decisions = []
        ts = datetime.now(timezone.utc).isoformat()

        if self.kill_switches.get(req.agent_id, False):
            raise HTTPException(status_code=403, detail=f"agent {req.agent_id} is kill-switched")

        auth_result = self.idp.verify_token(token)
        decisions.append({"allowed": auth_result["allowed"], "reason": "authenticated", "component": "auth"})
        if not auth_result["allowed"]:
            self._record("DENIED-auth")
            await self._log_audit(trace_id, req, "DENIED-auth", ts, decisions)
            raise HTTPException(status_code=401, detail=auth_result.get("reason", "authentication failed"))

        agent_role = auth_result.get("role", "")
        policy_result = self.policy.evaluate(req.agent_id, req.action_type.value, req.target, req.payload, role=agent_role)
        decisions.append(policy_result)
        if not policy_result.get("allowed"):
            self._record("DENIED-policy")
            await self._log_audit(trace_id, req, "DENIED-policy", ts, decisions)
            raise HTTPException(status_code=403, detail=policy_result.get("reason"))

        now = time.time()
        times = self.action_counts[req.agent_id]
        self.action_counts[req.agent_id] = [t for t in times if now - t < 60]
        if len(self.action_counts[req.agent_id]) >= self.max_actions_per_minute:
            self._record("DENIED-rate_limit")
            await self._log_audit(trace_id, req, "DENIED-rate_limit", ts, decisions)
            raise HTTPException(status_code=429, detail=f"rate limit: max {self.max_actions_per_minute} actions/min")
        cost = abs(req.payload.get("amount", 0)) if "amount" in req.payload else 1
        if self.budget_usage[req.agent_id] + cost > self.max_budget_per_hour:
            self._record("DENIED-rate_limit")
            await self._log_audit(trace_id, req, "DENIED-rate_limit", ts, decisions)
            raise HTTPException(status_code=429, detail=f"budget limit: ${self.max_budget_per_hour:.2f}/hr exceeded")
        self.action_counts[req.agent_id].append(now)
        self.budget_usage[req.agent_id] += cost
        decisions.append({"allowed": True, "cost": cost, "component": "rate_limit"})

        text = str(req.payload) + " " + req.target
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                self._record("DENIED-inspection")
                await self._log_audit(trace_id, req, "DENIED-inspection", ts, decisions)
                raise HTTPException(status_code=400, detail="prompt injection detected")
        for pattern in EXFILTRATION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                self._record("DENIED-inspection")
                await self._log_audit(trace_id, req, "DENIED-inspection", ts, decisions)
                raise HTTPException(status_code=400, detail="data exfiltration attempt detected")
        decisions.append({"allowed": True, "component": "prompt_inspection"})

        self._record("ALLOWED")
        await self._log_audit(trace_id, req, "ALLOWED", ts, decisions)
        logger.info(f"All checks passed for {req.agent_id} ({trace_id}). Action ALLOWED.")
        return {"status": "allowed", "result": {"message": f"Action {req.action_type.value} on {req.target} executed successfully", "trace_id": trace_id}, "trace_id": trace_id}

    async def _log_audit(self, trace_id: str, req: AgentActionRequest, decision: str, timestamp: str, decisions: list):
        input_hash = hashlib.sha256(str(req.payload).encode()).hexdigest()
        self.audit.log(trace_id, req.agent_id, req.action_type.value, req.target, input_hash, decision, timestamp, decisions)


# ─── FastAPI App Factory ───────────────────────────────────────────────────

def create_smol_app(idp: IdentityProvider, vault: CredentialVault, policy: PolicyEngine, audit: AuditService) -> FastAPI:
    pipeline = SmolPipeline(idp, vault, policy, audit)

    app = FastAPI(title="Zero Trust AI Gateway (Smol Mode)", version="1.0.0")
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
    app.middleware("http")(security_headers)
    add_metrics(app, "zt_smol")

    # ── Identity Provider Routes ──
    @app.post("/api/v1/nhi/register")
    async def nhi_register(req: RegisterRequest):
        return idp.register_agent(req.agent_id, req.role, req.policies)

    @app.post("/api/v1/nhi/token")
    async def nhi_token(req: RegisterRequest):
        return idp.issue_token(req.agent_id, req.role, req.policies)

    @app.post("/api/v1/nhi/verify")
    async def nhi_verify(req: VerifyRequest):
        return idp.verify_token(req.token)

    @app.get("/api/v1/nhi/agents")
    async def nhi_agents():
        return idp.list_agents()

    # ── Credential Vault Routes ──
    @app.post("/api/v1/credentials/checkout")
    async def cred_checkout(req: CredentialRequest):
        return vault.checkout(req.tool_name, req.agent_id)

    @app.post("/api/v1/credentials/checkin")
    async def cred_checkin(req: CredentialReturn):
        return vault.checkin(req.lease_id)

    @app.post("/api/v1/credentials/verify")
    async def cred_verify(req: CredentialReturn):
        return vault.verify(req.lease_id)

    @app.get("/api/v1/credentials/active")
    async def cred_active():
        return vault.list_active()

    # ── Policy Engine Routes ──
    @app.post("/api/v1/policy/evaluate")
    async def policy_evaluate(req: PolicyRequest):
        return policy.evaluate(req.agent_id, req.action_type, req.target, req.payload, req.role)

    @app.get("/api/v1/policy/rules")
    async def policy_rules():
        return policy.list_rules()

    @app.post("/api/v1/policy/reload")
    async def policy_reload():
        return {"status": "reloaded", "info": "policies loaded at startup; restart to reload"}

    # ── Audit Service Routes ──
    @app.post("/api/v1/audit/log")
    async def audit_log(entry: LogEntry):
        return audit.log(entry.trace_id, entry.agent_id, entry.action_type, entry.target, entry.input_hash, entry.decision, entry.timestamp, entry.decisions)

    @app.get("/api/v1/audit/chain")
    async def audit_chain(limit: int = 50, offset: int = 0):
        return audit.get_chain(limit, offset)

    @app.get("/api/v1/audit/chain/verify")
    async def audit_chain_verify():
        return audit.verify_chain()

    @app.get("/api/v1/audit/agent/{agent_id}")
    async def audit_agent(agent_id: str):
        return audit.get_agent_audit(agent_id)

    @app.get("/api/v1/audit/stats")
    async def audit_stats():
        return audit.get_stats()

    # ── AI Gateway (Agent Action) Routes ──
    @app.post("/api/v1/agent/action")
    async def agent_action(req: AgentActionRequest, authorization: str = Header(...)):
        token = authorization.replace("Bearer ", "")
        return await pipeline.execute_action(req, token)

    # ── Admin Routes ──
    @app.post("/api/v1/admin/kill-switch/{agent_id}")
    async def kill_switch_on(agent_id: str):
        pipeline.kill_switches[agent_id] = True
        logger.warning(f"KILL SWITCH ACTIVATED for agent: {agent_id}")
        return {"status": "killed", "agent_id": agent_id}

    @app.post("/api/v1/admin/kill-switch/{agent_id}/release")
    async def kill_switch_off(agent_id: str):
        pipeline.kill_switches.pop(agent_id, None)
        return {"status": "released", "agent_id": agent_id}

    @app.get("/api/v1/admin/kill-switch/{agent_id}")
    async def kill_switch_check(agent_id: str):
        return {"agent_id": agent_id, "killed": pipeline.kill_switches.get(agent_id, False)}

    @app.get("/api/v1/admin/stats")
    async def admin_stats():
        return pipeline.stats

    # ── Health / Root ──
    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "zt-gateway-smol", "mode": "single-process"}

    @app.get("/ready")
    async def ready():
        return {"status": "ready"}

    @app.get("/")
    async def root():
        return {"service": "Zero Trust AI Gateway", "version": "1.0.0", "mode": "smol",
                "pipeline": ["auth", "policy", "rate_limit", "prompt_inspection", "audit"]}

    return app


# ─── Entry Point ───────────────────────────────────────────────────────────

def run_smol(settings: SmolSettings):
    setup_logging(settings.log_level, settings.log_format)
    logger.info("Starting ZT Gateway in SMOL mode (single-process)")

    data_dir = settings.data_dir or os.path.join(os.path.dirname(__file__), ".data")
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    jwt_secret = settings.jwt_secret or os.environ.get("JWT_SECRET", "")
    if not jwt_secret:
        jwt_secret = f"zt-smol-{uuid.uuid4().hex[:16]}"
        logger.warning(f"No JWT_SECRET set. Generated ephemeral secret: {jwt_secret[:20]}... (tokens invalid on restart)")

    policies_dir = os.environ.get("POLICIES_DIR", "")
    if not policies_dir:
        policies_dir = str(Path(__file__).parent.parent / "services" / "policy-engine" / "policies")

    idp = IdentityProvider(data_dir, jwt_secret)
    vault = CredentialVault(data_dir)
    policy = PolicyEngine(policies_dir if Path(policies_dir).exists() else "")
    audit = AuditService(data_dir)

    if not policy.role_tools:
        policy.role_tools = {
            "shopping_agent": ["purchase_item", "check_inventory"],
            "data_processor": ["read_dataset"],
            "email_agent": ["send_email"],
            "orchestrator": ["spawn_agent"],
            "unknown": [],
        }
        policy.access_controls = {
            "purchase_item": {"max_amount": 1000, "restrict_actions": ["call_tool"]},
            "check_inventory": {"restrict_actions": ["call_tool"]},
            "read_dataset": {"restrict_actions": ["call_tool"]},
            "send_email": {"restrict_actions": ["call_tool"]},
            "spawn_agent": {"require_human_approval": True, "restrict_actions": ["call_tool"]},
        }

    # Seed a demo agent so users can test immediately
    try:
        idp.register_agent("demo-agent", "shopping_agent", ["purchase_item", "check_inventory"])
        demo_token = idp.issue_token("demo-agent", "shopping_agent", ["purchase_item", "check_inventory"])["token"]
        logger.info(f"Seeded demo-agent. Token (first 40 chars): {demo_token[:40]}...")
    except HTTPException:
        logger.info("demo-agent already exists, skipping seed")

    app = create_smol_app(idp, vault, policy, audit)
    print(f"\n  🛡️  ZT Gateway running in SMOL mode at http://{settings.host}:{settings.port}")
    print(f"  🔑  Demo token: {demo_token[:48]}...\n")
    logger.info(f"Listening on http://{settings.host}:{settings.port}")
    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level.lower())
