"""
Credential Vault — issues dynamic per-action credentials with short TTLs.
Implements just-in-time access: credentials are checked out, used once, and auto-expire.
"""
import uuid
import hashlib
import time
import os
import sys
import logging
import sqlite3
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from shared.production import setup_logging, register_shutdown, security_headers_middleware, add_metrics

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Credential Vault", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.middleware("http")(security_headers_middleware)
add_metrics(app, "vault")

DATA_DIR = Path(os.environ.get("VAULT_DATA_DIR", os.path.join(os.path.dirname(__file__), "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "vault.db")

CREDENTIAL_TTL = int(os.environ.get("CREDENTIAL_TTL", "120"))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with closing(get_db()) as db:
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
        db.commit()

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
                (tool_name, cred_type, cred_value, endpoint),
            )
        db.commit()


def clean_expired():
    with closing(get_db()) as db:
        now = time.time()
        deleted = db.execute("DELETE FROM active_leases WHERE expires_at < ?", (now,)).rowcount
        if deleted:
            db.commit()
            logger.debug(f"Cleaned {deleted} expired leases")


class CredentialRequest(BaseModel):
    tool_name: str
    agent_id: str


class CredentialReturn(BaseModel):
    lease_id: str


@app.post("/api/v1/credentials/checkout")
async def checkout_credential(req: CredentialRequest):
    clean_expired()
    with closing(get_db()) as db:
        tool = db.execute("SELECT * FROM tool_credentials WHERE tool_name = ?", (req.tool_name,)).fetchone()
    if not tool:
        raise HTTPException(status_code=404, detail=f"no credentials found for tool: {req.tool_name}")

    lease_id = str(uuid.uuid4())
    expires_at = time.time() + CREDENTIAL_TTL
    rotated_value = hashlib.sha256(
        f"{tool['credential_value']}:{lease_id}:{time.time()}".encode()
    ).hexdigest()[:32]

    with closing(get_db()) as db:
        db.execute(
            "INSERT INTO active_leases (lease_id, tool_name, agent_id, credential_value, endpoint, credential_type, expires_at, issued_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (lease_id, req.tool_name, req.agent_id, rotated_value,
             tool["endpoint"], tool["credential_type"], expires_at,
             datetime.now(timezone.utc).isoformat()),
        )
        db.commit()

    logger.info(f"Credential CHECKED OUT: tool={req.tool_name} agent={req.agent_id} lease={lease_id[:8]} expires_in={CREDENTIAL_TTL}s")
    return {
        "lease_id": lease_id,
        "tool": req.tool_name,
        "agent_id": req.agent_id,
        "credential": rotated_value,
        "endpoint": tool["endpoint"],
        "type": tool["credential_type"],
        "expires_at": expires_at,
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/v1/credentials/checkin")
async def checkin_credential(req: CredentialReturn):
    with closing(get_db()) as db:
        cred = db.execute("SELECT * FROM active_leases WHERE lease_id = ?", (req.lease_id,)).fetchone()
        if not cred:
            raise HTTPException(status_code=404, detail="lease not found or already returned")
        db.execute("DELETE FROM active_leases WHERE lease_id = ?", (req.lease_id,))
        db.commit()
    logger.info(f"Credential CHECKED IN: tool={cred['tool_name']} agent={cred['agent_id']} lease={req.lease_id[:8]}")
    return {"status": "returned", "tool": cred["tool_name"], "lease_id": req.lease_id}


@app.post("/api/v1/credentials/verify")
async def verify_credential(req: CredentialReturn):
    clean_expired()
    with closing(get_db()) as db:
        cred = db.execute("SELECT * FROM active_leases WHERE lease_id = ?", (req.lease_id,)).fetchone()
    if not cred:
        raise HTTPException(status_code=401, detail="credential not found or expired")
    if time.time() > cred["expires_at"]:
        with closing(get_db()) as db:
            db.execute("DELETE FROM active_leases WHERE lease_id = ?", (req.lease_id,))
            db.commit()
        raise HTTPException(status_code=401, detail="credential expired")
    return {"valid": True, "tool": cred["tool_name"], "expires_at": cred["expires_at"]}


@app.get("/api/v1/credentials/active")
async def list_active():
    clean_expired()
    with closing(get_db()) as db:
        now = time.time()
        rows = db.execute("SELECT * FROM active_leases WHERE expires_at > ? ORDER BY expires_at DESC", (now,)).fetchall()
        leases = [dict(r) for r in rows]
    return {"active_leases": len(leases), "leases": leases}


@app.get("/health")
async def health():
    clean_expired()
    with closing(get_db()) as db:
        count = db.execute("SELECT COUNT(*) as cnt FROM active_leases").fetchone()["cnt"]
    return {"status": "healthy", "service": "credential-vault", "active_leases": count}


@app.get("/")
async def root():
    return {"service": "Credential Vault", "version": "1.0.0", "status": "running"}


init_db()
register_shutdown()
