"""
Identity Provider — manages Non-Human Identities (NHIs) for AI agents.
Handles agent registration, JWT issuance, and token verification.
"""
import os
import sys
import uuid
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from contextlib import closing
from pathlib import Path
import jwt
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from shared.production import setup_logging, register_shutdown, security_headers_middleware, add_metrics

setup_logging()
logger = logging.getLogger(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")
if JWT_SECRET == "zt-lab-secret-change-in-prod":
    logger.warning("Using default JWT_SECRET — set a strong secret in production")

JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = int(os.environ.get("JWT_TTL_MINUTES", "60"))

app = FastAPI(title="Identity Provider", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.middleware("http")(security_headers_middleware)
add_metrics(app, "idp")

DATA_DIR = Path(os.environ.get("IDP_DATA_DIR", os.path.join(os.path.dirname(__file__), "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "identity.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with closing(get_db()) as db:
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


class RegisterRequest(BaseModel):
    agent_id: str
    role: str
    policies: list[str] = []


class VerifyRequest(BaseModel):
    token: str


@app.post("/api/v1/nhi/register")
async def register_agent(req: RegisterRequest):
    with closing(get_db()) as db:
        existing = db.execute("SELECT agent_id FROM agents WHERE agent_id = ?", (req.agent_id,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="agent already registered")
        now = datetime.now(timezone.utc).isoformat()
        policies_str = ",".join(req.policies)
        db.execute("INSERT INTO agents (agent_id, role, policies, created_at, active) VALUES (?, ?, ?, ?, 1)",
                   (req.agent_id, req.role, policies_str, now))
        db.commit()
        logger.info(f"Registered NHI: {req.agent_id} (role: {req.role})")
        return {"agent_id": req.agent_id, "role": req.role, "policies": req.policies, "created_at": now, "active": True}


@app.post("/api/v1/nhi/token")
async def issue_token(req: RegisterRequest):
    with closing(get_db()) as db:
        agent = db.execute("SELECT * FROM agents WHERE agent_id = ? AND active = 1", (req.agent_id,)).fetchone()
    if not agent:
        raise HTTPException(status_code=401, detail="agent not registered or inactive")
    now = datetime.now(timezone.utc)
    payload = {
        "sub": req.agent_id, "role": agent["role"],
        "policies": agent["policies"].split(",") if agent["policies"] else [],
        "iat": now, "exp": now + timedelta(minutes=JWT_TTL_MINUTES), "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    with closing(get_db()) as db:
        db.execute("INSERT INTO token_log (agent_id, jti, issued_at) VALUES (?, ?, ?)",
                   (req.agent_id, payload["jti"], now.isoformat()))
        db.commit()
    logger.info(f"Issued token for {req.agent_id} (expires in {JWT_TTL_MINUTES}m)")
    return {"token": token, "expires_in": JWT_TTL_MINUTES * 60, "agent_id": req.agent_id}


@app.post("/api/v1/nhi/verify")
async def verify_token(req: VerifyRequest):
    try:
        payload = jwt.decode(req.token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        with closing(get_db()) as db:
            agent = db.execute("SELECT * FROM agents WHERE agent_id = ? AND active = 1", (payload["sub"],)).fetchone()
        if not agent:
            raise HTTPException(status_code=401, detail="agent not active")
        logger.info(f"Token verified for {payload['sub']}")
        return {"allowed": True, "agent_id": payload["sub"], "role": payload.get("role"), "policies": payload.get("policies", [])}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")


@app.get("/api/v1/nhi/agents")
async def list_agents():
    with closing(get_db()) as db:
        rows = db.execute("SELECT * FROM agents ORDER BY created_at DESC").fetchall()
    return {"agents": [dict(r) for r in rows]}


@app.get("/health")
async def health():
    with closing(get_db()) as db:
        count = db.execute("SELECT COUNT(*) as cnt FROM agents").fetchone()["cnt"]
    return {"status": "healthy", "service": "identity-provider", "agents_registered": count}


@app.get("/")
async def root():
    return {"service": "Identity Provider", "version": "1.0.0", "status": "running"}


init_db()
register_shutdown()
