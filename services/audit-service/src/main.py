"""
Audit Service — maintains an immutable hash-chain log of all agent actions.
Each entry contains a SHA256 hash of the previous entry (blockchain-style).
Provides chain verification endpoint to detect any tampering with logs.
"""
import sqlite3
import hashlib
import logging
import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from shared.production import setup_logging, register_shutdown, security_headers_middleware, add_metrics

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Audit Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.middleware("http")(security_headers_middleware)
add_metrics(app, "audit")

DATA_DIR = Path(os.environ.get("AUDIT_DATA_DIR", os.path.join(os.path.dirname(__file__), "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = str(DATA_DIR / "audit.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db():
    with closing(get_db()) as db:
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
                (datetime.now(timezone.utc).isoformat(), "0" * 64, genesis_hash),
            )
            db.commit()
            logger.info("Initialized genesis block in audit chain")

        db.commit()


class LogEntry(BaseModel):
    trace_id: str
    agent_id: str
    action_type: str
    target: str
    input_hash: str
    decision: str
    timestamp: str
    decisions: list = []


class ChainVerifyResult(BaseModel):
    valid: bool
    entries_checked: int
    first_invalid_index: int = -1


@app.post("/api/v1/audit/log")
async def log_entry(entry: LogEntry):
    with closing(get_db()) as db:
        prev = db.execute("SELECT hash FROM audit_chain ORDER BY idx DESC LIMIT 1").fetchone()
        prev_hash = prev["hash"]

        raw = f"{entry.timestamp}|{entry.agent_id}|{entry.action_type}|{entry.target}|{entry.decision}|{prev_hash}"
        current_hash = hashlib.sha256(raw.encode()).hexdigest()

        decisions_json = json.dumps([d if isinstance(d, dict) else d.model_dump() for d in entry.decisions])

        db.execute(
            "INSERT INTO audit_chain (trace_id, agent_id, action_type, target, input_hash, decision, timestamp, prev_hash, hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (entry.trace_id, entry.agent_id, entry.action_type, entry.target,
             entry.input_hash, entry.decision, entry.timestamp, prev_hash, current_hash),
        )
        db.commit()
        idx = db.execute("SELECT idx FROM audit_chain WHERE hash = ?", (current_hash,)).fetchone()["idx"]

    log_decision = (
        f"ALLOWED: {entry.agent_id} -> {entry.action_type} on {entry.target}"
        if entry.decision == "ALLOWED"
        else f"DENIED ({entry.decision}): {entry.agent_id} -> {entry.action_type} on {entry.target}"
    )
    logger.info(f"Audit logged [{idx}]: {log_decision}")
    return {"index": idx, "hash": current_hash, "status": "logged"}


@app.get("/api/v1/audit/chain")
async def get_chain(limit: int = 50, offset: int = 0):
    with closing(get_db()) as db:
        total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"]
        rows = db.execute(
            "SELECT * FROM audit_chain ORDER BY idx ASC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        entries = [dict(r) for r in rows]
    return {"total": total, "offset": offset, "limit": limit, "entries": entries}


@app.get("/api/v1/audit/chain/verify")
async def verify_chain():
    with closing(get_db()) as db:
        rows = db.execute("SELECT * FROM audit_chain ORDER BY idx ASC").fetchall()

    for i in range(1, len(rows)):
        current = dict(rows[i])
        prev = dict(rows[i - 1])

        if current["prev_hash"] != prev["hash"]:
            return ChainVerifyResult(valid=False, entries_checked=i, first_invalid_index=i)

        raw = f"{current['timestamp']}|{current['agent_id']}|{current['action_type']}|{current['target']}|{current['decision']}|{prev['hash']}"
        expected_hash = hashlib.sha256(raw.encode()).hexdigest()
        if current["hash"] != expected_hash:
            return ChainVerifyResult(valid=False, entries_checked=i, first_invalid_index=i)

    return ChainVerifyResult(valid=True, entries_checked=len(rows))


@app.get("/api/v1/audit/agent/{agent_id}")
async def get_agent_audit(agent_id: str):
    with closing(get_db()) as db:
        total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE agent_id = ?", (agent_id,)).fetchone()["cnt"]
        rows = db.execute(
            "SELECT * FROM audit_chain WHERE agent_id = ? ORDER BY idx DESC LIMIT 50",
            (agent_id,),
        ).fetchall()
        entries = [dict(r) for r in rows]
    return {"agent_id": agent_id, "total_actions": total, "entries": entries}


@app.get("/api/v1/audit/stats")
async def get_stats():
    with closing(get_db()) as db:
        total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"] - 1
        allowed = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'ALLOWED'").fetchone()["cnt"]
        denied = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE decision LIKE 'DENIED%'").fetchone()["cnt"]
        verify = await verify_chain()
    return {
        "total_actions": total,
        "allowed": allowed,
        "denied": denied,
        "chain_integrity": "verified" if verify.valid else "COMPROMISED",
    }


@app.get("/health")
async def health():
    with closing(get_db()) as db:
        length = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"]
    return {"status": "healthy", "service": "audit-service", "chain_length": length}


@app.get("/")
async def root():
    return {"service": "Audit Service", "version": "1.0.0", "status": "running"}


init_db()
register_shutdown()
