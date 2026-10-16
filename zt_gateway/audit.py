"""
Audit — hash-linked SQLite chain (tamper-evident) + JSONL forensic sidecar.

Chain: every entry's hash covers the previous hash (blockchain-style).
Forensics: one JSON line per request with rule IDs / decisions, SIEM-friendly
(Kafka/Logstash/Filebeat can tail it) — ClawShield-style forensic records.
"""
import os
import json
import uuid
import hashlib
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing

logger = logging.getLogger(__name__)


class AuditService:
    def __init__(self, data_dir: str = ""):
        data_dir = data_dir or os.environ.get("ZT_DATA_DIR", "") or \
            os.path.join(os.path.dirname(__file__), ".data")
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        db_dir = Path(data_dir) / "audit"
        db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = str(db_dir / "audit.db")
        self.forensic_path = str(Path(data_dir) / "forensics.jsonl")
        self._lock = threading.Lock()  # serializes read-prev -> insert (prevents chain forks)
        self._init_db()

    def _get_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with closing(self._get_db()) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS audit_chain (
                idx INTEGER PRIMARY KEY AUTOINCREMENT, trace_id TEXT NOT NULL,
                method TEXT NOT NULL, target TEXT NOT NULL, status_code INTEGER,
                decision TEXT NOT NULL, reason TEXT DEFAULT '', bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0,
                rules TEXT DEFAULT '[]', timestamp TEXT NOT NULL,
                prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)""")
            row = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()
            if row["cnt"] == 0:
                gh = hashlib.sha256(b"genesis_proxy").hexdigest()
                db.execute(
                    "INSERT INTO audit_chain (idx, trace_id, method, target, status_code, decision, timestamp, prev_hash, hash) "
                    "VALUES (0, 'genesis', 'system', 'init', 0, 'initialized', ?, ?, ?)",
                    (datetime.now(timezone.utc).isoformat(), "0" * 64, gh))
                db.commit()
            # migrate pre-1.1 DBs: add rules column if missing
            cols = [c[1] for c in db.execute("PRAGMA table_info(audit_chain)").fetchall()]
            if "rules" not in cols:
                db.execute("ALTER TABLE audit_chain ADD COLUMN rules TEXT DEFAULT '[]'")
                db.commit()

    def log(self, method: str, target: str, status_code: int, decision: str, reason: str = "",
            bytes_sent: int = 0, bytes_received: int = 0, duration_ms: int = 0,
            rules: list = None, trace_id: str = "") -> dict:
        trace_id = trace_id or uuid.uuid4().hex[:12]
        ts = datetime.now(timezone.utc).isoformat()
        rules = rules or []
        rules_json = json.dumps(rules, separators=(",", ":"))
        with self._lock, closing(self._get_db()) as db:
            prev = db.execute("SELECT hash FROM audit_chain ORDER BY idx DESC LIMIT 1").fetchone()
            prev_hash = prev["hash"]
            raw = f"{ts}|{method}|{target}|{decision}|{prev_hash}"
            current_hash = hashlib.sha256(raw.encode()).hexdigest()
            db.execute(
                "INSERT INTO audit_chain (trace_id, method, target, status_code, decision, reason, "
                "bytes_sent, bytes_received, duration_ms, rules, timestamp, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (trace_id, method, target[:500], status_code, decision, reason,
                 bytes_sent, bytes_received, duration_ms, rules_json, ts, prev_hash, current_hash))
            db.commit()
        # Forensic JSONL sidecar (best-effort — never break the proxy)
        try:
            with open(self.forensic_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": ts, "trace_id": trace_id, "method": method, "target": target[:500],
                    "status": status_code, "decision": decision, "reason": reason,
                    "rules": rules, "bytes_out": bytes_sent, "bytes_in": bytes_received,
                    "ms": duration_ms, "chain_hash": current_hash,
                }, separators=(",", ":")) + "\n")
        except OSError:
            pass
        return {"trace_id": trace_id, "hash": current_hash}

    def get_chain(self, limit: int = 100, offset: int = 0) -> dict:
        with closing(self._get_db()) as db:
            total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"]
            rows = db.execute("SELECT * FROM audit_chain ORDER BY idx DESC LIMIT ? OFFSET ?",
                              (limit, offset)).fetchall()
        entries = []
        for r in rows:
            e = dict(r)
            try:
                e["rules"] = json.loads(e.get("rules") or "[]")
            except json.JSONDecodeError:
                e["rules"] = []
            entries.append(e)
        return {"total": total, "offset": offset, "limit": limit, "entries": entries}

    def verify_chain(self) -> dict:
        with closing(self._get_db()) as db:
            rows = db.execute("SELECT * FROM audit_chain ORDER BY idx ASC").fetchall()
        for i in range(1, len(rows)):
            cur, prev = dict(rows[i]), dict(rows[i - 1])
            if cur["prev_hash"] != prev["hash"]:
                return {"valid": False, "entries_checked": i, "first_invalid_index": i}
            raw = f"{cur['timestamp']}|{cur['method']}|{cur['target']}|{cur['decision']}|{prev['hash']}"
            if cur["hash"] != hashlib.sha256(raw.encode()).hexdigest():
                return {"valid": False, "entries_checked": i, "first_invalid_index": i}
        return {"valid": True, "entries_checked": len(rows)}

    def get_stats(self) -> dict:
        with closing(self._get_db()) as db:
            total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"] - 1
            blocked = db.execute(
                "SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'BLOCKED'").fetchone()["cnt"]
            warned = db.execute(
                "SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'WARNED'").fetchone()["cnt"]
            proxied = db.execute(
                "SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'PROXIED'").fetchone()["cnt"]
            tunneled = db.execute(
                "SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'TUNNELED'").fetchone()["cnt"]
        v = self.verify_chain()
        return {"total_requests": total, "proxied": proxied, "tunneled": tunneled,
                "blocked": blocked, "warned": warned,
                "chain_integrity": "verified" if v["valid"] else "COMPROMISED"}

    def tail_forensics(self, n: int = 50) -> list:
        try:
            with open(self.forensic_path, encoding="utf-8") as f:
                lines = f.readlines()
        except OSError:
            return []
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
