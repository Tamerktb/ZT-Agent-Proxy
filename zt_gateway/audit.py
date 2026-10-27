"""
Audit — hash-linked SQLite chain (tamper-evident) + JSONL forensic sidecar.

Chain: every entry's hash covers the previous hash (blockchain-style).

v1.2 hardening:
  * the hash now covers EVERY meaningful field — status_code, reason,
    bytes_sent, bytes_received, duration_ms and the rules that fired — not just
    ts|method|target|decision. Altering which detections fired no longer
    verifies.
  * v1-format rows are still accepted (verified with the legacy preimage) so
    existing databases do not suddenly report COMPROMISED.
  * the genesis entry is verified too (v1 skipped index 0).
  * verification is incremental for /stats (the dashboard polls it) and full
    for the explicit /audit/verify endpoint.
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

GENESIS_SEED = b"genesis_proxy"
ZERO_HASH = "0" * 64

# Fields covered by the v2 chain hash, in fixed order.
_V2_FIELDS = ("timestamp", "method", "target", "status_code", "decision", "reason",
              "bytes_sent", "bytes_received", "duration_ms")

_TAIL_BLOCK = 65536


def canonical_rules(rules) -> str:
    """Deterministic JSON for the rules list (stable across dict ordering)."""
    if isinstance(rules, str):
        try:
            rules = json.loads(rules)
        except (json.JSONDecodeError, TypeError):
            return "[]"
    return json.dumps(rules or [], separators=(",", ":"), sort_keys=True)


def _field(row, key, default):
    v = row.get(key, default) if hasattr(row, "get") else default
    return default if v is None else v


def chain_hash_v2(row: dict, rules_json: str, prev_hash: str) -> str:
    """v2 preimage — covers all fields plus the canonical rules blob."""
    parts = [str(_field(row, f, "")) for f in _V2_FIELDS]
    parts.append(rules_json)
    parts.append(prev_hash)
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def chain_hash_v1(row: dict, prev_hash: str) -> str:
    """Legacy (1.0/1.1) preimage — kept so old rows still verify."""
    raw = f"{row['timestamp']}|{row['method']}|{row['target']}|{row['decision']}|{prev_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


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
        self._verified_upto = 0        # incremental verification watermark
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
                gh = hashlib.sha256(GENESIS_SEED).hexdigest()
                db.execute(
                    "INSERT INTO audit_chain (idx, trace_id, method, target, status_code, decision, timestamp, prev_hash, hash) "
                    "VALUES (0, 'genesis', 'system', 'init', 0, 'initialized', ?, ?, ?)",
                    (datetime.now(timezone.utc).isoformat(), ZERO_HASH, gh))
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
        rules_json = canonical_rules(rules)
        with self._lock, closing(self._get_db()) as db:
            prev = db.execute("SELECT hash FROM audit_chain ORDER BY idx DESC LIMIT 1").fetchone()
            prev_hash = prev["hash"]
            current_hash = chain_hash_v2(
                {"timestamp": ts, "method": method, "target": target[:500],
                 "status_code": status_code, "decision": decision, "reason": reason,
                 "bytes_sent": bytes_sent, "bytes_received": bytes_received,
                 "duration_ms": duration_ms},
                rules_json, prev_hash)
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

    def verify_chain(self, full: bool = False) -> dict:
        """Verify the hash chain.

        full=False (default) checks only entries added since the last call —
        cheap enough for the dashboard's /stats polling.
        full=True re-hashes the entire chain — used by /audit/verify.
        """
        with closing(self._get_db()) as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM audit_chain ORDER BY idx ASC").fetchall()]
        total = len(rows)
        if not rows:
            return {"valid": True, "entries_checked": 0, "legacy_entries": 0, "full": full}

        # genesis
        g = rows[0]
        if g.get("prev_hash") != ZERO_HASH or g.get("hash") != hashlib.sha256(GENESIS_SEED).hexdigest():
            return {"valid": False, "entries_checked": 0, "first_invalid_index": 0,
                    "reason": "genesis entry does not match", "full": full}

        start = 1 if full else max(1, min(self._verified_upto, total))
        legacy = 0
        for i in range(start, total):
            cur, prev = rows[i], rows[i - 1]
            if cur["prev_hash"] != prev["hash"]:
                return {"valid": False, "entries_checked": total, "first_invalid_index": i,
                        "reason": "prev_hash mismatch", "full": full}
            if cur["hash"] == chain_hash_v2(cur, canonical_rules(cur.get("rules")), prev["hash"]):
                continue
            if cur["hash"] == chain_hash_v1(cur, prev["hash"]):
                legacy += 1            # written by 1.0/1.1 — still valid
                continue
            return {"valid": False, "entries_checked": total, "first_invalid_index": i,
                    "reason": "hash mismatch", "full": full}

        self._verified_upto = total
        return {"valid": True, "entries_checked": total,
                "legacy_pre_1_2_entries": legacy, "full": full}

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
        v = self.verify_chain(full=False)   # incremental — safe to call per request
        return {"total_requests": total, "proxied": proxied, "tunneled": tunneled,
                "blocked": blocked, "warned": warned,
                "chain_integrity": "verified" if v["valid"] else "COMPROMISED"}

    def tail_forensics(self, n: int = 50) -> list:
        """Return the last n forensic records. Reads backwards from EOF so the
        cost is proportional to n, not to the size of the log."""
        n = max(1, min(int(n), 5000))
        try:
            with open(self.forensic_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                data = b""
                while size > 0 and data.count(b"\n") <= n:
                    step = min(_TAIL_BLOCK, size)
                    size -= step
                    f.seek(size)
                    data = f.read(step) + data
        except OSError:
            return []
        out = []
        for line in data.decode("utf-8", "replace").splitlines()[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
