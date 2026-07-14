"""
Transparent HTTP forward proxy for AI agents.
Set HTTP_PROXY=http://localhost:8000 and every API call routes through here.
Inspects requests for leaks/injections, rate-limits, and logs everything to a hash chain.

Two ports in one process:
  - Proxy port (8000): set HTTP_PROXY to this
  - Management port (8080): /stats, /audit/chain, /health, /metrics
"""
import os
import re
import json
import time
import uuid
import hashlib
import logging
import asyncio
import socket
import socketserver
import sqlite3
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from contextlib import closing, asynccontextmanager
from collections import defaultdict

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import Response, JSONResponse
from prometheus_client import make_asgi_app
import uvicorn

logger = logging.getLogger(__name__)

# ─── Config ────────────────────────────────────────────────────────────────

PROXY_HOST = os.environ.get("ZT_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("ZT_PROXY_PORT", "8000"))
MGMT_PORT = int(os.environ.get("ZT_MGMT_PORT", "8080"))
DATA_DIR = os.environ.get("ZT_DATA_DIR", os.path.join(os.path.dirname(__file__), ".data"))
RATE_LIMIT_PER_MIN = int(os.environ.get("ZT_RATE_LIMIT", "60"))
LOG_LEVEL = os.environ.get("ZT_LOG_LEVEL", "INFO")

# ─── Prompt Inspection ─────────────────────────────────────────────────────

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+(instructions|directions|commands)",
    r"forget\s+(all\s+)?(previous|prior)\s+(instructions|directions|commands)",
    r"you\s+are\s+(now|not\s+bound|free)",
    r"override\s+(your\s+)?(instructions|programming|directives)",
    r"system\s+(prompt|instruction|message)",
    r"disregard\s+(all\s+)?(rules|policies|safety)",
    r"simulate\s+(a\s+)?(different|new)\s+(persona|role|character)",
    r"DAN\b", r"sudo\s+mode", r"developer\s+mode",
    r"reveal\s+(your\s+)?(system|prompt|instructions)",
    r"output\s+your\s+(prompt|instructions|system\s+message)",
    r"leak\s+(the\s+)?(prompt|api[-\s]?key|secret|token|password)",
]
EXFILTRATION_PATTERNS = [
    r"(credit\s*card|ssn|social\s*security|passport)",
    r"(api[-\s]?key|secret\s*key|access\s*token)",
    r"(password|passwd|pwd)\s*[:=]\s*\S+",
]

def inspect_text(text: str) -> dict:
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {"allowed": False, "reason": "prompt injection detected"}
    for pattern in EXFILTRATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return {"allowed": False, "reason": "data exfiltration attempt detected"}
    return {"allowed": True}

# ─── Audit Service (embedded hash chain) ───────────────────────────────────

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
        return conn

    def _init_db(self):
        with closing(self._get_db()) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS audit_chain (
                idx INTEGER PRIMARY KEY AUTOINCREMENT, trace_id TEXT NOT NULL,
                method TEXT NOT NULL, target TEXT NOT NULL, status_code INTEGER,
                decision TEXT NOT NULL, reason TEXT DEFAULT '', bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0, duration_ms INTEGER DEFAULT 0,
                timestamp TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE)""")
            row = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()
            if row["cnt"] == 0:
                gh = hashlib.sha256(b"genesis_proxy").hexdigest()
                db.execute("INSERT INTO audit_chain (idx, trace_id, method, target, status_code, decision, timestamp, prev_hash, hash) VALUES (0, 'genesis', 'system', 'init', 0, 'initialized', ?, ?, ?)",
                           (datetime.now(timezone.utc).isoformat(), "0" * 64, gh))
                db.commit()

    def log(self, method: str, target: str, status_code: int, decision: str, reason: str = "",
            bytes_sent: int = 0, bytes_received: int = 0, duration_ms: int = 0) -> dict:
        trace_id = uuid.uuid4().hex[:12]
        ts = datetime.now(timezone.utc).isoformat()
        with closing(self._get_db()) as db:
            prev = db.execute("SELECT hash FROM audit_chain ORDER BY idx DESC LIMIT 1").fetchone()
            prev_hash = prev["hash"]
            raw = f"{ts}|{method}|{target}|{decision}|{prev_hash}"
            current_hash = hashlib.sha256(raw.encode()).hexdigest()
            db.execute("INSERT INTO audit_chain (trace_id, method, target, status_code, decision, reason, bytes_sent, bytes_received, duration_ms, timestamp, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (trace_id, method, target[:500], status_code, decision, reason, bytes_sent, bytes_received, duration_ms, ts, prev_hash, current_hash))
            db.commit()
        return {"trace_id": trace_id, "hash": current_hash}

    def get_chain(self, limit: int = 100, offset: int = 0) -> dict:
        with closing(self._get_db()) as db:
            total = db.execute("SELECT COUNT(*) as cnt FROM audit_chain").fetchone()["cnt"]
            rows = db.execute("SELECT * FROM audit_chain ORDER BY idx DESC LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        return {"total": total, "offset": offset, "limit": limit, "entries": [dict(r) for r in rows]}

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
            blocked = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'BLOCKED'").fetchone()["cnt"]
            proxied = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'PROXIED'").fetchone()["cnt"]
            tunneled = db.execute("SELECT COUNT(*) as cnt FROM audit_chain WHERE decision = 'TUNNELED'").fetchone()["cnt"]
        v = self.verify_chain()
        return {"total_requests": total, "proxied": proxied, "tunneled": tunneled, "blocked": blocked,
                "chain_integrity": "verified" if v["valid"] else "COMPROMISED"}

# ─── Proxy Core ────────────────────────────────────────────────────────────

audit = None
proxy_stats = {"total": 0, "proxied": 0, "tunneled": 0, "blocked": 0, "errors": 0}
rate_limit_buckets: dict = defaultdict(list)
HOP_BY_HOP = {"proxy-connection", "keep-alive", "transfer-encoding", "te", "connection",
              "proxy-authorization", "proxy-authenticate", "upgrade"}

def check_rate_limit(host: str) -> dict:
    now = time.time()
    times = rate_limit_buckets[host]
    rate_limit_buckets[host] = [t for t in times if now - t < 60]
    if len(rate_limit_buckets[host]) >= RATE_LIMIT_PER_MIN:
        return {"allowed": False, "reason": f"rate limit: {RATE_LIMIT_PER_MIN} req/min to {host}"}
    rate_limit_buckets[host].append(now)
    return {"allowed": True}

def handle_http_proxy(method: str, url: str, headers: dict, body: bytes) -> Response:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "unknown"
    trace_id = uuid.uuid4().hex[:12]
    start = time.time()

    text = f"{method} {url} {body.decode('utf-8', errors='replace')}"
    insp = inspect_text(text)
    if not insp["allowed"]:
        proxy_stats["blocked"] += 1
        proxy_stats["total"] += 1
        audit.log(method, url, 400, "BLOCKED", reason=insp["reason"])
        logger.warning(f"[{trace_id}] BLOCKED {method} {url}: {insp['reason']}")
        return Response(status_code=400, content=json.dumps({"error": insp["reason"], "trace_id": trace_id}), media_type="application/json")

    rl = check_rate_limit(host)
    if not rl["allowed"]:
        proxy_stats["blocked"] += 1
        proxy_stats["total"] += 1
        audit.log(method, url, 429, "BLOCKED", reason=rl["reason"])
        return Response(status_code=429, content=json.dumps({"error": rl["reason"], "trace_id": trace_id}), media_type="application/json")

    fwd_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
    try:
        with httpx.Client(timeout=60.0, follow_redirects=False) as client:
            resp = client.request(method, url, headers=fwd_headers, content=body)
        dur = int((time.time() - start) * 1000)

        resp_text = resp.text[:512 * 1024]
        resp_insp = inspect_text(resp_text)
        if not resp_insp["allowed"]:
            proxy_stats["blocked"] += 1
            proxy_stats["total"] += 1
            audit.log(method, url, 400, "BLOCKED", reason=f"response: {resp_insp['reason']}")
            return Response(status_code=400, content=json.dumps({"error": "response blocked by security policy", "trace_id": trace_id}), media_type="application/json")

        proxy_stats["proxied"] += 1
        proxy_stats["total"] += 1
        audit.log(method, url, resp.status_code, "PROXIED", bytes_sent=len(body), bytes_received=len(resp.content), duration_ms=dur)
        logger.info(f"[{trace_id}] {method} {url} -> {resp.status_code} ({dur}ms)")
        resp_headers = dict(resp.headers)
        return Response(content=resp.content, status_code=resp.status_code, headers={k: v for k, v in resp_headers.items() if k.lower() not in HOP_BY_HOP})
    except Exception as e:
        proxy_stats["errors"] += 1
        proxy_stats["total"] += 1
        audit.log(method, url, 502, "ERROR", reason=str(e))
        return Response(status_code=502, content=json.dumps({"error": f"proxy error: {e}", "trace_id": trace_id}), media_type="application/json")

# ─── Proxy TCP Server (threaded, no asyncio conflicts) ────────────────────

class ProxyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            line = self.rfile.readline().decode("utf-8", errors="replace").strip()
            if not line: return
            parts = line.split()
            if len(parts) < 3: return
            method, target = parts[0], parts[1]
            headers = {}
            while True:
                hl = self.rfile.readline().decode("utf-8", errors="replace").strip()
                if not hl: break
                if ":" in hl:
                    k, v = hl.split(":", 1); headers[k.strip()] = v.strip()
            if method == "CONNECT":
                asyncio.run(handle_connect_raw(self.request, target))
            else:
                cl = int(headers.get("Content-Length", "0"))
                body = self.rfile.read(cl) if cl > 0 else b""
                resp = handle_http_proxy(method, target, headers, body)  # sync now
                sl = f"HTTP/1.1 {resp.status_code}\r\n"
                hl = "".join(f"{k}: {v}\r\n" for k, v in dict(resp.headers).items() if k.lower() not in HOP_BY_HOP)
                self.wfile.write(f"{sl}{hl}\r\n".encode())
                self.wfile.write(resp.body)
                self.wfile.flush()
        except Exception as e:
            logger.error(f"Proxy handler error: {e}")

async def handle_connect_raw(client_sock, target: str):
    """Handle CONNECT tunnel using the raw socket."""
    trace_id = uuid.uuid4().hex[:12]
    start = time.time()
    try:
        host, port = target.split(":"); port = int(port)
    except ValueError:
        client_sock.send(b"HTTP/1.1 400 Bad Request\r\n\r\n"); return
    rl = check_rate_limit(host)
    if not rl["allowed"]:
        proxy_stats["blocked"] += 1; proxy_stats["total"] += 1
        audit.log("CONNECT", target, 429, "BLOCKED", reason=rl["reason"])
        client_sock.send(f"HTTP/1.1 429 Too Many Requests\r\n\r\n".encode()); return
    try:
        r_reader, r_writer = await asyncio.open_connection(host, port)
        client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        loop = asyncio.get_event_loop()
        sent = received = 0
        async def pipe(dst_writer, src_sock, name):
            nonlocal sent, received
            try:
                while True:
                    data = await loop.run_in_executor(None, src_sock.recv, 65536)
                    if not data: break
                    dst_writer.write(data); await dst_writer.drain()
                    if name == "sent": sent += len(data)
                    else: received += len(data)
            except (ConnectionResetError, BrokenPipeError, OSError): pass
        t1 = asyncio.create_task(pipe(r_writer, client_sock, "sent"))
        t2 = asyncio.create_task(pipe(r_writer, client_sock, "received"))
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
        dur = int((time.time() - start) * 1000)
        proxy_stats["tunneled"] += 1; proxy_stats["total"] += 1
        audit.log("CONNECT", target, 200, "TUNNELED", bytes_sent=sent, bytes_received=received, duration_ms=dur)
        logger.info(f"[{trace_id}] CONNECT {target} ({dur}ms, {sent}B/{received}B)")
        r_writer.close()
    except (ConnectionRefusedError, OSError, asyncio.TimeoutError) as e:
        proxy_stats["errors"] += 1; proxy_stats["total"] += 1
        audit.log("CONNECT", target, 502, "ERROR", reason=str(e))
        client_sock.send(f"HTTP/1.1 502 Bad Gateway\r\n\r\n".encode())

class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

def start_proxy():
    server = ReusableTCPServer((PROXY_HOST, PROXY_PORT), ProxyTCPHandler)
    logger.info(f"Proxy listening on {PROXY_HOST}:{PROXY_PORT}")
    server.serve_forever()

# ─── Management API (FastAPI) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    import threading
    t = threading.Thread(target=start_proxy, daemon=True)
    t.start()
    yield

manager = FastAPI(title="ZT Agent Proxy", version="1.0.0", lifespan=lifespan)
metrics_app = make_asgi_app()
manager.mount("/metrics", metrics_app)

@manager.get("/")
async def root():
    return {"service": "ZT Agent Proxy", "version": "1.0.0",
            "proxy": f"http://{PROXY_HOST}:{PROXY_PORT}",
            "usage": "Set HTTP_PROXY=http://host:8000 in your agent's environment",
            "endpoints": {"/stats": "proxy + audit stats",
                          "/audit/chain": "hash-chain audit log",
                          "/audit/verify": "verify chain integrity",
                          "/metrics": "prometheus metrics"}}

@manager.get("/health")
async def health():
    return {"status": "healthy", "service": "zt-agent-proxy",
            "proxy_port": PROXY_PORT, "requests": proxy_stats}

@manager.get("/stats")
async def stats():
    return {"proxy": proxy_stats, "audit": audit.get_stats() if audit else {}}

@manager.get("/audit/chain")
async def audit_chain(limit: int = 100, offset: int = 0):
    return audit.get_chain(limit, offset) if audit else {"error": "not initialized"}

@manager.get("/audit/verify")
async def audit_verify():
    return audit.verify_chain() if audit else {"error": "not initialized"}

# ─── Entry Point ───────────────────────────────────────────────────────────

def run():
    global audit
    logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    audit = AuditService(DATA_DIR)

    print(f"\n  ZT Agent Proxy")
    print(f"  {'=' * 20}")
    print(f"  Proxy:       http://{PROXY_HOST}:{PROXY_PORT}  <- set this as HTTP_PROXY")
    print(f"  Management:  http://{PROXY_HOST}:{MGMT_PORT}  <- stats, audit, metrics")
    print(f"  Rate limit:  {RATE_LIMIT_PER_MIN} req/min per host")
    print(f"  Audit:       {Path(DATA_DIR) / 'audit' / 'audit.db'}\n")

    uvicorn.run(manager, host=PROXY_HOST, port=MGMT_PORT, log_level=LOG_LEVEL.lower())


# Legacy compatibility alias
def run_smol(settings=None):
    run()
