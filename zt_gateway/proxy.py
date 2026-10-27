"""
Proxy core — HTTP forwarding + CONNECT tunnels, wired to detect/policy/audit.

Fix vs 1.0: CONNECT was one-way (both pipe tasks read from the client, so
HTTPS responses never came back). Now uses plain blocking sockets in two
threads: client->remote and remote->client.
"""
import os
import re
import json
import time
import uuid
import socket
import logging
import threading
import socketserver
import urllib.parse
from collections import defaultdict

import httpx
from fastapi.responses import Response
from prometheus_client import Counter, Histogram

from .detect import inspect_text
from .policy import Policy

logger = logging.getLogger(__name__)

PROXY_HOST = os.environ.get("ZT_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.environ.get("ZT_PROXY_PORT", "8000"))
MGMT_PORT = int(os.environ.get("ZT_MGMT_PORT", "8080"))
RATE_LIMIT_PER_MIN = int(os.environ.get("ZT_RATE_LIMIT", "60"))
MAX_BODY_SCAN = 512 * 1024          # inspect first 512 KiB of any body/response
MAX_REQUEST_BODY = 8 * 1024 * 1024  # cap on a buffered request body (8 MiB)


def read_chunked_body(rfile, limit: int = MAX_REQUEST_BODY) -> bytes:
    """Decode a chunked transfer-encoded body so it can actually be inspected.

    v1.2 fix: chunked requests carried no Content-Length, so the body was never
    read and never scanned — a trivial inspection bypass.
    """
    body = bytearray()
    while len(body) < limit:
        line = rfile.readline(65536).strip()
        if not line:
            break
        try:
            size = int(line.split(b";")[0], 16)
        except ValueError:
            break
        if size <= 0:
            rfile.readline(65536)   # CRLF after the terminating chunk
            break
        body += rfile.read(min(size, limit - len(body)))
        rfile.readline(65536)       # CRLF after each chunk
    return bytes(body)

# Prometheus
PROXY_REQS = Counter("zt_proxy_requests_total", "Proxy requests", ["decision"])
PROXY_FINDINGS = Counter("zt_proxy_findings_total", "Detection findings", ["category", "rule_id"])
PROXY_LATENCY = Histogram("zt_proxy_duration_seconds", "Proxy request duration")

HOP_BY_HOP = {"proxy-connection", "keep-alive", "transfer-encoding", "te", "connection",
              "proxy-authorization", "proxy-authenticate", "upgrade"}

proxy_stats = {"total": 0, "proxied": 0, "tunneled": 0, "blocked": 0, "warned": 0, "errors": 0}
_stats_lock = threading.Lock()
rate_limit_buckets: dict = defaultdict(list)
_rate_lock = threading.Lock()

audit = None          # AuditService, set by smol_app.run()
policy: Policy = None  # set by smol_app.run()


def _bump(key: str):
    with _stats_lock:
        proxy_stats[key] = proxy_stats.get(key, 0) + 1


def _resolve_policy() -> Policy:
    global policy
    if policy is None:
        policy = Policy()
    return policy


def _resolve_audit():
    global audit
    if audit is None:
        from .audit import AuditService
        audit = AuditService()
    return audit


def check_rate_limit(host: str) -> dict:
    limit = _resolve_policy().config.get("rate_limit_per_min") or RATE_LIMIT_PER_MIN
    now = time.time()
    with _rate_lock:
        times = rate_limit_buckets[host]
        rate_limit_buckets[host] = [t for t in times if now - t < 60]
        if len(rate_limit_buckets[host]) >= limit:
            return {"allowed": False, "reason": f"rate limit: {limit} req/min to {host}"}
        rate_limit_buckets[host].append(now)
    return {"allowed": True}


def _decide(findings: list) -> dict:
    """Resolve findings through the policy engine.
    Returns {'action': block|warn|log, 'rules': [...]} — highest severity first."""
    if not findings:
        return {"action": None, "rules": []}
    pol = _resolve_policy()
    order = {"block": 0, "warn": 1, "log": 2}
    actions = {pol.action_for(f["category"]) for f in findings}
    if "block" in actions:
        action = "block"
    elif "warn" in actions:
        action = "warn"
    else:
        action = "log"
    return {"action": action, "rules": findings}


def handle_http_proxy(method: str, url: str, headers: dict, body: bytes) -> Response:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "unknown"
    trace_id = uuid.uuid4().hex[:12]
    start = time.time()
    pol = _resolve_policy()
    aud = _resolve_audit()

    def blocked(status, reason, rules, extra=None):
        _bump("blocked"); _bump("total")
        PROXY_REQS.labels(decision="blocked").inc()
        for r in rules:
            PROXY_FINDINGS.labels(category=r["category"], rule_id=r["rule_id"]).inc()
        aud.log(method, url, status, "BLOCKED", reason=reason,
                bytes_sent=len(body), rules=rules, trace_id=trace_id)
        logger.warning(f"[{trace_id}] BLOCKED {method} {url}: {reason}")
        payload = {"error": reason, "trace_id": trace_id, "rules": rules}
        if extra:
            payload.update(extra)
        return Response(status_code=status, content=json.dumps(payload),
                        media_type="application/json")

    # 1. Egress domain policy
    allowed, why = pol.domain_allowed(host)
    if not allowed:
        return blocked(403, why, [], {"category": "egress"})

    # 2. Rate limit
    rl = check_rate_limit(host)
    if not rl["allowed"]:
        _bump("blocked"); _bump("total")
        PROXY_REQS.labels(decision="rate_limited").inc()
        aud.log(method, url, 429, "BLOCKED", reason=rl["reason"], trace_id=trace_id)
        return Response(status_code=429, content=json.dumps({"error": rl["reason"], "trace_id": trace_id}),
                        media_type="application/json")

    # 3. Request inspection (rules -> policy action)
    text = f"{method} {url} " + body[:MAX_BODY_SCAN].decode("utf-8", errors="replace")
    decision = _decide(inspect_text(text))
    if decision["action"] == "block":
        first = decision["rules"][0]
        return blocked(400, f"{first['category']} detected by {first['rule_id']} ({first['name']})",
                       decision["rules"])
    warned = decision["action"] == "warn"

    # 4. Forward
    fwd_headers = {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}
    try:
        with httpx.Client(timeout=60.0, follow_redirects=False) as client:
            resp = client.request(method, url, headers=fwd_headers, content=body)
        dur = int((time.time() - start) * 1000)
        PROXY_LATENCY.observe(dur)

        # 5. Response inspection (secret/PII leakage back to the agent)
        ctype = resp.headers.get("content-type", "")
        resp_decision = {"action": None, "rules": []}
        if not ctype or any(t in ctype for t in ("text", "json", "xml", "javascript", "html")):
            resp_text = resp.text[:MAX_BODY_SCAN]
            resp_decision = _decide(inspect_text(resp_text))
            if resp_decision["action"] == "block":
                for r in resp_decision["rules"]:
                    PROXY_FINDINGS.labels(category=r["category"], rule_id=r["rule_id"]).inc()
                aud.log(method, url, 400, "BLOCKED",
                        reason=f"response: {resp_decision['rules'][0]['name']}",
                        bytes_sent=len(body), bytes_received=len(resp.content),
                        duration_ms=dur, rules=resp_decision["rules"], trace_id=trace_id)
                _bump("blocked"); _bump("total")
                PROXY_REQS.labels(decision="blocked").inc()
                return Response(status_code=400,
                                content=json.dumps({"error": "response blocked by security policy",
                                                    "trace_id": trace_id, "rules": resp_decision["rules"]}),
                                media_type="application/json")
            if resp_decision["action"] == "warn":
                warned = True
                decision["rules"] = decision["rules"] + resp_decision["rules"]

        all_rules = decision["rules"] + (resp_decision["rules"] if resp_decision["action"] else [])
        if warned:
            _bump("warned"); _bump("total")
            PROXY_REQS.labels(decision="warned").inc()
            aud.log(method, url, resp.status_code, "WARNED",
                    reason="; ".join(f"{r['rule_id']}:{r['name']}" for r in all_rules),
                    bytes_sent=len(body), bytes_received=len(resp.content),
                    duration_ms=dur, rules=all_rules, trace_id=trace_id)
            logger.warning(f"[{trace_id}] WARN {method} {url} -> {resp.status_code}: "
                           f"{[r['rule_id'] for r in all_rules]}")
        else:
            _bump("proxied"); _bump("total")
            PROXY_REQS.labels(decision="proxied").inc()
            aud.log(method, url, resp.status_code, "PROXIED",
                    bytes_sent=len(body), bytes_received=len(resp.content),
                    duration_ms=dur, rules=all_rules, trace_id=trace_id)
            logger.info(f"[{trace_id}] {method} {url} -> {resp.status_code} ({dur}ms)")

        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in HOP_BY_HOP}
        resp_headers["X-ZT-Trace-Id"] = trace_id
        if warned:
            resp_headers["X-ZT-Warnings"] = ",".join(r["rule_id"] for r in all_rules)
        return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)
    except Exception as e:
        _bump("errors"); _bump("total")
        PROXY_REQS.labels(decision="error").inc()
        aud.log(method, url, 502, "ERROR", reason=str(e), trace_id=trace_id)
        return Response(status_code=502, content=json.dumps({"error": f"proxy error: {e}",
                                                             "trace_id": trace_id}),
                        media_type="application/json")


def handle_connect_raw(client_sock, target: str):
    """Bidirectional CONNECT tunnel (fixed: was client->remote only)."""
    trace_id = uuid.uuid4().hex[:12]
    start = time.time()
    aud = _resolve_audit()
    pol = _resolve_policy()
    try:
        host, _, port_s = target.rpartition(":")
        port = int(port_s)
        if not host:
            raise ValueError("no host")
    except ValueError:
        client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        return

    allowed, why = pol.domain_allowed(host)
    if not allowed:
        _bump("blocked"); _bump("total")
        PROXY_REQS.labels(decision="blocked").inc()
        aud.log("CONNECT", target, 403, "BLOCKED", reason=why, trace_id=trace_id)
        client_sock.sendall(f"HTTP/1.1 403 Forbidden\r\nX-ZT-Reason: {why}\r\n\r\n".encode())
        return

    rl = check_rate_limit(host)
    if not rl["allowed"]:
        _bump("blocked"); _bump("total")
        PROXY_REQS.labels(decision="rate_limited").inc()
        aud.log("CONNECT", target, 429, "BLOCKED", reason=rl["reason"], trace_id=trace_id)
        client_sock.sendall(b"HTTP/1.1 429 Too Many Requests\r\n\r\n")
        return

    try:
        remote = socket.create_connection((host, port), timeout=30)
    except OSError as e:
        _bump("errors"); _bump("total")
        aud.log("CONNECT", target, 502, "ERROR", reason=str(e), trace_id=trace_id)
        try:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except OSError:
            pass
        return

    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    remote.settimeout(None)  # blocking mode — idle tunnels must not time out
    counters = {"sent": 0, "received": 0}
    stop = threading.Event()

    def pump(src, dst, key):
        try:
            while not stop.is_set():
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
                counters[key] += len(data)
        except OSError:
            pass
        finally:
            stop.set()
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    t = threading.Thread(target=pump, args=(client_sock, remote, "sent"), daemon=True)
    t.start()
    pump(remote, client_sock, "received")  # current thread
    t.join(timeout=5)
    remote.close()
    dur = int((time.time() - start) * 1000)
    _bump("tunneled"); _bump("total")
    PROXY_REQS.labels(decision="tunneled").inc()
    aud.log("CONNECT", target, 200, "TUNNELED", bytes_sent=counters["sent"],
            bytes_received=counters["received"], duration_ms=dur, trace_id=trace_id)
    logger.info(f"[{trace_id}] CONNECT {target} ({dur}ms, "
                f"{counters['sent']}B/{counters['received']}B)")


class ProxyTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            line = self.rfile.readline().decode("utf-8", errors="replace").strip()
            if not line:
                return
            parts = line.split()
            if len(parts) < 3:
                return
            method, target = parts[0], parts[1]
            headers = {}
            while True:
                hl = self.rfile.readline().decode("utf-8", errors="replace").strip()
                if not hl:
                    break
                if ":" in hl:
                    k, v = hl.split(":", 1)
                    headers[k.strip()] = v.strip()
            if method == "CONNECT":
                handle_connect_raw(self.request, target)
                return
            te = (headers.get("Transfer-Encoding") or headers.get("transfer-encoding") or "").lower()
            if "chunked" in te:
                body = read_chunked_body(self.rfile)   # inspect chunked bodies too
                headers = {k: v for k, v in headers.items() if k.lower() != "transfer-encoding"}
            else:
                try:
                    cl = int(headers.get("Content-Length", "0") or "0")
                except ValueError:
                    cl = 0
                cl = max(0, min(cl, MAX_REQUEST_BODY))
                body = self.rfile.read(cl) if cl > 0 else b""
            resp = handle_http_proxy(method, target, headers, body)
            reason = {200: "OK", 400: "Bad Request", 403: "Forbidden",
                      429: "Too Many Requests", 502: "Bad Gateway"}.get(resp.status_code, "OK")
            self.wfile.write(f"HTTP/1.1 {resp.status_code} {reason}\r\n".encode())
            hdrs = {k: v for k, v in dict(resp.headers).items()
                    if k.lower() not in HOP_BY_HOP}
            hdrs["Content-Length"] = str(len(resp.body))
            hdrs["Connection"] = "close"
            self.wfile.write("".join(f"{k}: {v}\r\n" for k, v in hdrs.items()).encode())
            self.wfile.write(b"\r\n")
            self.wfile.write(resp.body)
            self.wfile.flush()
        except Exception as e:
            logger.error(f"Proxy handler error: {e}")


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_proxy():
    server = ReusableTCPServer((PROXY_HOST, PROXY_PORT), ProxyTCPHandler)
    logger.info(f"Proxy listening on {PROXY_HOST}:{PROXY_PORT}")
    server.serve_forever()
