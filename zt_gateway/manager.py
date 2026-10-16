"""
Management API (port 8080) — stats, audit, /check, policy, forensics, metrics.

New in 1.1: optional bearer-token auth (ZT_MGMT_TOKEN), /check detection-only
endpoint (AIProxyGuard-style), /forensics JSONL tail, /policy view+reload,
/rule-catalog, simple HTML dashboard.
"""
import os
import hmac
import json
import logging
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from prometheus_client import make_asgi_app
import uvicorn

from . import detect
from .policy import Policy
from .audit import AuditService
from . import proxy as proxymod

logger = logging.getLogger(__name__)

MGMT_TOKEN = os.environ.get("ZT_MGMT_TOKEN", "")
PUBLIC_PATHS = {"/health", "/", "/dashboard"}

DASHBOARD_HTML = """<!doctype html><html><head><title>ZT Agent Proxy</title>
<meta http-equiv="refresh" content="5"><style>
body{font-family:ui-monospace,monospace;background:#0b0f14;color:#d7e0ea;margin:2rem}
h1{color:#5eead4} a{color:#7dd3fc} .ok{color:#4ade80} .bad{color:#f87171}
table{border-collapse:collapse;margin-top:1rem}td,th{border:1px solid #243447;padding:.4rem .8rem;text-align:left}
</style></head><body><h1>ZT Agent Proxy</h1><div id=s>loading...</div>
<script>async function r(p){const j=await (await fetch(p)).json();return j}
r('/stats').then(s=>{document.getElementById('s').innerHTML=
`<p>total <b>${s.proxy.total}</b> | proxied <b>${s.proxy.proxied}</b> | tunneled <b>${s.proxy.tunneled}</b> | `+
`blocked <b>${s.proxy.blocked}</b> | warned <b>${(s.proxy.warned||0)}</b> | errors <b>${s.proxy.errors}</b><br>`+
`chain: <span class="${s.audit.chain_integrity==='verified'?'ok':'bad'}">${s.audit.chain_integrity}</span> `+
`(blocked=${s.audit.blocked}, warned=${s.audit.warned||0})</p>`});
r('/audit/chain?limit=15').then(a=>{
 const rows=a.entries.map(e=>`<tr><td>${e.idx}</td><td>${e.method}</td>`+
 `<td>${(e.target||'').slice(0,60)}</td><td>${e.status_code}</td>`+
 `<td>${e.decision}</td><td>${e.reason||''}</td><td>${(e.rules||[]).map(x=>x.rule_id).join(' ')}</td></tr>`).join('');
 document.getElementById('s').innerHTML+=
 `<table><tr><th>#</th><th>method</th><th>target</th><th>code</th><th>decision</th><th>reason</th><th>rules</th></tr>${rows}</table>`});
</script></body></html>"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    import threading
    t = threading.Thread(target=proxymod.start_proxy, daemon=True)
    t.start()
    yield


def _auth_ok(request: Request) -> bool:
    token = os.environ.get("ZT_MGMT_TOKEN", "")
    if not token:
        return True
    hdr = request.headers.get("authorization", "")
    if hdr.startswith("Bearer "):
        return hmac.compare_digest(hdr[7:].strip(), token)
    return False


def create_manager(audit: AuditService, policy: Policy) -> FastAPI:
    app = FastAPI(title="ZT Agent Proxy", version="1.1.0", lifespan=lifespan)
    app.mount("/metrics", make_asgi_app())

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if request.url.path not in PUBLIC_PATHS and not _auth_ok(request):
            return JSONResponse(status_code=401,
                                content={"error": "management API auth required",
                                         "hint": "Authorization: Bearer <ZT_MGMT_TOKEN>"})
        return await call_next(request)

    @app.get("/")
    async def root():
        return {"service": "ZT Agent Proxy", "version": "1.1.0",
                "proxy": f"http://{proxymod.PROXY_HOST}:{proxymod.PROXY_PORT}",
                "usage": "Set HTTP_PROXY=http://host:8000 in your agent's environment",
                "auth": "enabled" if os.environ.get("ZT_MGMT_TOKEN") else "disabled",
                "endpoints": {"/stats": "proxy + audit stats",
                              "/check": "POST {text} — detection-only scan",
                              "/rule-catalog": "all detection rules with IDs",
                              "/audit/chain": "hash-chain audit log",
                              "/audit/verify": "verify chain integrity",
                              "/forensics": "tail JSONL forensic log",
                              "/policy": "effective policy (GET) / reload (POST)",
                              "/dashboard": "HTML dashboard",
                              "/metrics": "prometheus metrics"}}

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "zt-agent-proxy",
                "proxy_port": proxymod.PROXY_PORT, "requests": proxymod.proxy_stats}

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        return HTMLResponse(DASHBOARD_HTML)

    @app.get("/stats")
    async def stats():
        return {"proxy": proxymod.proxy_stats, "audit": audit.get_stats()}

    # ── Detection-only scan (AIProxyGuard-style /check) ──
    @app.post("/check")
    async def check(request: Request):
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            raise HTTPException(status_code=400, detail="body must be JSON")
        text = data.get("text", "")
        if not isinstance(text, str) or not text:
            raise HTTPException(status_code=400, detail="field 'text' (non-empty string) required")
        findings = detect.inspect_text(text[:64 * 1024])
        decision = proxymod._decide(findings)
        return {"findings": findings, "action": decision["action"] or "allow",
                "would_block": decision["action"] == "block",
                "categories_scanned": sorted({r[1] for r in detect.RULES})}

    @app.get("/rule-catalog")
    async def rule_catalog():
        rules = detect.describe()
        return {"count": len(rules), "actions": policy.config["actions"], "rules": rules}

    @app.get("/audit/chain")
    async def audit_chain(limit: int = 100, offset: int = 0):
        return audit.get_chain(limit, offset)

    @app.get("/audit/verify")
    async def audit_verify():
        return audit.verify_chain()

    @app.get("/forensics")
    async def forensics(n: int = 50):
        return {"entries": audit.tail_forensics(min(n, 500))}

    @app.get("/policy")
    async def policy_get():
        return {"config": policy.redacted(), "path": policy.config_path or "(defaults+env)"}

    @app.post("/policy/reload")
    async def policy_reload():
        cfg = policy.load()
        logger.info("Policy reloaded")
        return {"status": "reloaded", "config": cfg}

    return app


def run_manager(app: FastAPI, host: str, port: int, log_level: str = "info"):
    uvicorn.run(app, host=host, port=port, log_level=log_level)
