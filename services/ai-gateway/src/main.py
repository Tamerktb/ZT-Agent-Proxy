"""
Entry point for the Zero Trust AI Gateway service.
Runs a FastAPI server that sits between AI agents and their tools.
Every agent action passes through 5 middleware stages before approval.
"""
import os
import sys
import logging
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from src.config import settings
from src.routers import agents, admin

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from shared.production import setup_logging, register_shutdown, security_headers_middleware, add_metrics

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Zero Trust AI Gateway", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.middleware("http")(security_headers_middleware)

add_metrics(app, "gateway")

app.include_router(agents.router)
app.include_router(admin.router)

DEPENDENCIES = [
    ("identity-provider", settings.identity_provider_url),
    ("credential-vault", settings.credential_vault_url),
    ("policy-engine", settings.policy_engine_url),
    ("audit-service", settings.audit_service_url),
]


@app.get("/health")
async def health():
    deps = {}
    all_healthy = True
    async with httpx.AsyncClient(timeout=3.0) as client:
        for name, url in DEPENDENCIES:
            try:
                r = await client.get(f"{url}/health")
                deps[name] = "healthy" if r.status_code == 200 else "unhealthy"
                if r.status_code != 200:
                    all_healthy = False
            except Exception:
                deps[name] = "unreachable"
                all_healthy = False
    return {"status": "healthy" if all_healthy else "degraded", "service": "ai-gateway", "dependencies": deps}


@app.get("/ready")
async def ready():
    async with httpx.AsyncClient(timeout=2.0) as client:
        for name, url in DEPENDENCIES:
            try:
                r = await client.get(f"{url}/health")
                if r.status_code != 200:
                    return JSONResponse({"status": "not_ready", "dependency": name}, status_code=503)
            except Exception:
                return JSONResponse({"status": "not_ready", "dependency": name}, status_code=503)
    return {"status": "ready"}


@app.get("/")
async def root():
    return {
        "service": "Zero Trust AI Gateway",
        "version": "1.0.0",
        "status": "running",
        "pipeline": ["auth", "policy", "rate_limit", "prompt_inspection", "audit"],
    }

register_shutdown()
