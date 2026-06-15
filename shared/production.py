"""
Shared production utilities for all Zero Trust Gateway services.
Import in every service: from shared.production import setup_logging, MetricsMiddleware, ...
"""
import os
import sys
import json
import signal
import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app, Counter, Histogram


def setup_logging(default_level="INFO"):
    fmt = os.environ.get("LOG_FORMAT", "text")
    level = getattr(logging, os.environ.get("LOG_LEVEL", default_level).upper(), logging.INFO)
    if fmt == "json":
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                return json.dumps({
                    "ts": self.formatTime(record),
                    "level": record.levelname,
                    "name": record.name,
                    "msg": record.getMessage(),
                    "module": record.module,
                })
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logging.basicConfig(level=level, handlers=[handler], force=True)
    else:
        logging.basicConfig(level=level)


def register_shutdown():
    logger = logging.getLogger(__name__)
    def handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        sys.exit(0)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response


def add_metrics(app: FastAPI, prefix: str = "service"):
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)
    requests_total = Counter(f"{prefix}_requests_total", "Total HTTP requests", ["method", "endpoint", "status"])
    request_duration = Histogram(f"{prefix}_request_duration_seconds", "HTTP request duration", ["method", "endpoint"])

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        import time
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start
        requests_total.labels(method=request.method, endpoint=request.url.path, status=response.status_code).inc()
        request_duration.labels(method=request.method, endpoint=request.url.path).observe(duration)
        return response


def add_readiness_endpoint(app: FastAPI, deps: list[tuple[str, str]]):
    import httpx

    @app.get("/ready")
    async def ready():
        async with httpx.AsyncClient(timeout=2.0) as client:
            for name, url in deps:
                try:
                    r = await client.get(f"{url}/health")
                    if r.status_code != 200:
                        return JSONResponse({"status": "not_ready", "dependency": name}, status_code=503)
                except Exception:
                    return JSONResponse({"status": "not_ready", "dependency": name}, status_code=503)
        return {"status": "ready"}
