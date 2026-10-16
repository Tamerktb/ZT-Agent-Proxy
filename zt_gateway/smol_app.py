"""
ZT Agent Proxy — wiring module (v1.1).

Keeps the legacy import surface: `from zt_gateway.smol_app import
manager, proxy_stats, audit, run` still works (test_proxy.py depends on it).
Real logic lives in detect.py / policy.py / audit.py / proxy.py / manager.py.
"""
import os
import logging
from pathlib import Path

from .policy import Policy
from .audit import AuditService
from . import proxy as proxymod
from .manager import create_manager, run_manager

__all__ = ["manager", "proxy_stats", "audit", "policy", "run", "run_smol"]

LOG_LEVEL = os.environ.get("ZT_LOG_LEVEL", "INFO")
DATA_DIR = os.environ.get("ZT_DATA_DIR", os.path.join(os.path.dirname(__file__), ".data"))
PROXY_HOST = proxymod.PROXY_HOST
PROXY_PORT = proxymod.PROXY_PORT
MGMT_PORT = proxymod.MGMT_PORT

# Module-level singletons (legacy contract: tests import these names)
audit = AuditService(DATA_DIR)
policy = Policy()
proxymod.audit = audit
proxymod.policy = policy

proxy_stats = proxymod.proxy_stats
manager = create_manager(audit, policy)


def run():
    """Start proxy thread + management API (blocking)."""
    logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)
    token_state = "ENABLED" if os.environ.get("ZT_MGMT_TOKEN") else "disabled"
    print(f"\n  ZT Agent Proxy v1.1")
    print(f"  {'=' * 24}")
    print(f"  Proxy:       http://{PROXY_HOST}:{PROXY_PORT}  <- set this as HTTP_PROXY")
    print(f"  Management:  http://{PROXY_HOST}:{MGMT_PORT}  <- stats, audit, /check, dashboard")
    print(f"  Rate limit:  {proxymod.RATE_LIMIT_PER_MIN} req/min per host")
    print(f"  Mgmt auth:   {token_state}")
    print(f"  Policy:      {policy.config_path or 'defaults + env'}")
    print(f"  Actions:     {policy.config['actions']}")
    print(f"  Audit:       {audit.db_path}\n")
    run_manager(manager, PROXY_HOST, MGMT_PORT, LOG_LEVEL.lower())


def run_smol(settings=None):
    """Legacy alias (v1.0 CLI compatibility)."""
    run()
