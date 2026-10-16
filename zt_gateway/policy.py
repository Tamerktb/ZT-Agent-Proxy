"""
Policy layer — resolves what to do with each detection.

- Per-category actions: block | warn | log (AIProxyGuard-style policy engine)
- Domain allow/deny lists (FireClaw-style egress control)
- Config from JSON file or environment; hot-reloadable via /policy/reload
"""
import os
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

VALID_ACTIONS = ("block", "warn", "log")

DEFAULT_CONFIG = {
    "actions": {
        "injection": "block",
        "pii": "block",
        "secret": "block",
        "vuln": "block",
    },
    "domains": {
        "allow": [],            # non-empty => allowlist mode (default deny)
        "block": [],            # always denied
        "allow_subdomains": True,
    },
    "rate_limit_per_min": 0,     # 0 => use ZT_RATE_LIMIT env
}


class Policy:
    def __init__(self, config_path: str = ""):
        self.config_path = config_path or os.environ.get("ZT_POLICY_FILE", "")
        self._config = None
        self.load()

    def load(self) -> dict:
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
        if self.config_path and Path(self.config_path).exists():
            try:
                user_cfg = json.loads(Path(self.config_path).read_text(encoding="utf-8"))
                for key in ("actions", "domains"):
                    if isinstance(user_cfg.get(key), dict):
                        cfg[key].update(user_cfg[key])
                if isinstance(user_cfg.get("rate_limit_per_min"), int):
                    cfg["rate_limit_per_min"] = user_cfg["rate_limit_per_min"]
                logger.info(f"Policy loaded from {self.config_path}")
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Policy file unreadable ({e}) — using defaults")
        # Env overrides (comma-separated domains)
        for env_key, dom_key in (("ZT_ALLOW_DOMAINS", "allow"), ("ZT_BLOCK_DOMAINS", "block")):
            raw = os.environ.get(env_key, "")
            if raw:
                cfg["domains"][dom_key] = [d.strip().lower() for d in raw.split(",") if d.strip()]
        for cat in cfg["actions"]:
            env = os.environ.get(f"ZT_ACTION_{cat.upper()}", "")
            if env in VALID_ACTIONS:
                cfg["actions"][cat] = env
        self._config = cfg
        return cfg

    @property
    def config(self) -> dict:
        return self._config or DEFAULT_CONFIG

    def action_for(self, category: str) -> str:
        return self.config["actions"].get(category, "block")

    def domain_allowed(self, host: str) -> tuple:
        """Return (allowed: bool, reason: str). Allowlist wins over blocklist? No —
        blocklist checked first, then allowlist (if non-empty)."""
        if not host:
            return True, ""
        host = host.lower().rstrip(".")
        dom = self.config["domains"]
        allow_sub = dom.get("allow_subdomains", True)

        def matches(pattern: str) -> bool:
            p = pattern.lower().rstrip(".")
            return host == p or (allow_sub and host.endswith("." + p))

        for blocked in dom.get("block", []):
            if matches(blocked):
                return False, f"domain '{host}' is on the blocklist"
        allow = dom.get("allow", [])
        if allow:
            for allowed in allow:
                if matches(allowed):
                    return True, ""
            return False, f"domain '{host}' not in allowlist"
        return True, ""

    def redacted(self) -> dict:
        """Safe-to-expose view for the management API."""
        return json.loads(json.dumps(self.config))
