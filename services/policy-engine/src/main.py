"""
Policy engine that parses Rego-style .rego files and evaluates access rules natively.
Uses the same policy structure as OPA but evaluates rules in Python for simplicity.
"""
import json
import os
import sys
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from shared.production import setup_logging, register_shutdown, security_headers_middleware, add_metrics

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Policy Engine", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.middleware("http")(security_headers_middleware)
add_metrics(app, "policy")

policies_dir = Path(os.environ.get("POLICIES_DIR", Path(__file__).parent.parent / "policies"))

ROLE_TOOLS: dict[str, list[str]] = {}
ACCESS_CONTROLS: dict[str, dict] = {}
JIT_POLICIES: dict[str, dict] = {}


def load_policies():
    global ROLE_TOOLS, ACCESS_CONTROLS, JIT_POLICIES

    agent_path = policies_dir / "agent_policy.rego"
    if agent_path.exists():
        content = agent_path.read_text()
        ROLE_TOOLS = _parse_rego_policy(content)
        logger.info(f"Loaded agent policies for roles: {list(ROLE_TOOLS.keys())}")

    tool_path = policies_dir / "tool_policy.rego"
    if tool_path.exists():
        content = tool_path.read_text()
        ACCESS_CONTROLS = _parse_rego_tool_policy(content)
        logger.info(f"Loaded tool access controls")

    jit_path = policies_dir / "just_in_time.rego"
    if jit_path.exists():
        content = jit_path.read_text()
        JIT_POLICIES = _parse_rego_jit_policy(content)
        logger.info(f"Loaded JIT policies")


def _parse_rego_policy(content: str) -> dict:
    policies = {}
    import re
    matches = re.findall(r'"([^"]+)"\s*:\s*\[([^\]]+)\]', content)
    for role, tools_str in matches:
        tools = re.findall(r'"([^"]+)"', tools_str)
        policies[role] = tools
    return policies


def _parse_rego_tool_policy(content: str) -> dict:
    controls = {}
    import re
    matches = re.findall(r'"([^"]+)"\s*:\s*\{([^}]+)\}', content)
    for tool, props_str in matches:
        tool_policy = {}
        kv_matches = re.findall(r'"([^"]+)"\s*:\s*("([^"]*)"|true|false|\d+)', props_str)
        for key, val, _ in kv_matches:
            if val.lower() == "true":
                tool_policy[key] = True
            elif val.lower() == "false":
                tool_policy[key] = False
            elif val.isdigit():
                tool_policy[key] = int(val)
            else:
                tool_policy[key] = val.strip('"')
        controls[tool] = tool_policy
    return controls


def _parse_rego_jit_policy(content: str) -> dict:
    policies = {}
    import re
    matches = re.findall(r'"([^"]+)"\s*:\s*\{([^}]+)\}', content)
    for agent_id, props_str in matches:
        agent_policy = {}
        kv_matches = re.findall(r'"([^"]+)"\s*:\s*("([^"]*)"|true|false|\d+)', props_str)
        for key, val, _ in kv_matches:
            if val.lower() == "true":
                agent_policy[key] = True
            elif val.lower() == "false":
                agent_policy[key] = False
            elif val.isdigit():
                agent_policy[key] = int(val)
            else:
                agent_policy[key] = val.strip('"')
        policies[agent_id] = agent_policy
    return policies


class PolicyRequest(BaseModel):
    agent_id: str
    action_type: str
    target: str
    payload: dict = {}
    role: str = ""


@app.post("/api/v1/policy/evaluate")
async def evaluate(req: PolicyRequest):
    role = req.role or _get_agent_role(req.agent_id)
    if not role:
        role = "unknown"

    # 1. Role-based tool access
    allowed_tools = ROLE_TOOLS.get(role, [])
    if req.action_type == "call_tool" and req.target not in allowed_tools:
        logger.warning(f"POLICY DENY: {req.agent_id} (role={role}) cannot access tool '{req.target}'")
        return {"allowed": False, "reason": f"agent role '{role}' not authorized for tool '{req.target}'", "component": "policy"}

    # 2. Tool-level access controls
    tool_control = ACCESS_CONTROLS.get(req.target, {})
    if tool_control.get("require_mfa", False):
        logger.warning(f"POLICY DENY: {req.agent_id} - tool '{req.target}' requires MFA")
        return {"allowed": False, "reason": f"tool '{req.target}' requires multi-factor authentication", "component": "policy"}
    if tool_control.get("require_human_approval", False):
        return {"allowed": False, "reason": f"tool '{req.target}' requires human-in-the-loop approval", "component": "policy"}

    # 3. Just-in-time policy
    jit = JIT_POLICIES.get(req.agent_id, {})
    if jit.get("max_daily_actions"):
        # Track would be in a real system; for demo we pass if no explicit deny
        pass

    # 4. Action-level restrictions
    restrict_actions = tool_control.get("restrict_actions", [])
    if restrict_actions and req.action_type not in restrict_actions:
        logger.warning(f"POLICY DENY: {req.agent_id} - action '{req.action_type}' not allowed on '{req.target}'")
        return {"allowed": False, "reason": f"action '{req.action_type}' not permitted on tool '{req.target}'", "component": "policy"}

    # 5. Amount-based restrictions
    max_amount = tool_control.get("max_amount", None)
    if max_amount is not None:
        amount = abs(req.payload.get("amount", 0))
        if amount > max_amount:
            logger.warning(f"POLICY DENY: {req.agent_id} - amount ${amount} exceeds max ${max_amount}")
            return {"allowed": False, "reason": f"transaction amount ${amount} exceeds maximum of ${max_amount}", "component": "policy"}

    logger.info(f"POLICY ALLOW: {req.agent_id} (role={role}) -> {req.action_type} on {req.target}")
    return {"allowed": True, "component": "policy"}


def _get_agent_role(agent_id: str) -> str:
    role_map = {
        "shopping-agent": "shopping_agent",
        "data-processor": "data_processor",
        "email-agent": "email_agent",
        "sub-agent-spawner": "orchestrator",
        "malicious-agent": "unknown",
    }
    return role_map.get(agent_id, "unknown")


@app.get("/api/v1/policy/rules")
async def list_rules():
    return {
        "role_tools": ROLE_TOOLS,
        "access_controls": ACCESS_CONTROLS,
        "jit_policies": JIT_POLICIES,
    }


@app.post("/api/v1/policy/reload")
async def reload_policies():
    load_policies()
    return {"status": "reloaded", "roles": list(ROLE_TOOLS.keys())}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "policy-engine"}


@app.get("/")
async def root():
    return {"service": "Policy Engine", "version": "1.0.0", "status": "running"}


load_policies()
