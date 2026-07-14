# Zero Trust Agentic AI Gateway

![CI](https://github.com/Tamerktb/ZT-Agentic-gateway/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-24%2F24-passing-green)

> **Dual-mode Zero Trust security gateway for AI agents.**  
> 🔹 **Personal mode:** `pip install zt-gateway && zt-gateway` — single process, no Docker.  
> 🔸 **Enterprise mode:** Docker Compose with 6 microservices, Terraform, Wazuh SIEM, Prometheus.

Every agent action is authenticated, authorized, rate-limited, inspected for attacks, and immutably logged — no exceptions, in either mode.

For a step-by-step walkthrough of the code and concepts, read **[TUTORIAL.md](TUTORIAL.md)**.

![Architecture Diagram](images/architecture.svg)

---

## Quick Start

### ⚡ Option 0: Smol Mode (personal — 1 command, no Docker)

```bash
pip install zt-gateway
zt-gateway
# → Listening on http://127.0.0.1:8000
```

All 6 services collapsed into a single process. SQLite persists in `~/.zt-gateway/data/`.  
Auto-generates a JWT secret (or set `ZT_JWT_SECRET`). Test it:

```bash
# Register an agent and run the full pipeline in one shot:
python test_smol.py
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | 8000 | Listen port |
| `--host` | 127.0.0.1 | Listen address |
| `--jwt-secret` | auto | JWT signing key |
| `--data-dir` | auto | SQLite data directory |
| `--log-level` | INFO | Log verbosity |

### 🏢 Enterprise deployment

```bash
cp .env.example .env
# Edit .env and set JWT_SECRET to a long random string
docker compose -f docker-compose.prod.yml up -d
```

All services expose Prometheus metrics at `/metrics`. Enable JSON logging:
```bash
LOG_FORMAT=json docker compose -f docker-compose.prod.yml up -d
```

### Option 1: Web UI Dashboard (no Docker)

```bash
pip install fastapi uvicorn httpx pydantic pydantic-settings PyJWT prometheus-client
set JWT_SECRET=your-long-random-secret
cd ZT-Agentic-gateway
python ui/server.py
```

Opens a browser at **http://127.0.0.1:8080** with a visual dashboard.

### Option 2: CLI (with Docker)

```bash
make build && make up
make demo-all
```

### Option 3: CLI (without Docker)

```bash
set JWT_SECRET=your-long-random-secret
python test_integration.py
```

### View results manually

```bash
# View audit chain:
curl http://localhost:8004/api/v1/audit/chain | python -m json.tool

# Check enforcement stats:
curl http://localhost:8000/api/v1/admin/stats | python -m json.tool
```

---

## Demo

![Attack Simulator Results](images/attack-simulator-result.txt)

### 5 Attack Scenarios Blocked

| Attack | How It's Blocked | HTTP Code |
|--------|-----------------|-----------|
| Invalid JWT | Auth middleware rejects fake/expired tokens | 401 |
| Prompt injection | Regex pattern matching detects "ignore instructions", jailbreaks | 400 |
| Privilege escalation | Policy engine denies tools outside agent's role | 403 |
| Excessive spend | Rate limiter throttles >10 actions/min or >$1000/hr | 429 |
| Data exfiltration | Pattern detection blocks credit cards, passwords, SSNs | 400 |

---

## Services

| Service | Port | Role |
|---------|------|------|
| `ai-gateway` | 8000 | Zero Trust enforcement — 5-stage middleware pipeline |
| `identity-provider` | 8001 | NHI management — JWT issuance/verification (SQLite) |
| `credential-vault` | 8002 | Dynamic per-action credentials with TTL expiry (SQLite) |
| `policy-engine` | 8003 | Rego-style policy rules (parsed in Python) |
| `audit-service` | 8004 | Immutable hash-chain audit log (SQLite) |
| `demo-agents` | — | Shopping agent + sub-agent spawner |
| `attack-simulator` | — | 6 Zero Trust control demonstrations |

---

## Middleware Pipeline

Every agent action passes through 5 stages before reaching any tool:

```
Agent → ① Authenticate (JWT) → ② Policy Check → ③ Rate Limit → ④ Prompt Inspection → ⑤ Audit Log → Tool
```

If any stage fails, the action is blocked immediately and logged.

---

## Project Structure

```
├── pyproject.toml                  # Pip package (pip install zt-gateway)
├── zt_gateway/                     # Smol mode — single-process CLI
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                     # CLI entry: zt-gateway --mode smol|prod|demo
│   └── smol_app.py                # All 6 services in one process
├── .github/workflows/ci.yml       # 24-test CI pipeline
├── .env.example                    # Documented env vars template
├── docker-compose.yml             # Multi-service orchestration
├── docker-compose.prod.yml        # Production config (volumes, required secrets)
├── Makefile                        # Build/run/demo commands
├── test_integration.py             # Full integration test suite
├── test_smol.py                    # Smol mode integration test
├── shared/                         # Shared production utilities
│   └── production.py              # Prometheus metrics, structured logging, security headers, graceful shutdown
├── services/
│   ├── ai-gateway/                # Core Zero Trust enforcement
│   │   └── src/middleware/        # 5-stage pipeline
│   ├── identity-provider/         # NHI management (JWT, SQLite)
│   ├── credential-vault/          # Dynamic secrets broker (SQLite)
│   ├── policy-engine/             # Rego-style policy rules
│   ├── audit-service/             # Hash-chain audit log (SQLite)
│   ├── demo-agents/               # Example agent flows
│   └── attack-simulator/          # Attack demonstrations
├── ui/                              # Web UI dashboard
│   ├── server.py                   # Starts services + serves UI
│   └── index.html                  # Visual dashboard
├── terraform/                      # AWS IaC deployment
├── monitoring/                     # Wazuh SIEM rules
└── images/                         # Architecture diagram
```

---

## Verification

```bash
python test_integration.py

RESULTS: 24/24 passed
```

Tests cover: NHI registration, JWT issuance/verification, credential checkout/expiry, policy allow/deny decisions, valid action routing, bad token rejection (401), prompt injection blocking (400), data exfiltration blocking (400), privilege escalation blocking (403), rate limiting (429), kill switch, admin stats, audit chain integrity.

---

## Terraform Deployment (AWS)

```bash
cd terraform
terraform init && terraform apply
```

Provisions: ECS Fargate, VPC with micro-segmentation, Security Groups, CloudTrail, VPC Flow Logs → S3 → Wazuh SIEM, CloudWatch alarms.

---

## Extending

Add a tool policy in `services/policy-engine/policies/tool_policy.rego`:
```python
tool_controls = {
    "my_new_tool": {
        "require_mfa": False,
        "max_amount": 1000,
        "restrict_actions": ["call_tool"],
    },
}
```

Register a new agent:
```bash
curl -X POST http://localhost:8001/api/v1/nhi/register \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "my-agent", "role": "shopping_agent", "policies": ["purchase_item"]}'
```

---

## License

MIT
