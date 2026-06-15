# Zero Trust Agentic AI Gateway

![CI](https://github.com/Tamerktb/ZT-Agentic-gateway/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-24%2F24-passing-green)

A working reference implementation of Zero Trust security for AI agents. Every agent action is authenticated, authorized, rate-limited, inspected for attacks, and immutably logged — no exceptions.

For a step-by-step walkthrough of the code and concepts, read **[TUTORIAL.md](TUTORIAL.md)**.

![Architecture Diagram](images/architecture.svg)

---

## Quick Start

### Production deployment

```bash
cp .env.example .env
# Edit .env and set JWT_SECRET to a long random string
docker compose -f docker-compose.prod.yml up -d
```

SQLite databases persist in Docker volumes — restart without losing data.
Requires `JWT_SECRET` to be set (fails with clear error if missing).

### Option 1: Web UI Dashboard (easiest — no Docker needed)

```bash
pip install fastapi uvicorn httpx pydantic pydantic-settings PyJWT
cd ZT-Agentic-gateway
python ui/server.py
```

Opens a browser at **http://127.0.0.1:8080** with a visual dashboard. Click "Run All Tests" to see the project working.

### Option 2: CLI (with Docker)

```bash
make build && make up
make demo-all
```

### Option 3: CLI (without Docker)

```bash
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
| `identity-provider` | 8001 | NHI management — JWT issuance and verification |
| `credential-vault` | 8002 | Dynamic per-action credentials with TTL expiry |
| `policy-engine` | 8003 | Rego-style policy rules (parsed in Python) |
| `audit-service` | 8004 | Immutable hash-chain audit log |
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
├── .github/workflows/ci.yml       # 24-test CI pipeline
├── docker-compose.yml             # Multi-service orchestration
├── Makefile                        # Build/run/demo commands
├── test_integration.py             # Full integration test suite
├── services/
│   ├── ai-gateway/                # Core Zero Trust enforcement
│   │   └── src/middleware/        # 5-stage pipeline
│   ├── identity-provider/         # NHI management (JWT)
│   ├── credential-vault/          # Dynamic secrets broker
│   ├── policy-engine/             # Rego-style policy rules
│   ├── audit-service/             # Hash-chain audit log
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
