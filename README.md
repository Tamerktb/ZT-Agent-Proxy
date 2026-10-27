# ZT Agent Proxy

[![PyPI version](https://img.shields.io/pypi/v/zt-gateway.svg)](https://pypi.org/project/zt-gateway/)
[![Python versions](https://img.shields.io/pypi/pyversions/zt-gateway.svg)](https://pypi.org/project/zt-gateway/)
[![CI](https://github.com/Tamerktb/ZT-Agent-Proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/Tamerktb/ZT-Agent-Proxy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Transparent HTTP forward proxy for AI agents.**
> Set `HTTP_PROXY=http://localhost:8000` and every API call your agent makes is inspected,
> rate-limited, and immutably audited — zero code changes.

v1.1 adds rule IDs, per-category policy actions, domain allow/block lists, a
detection-only endpoint, mgmt bearer auth, forensic JSONL logging, and an HTML
dashboard. All inherited from a feature audit of FireClaw, ClawShield,
AIProxyGuard, and Trylon.

## Quick Start

```bash
pip install zt-gateway
zt-gateway
# → Proxy:   http://127.0.0.1:8000  ← set this as HTTP_PROXY
# → Mgmt:    http://127.0.0.1:8080  ← stats, audit, /check, dashboard
```

> From source instead: `pip install git+https://github.com/Tamerktb/ZT-Agent-Proxy.git`

Then configure your AI agent:

```bash
# opencode, Hermes, or any Python agent:
set HTTP_PROXY=http://localhost:8000
set HTTPS_PROXY=http://localhost:8000
```

### Docker

```bash
docker build -t zt-agent-proxy .
docker run -p 8000:8000 -p 8080:8080 -v zt-data:/data zt-agent-proxy
```

### CLI Options

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--proxy-port` | `ZT_PROXY_PORT` | 8000 | HTTP forward proxy port |
| `--mgmt-port` | `ZT_MGMT_PORT` | 8080 | Management API port |
| `--rate-limit` | `ZT_RATE_LIMIT` | 60 | Requests/min per host |
| `--policy` | `ZT_POLICY_FILE` | — | Policy JSON (actions, domains, rate limit) |
| `--mgmt-token` | `ZT_MGMT_TOKEN` | — | Bearer token required on mgmt API |
| `--allow-domain` | `ZT_ALLOW_DOMAINS` | — | Allowlist domain (repeatable; non-empty ⇒ default deny) |
| `--block-domain` | `ZT_BLOCK_DOMAINS` | — | Blocklist domain (repeatable) |
| `--action` | `ZT_ACTION_<CAT>` | block | Per-category action: `injection\|pii\|secret\|vuln = block\|warn\|log` |
| `--data-dir` | `ZT_DATA_DIR` | auto | SQLite + forensics.jsonl directory |
| `--log-level` | `ZT_LOG_LEVEL` | INFO | Log verbosity |

## What Gets Blocked

27 detection rules with stable IDs, grouped into 4 categories. Each category's
action is independently configurable (block / warn / log).

| Category | Rules | Examples |
|----------|-------|----------|
| `injection` | INJ-001…016 | ignore-previous-instructions, jailbreaks, system-prompt extraction, tool-override |
| `pii` | PII-001…004 | credit cards (Luhn-checked), SSN, email, phone |
| `secret` | SEC-001…006 | AWS keys, GitHub tokens, OpenAI/Anthropic keys, private-key blocks, bearer tokens |
| `vuln` | VUL-001…003 | SQL injection, command injection, path traversal |

`warn` mode forwards the request but adds `X-ZT-Warnings` and `X-ZT-Trace-Id`
response headers so the agent (or a human) can react. `log` records the finding
in the audit chain without touching the traffic.

Domain policy: blocklist hits → 403 immediately. Allowlist (when non-empty) →
default-deny everything else.

Rate limiting: sliding-window per destination host → 429.

## Architecture

```
Agent → HTTP_PROXY → ZT Agent Proxy (port 8000) → Target API
                          │
                     ┌────┴─────┐
                     │  policy  │ ← domain allow/block, per-category actions
                     │  detect  │ ← 27 rules, Luhn guard, stable rule IDs
                     │  rate    │ ← per-host sliding window
                     │  audit   │ ← SQLite hash chain + forensics.jsonl
                     └──────────┘
```

CONNECT tunnels (HTTPS) are inspected at the domain level only (SNI/host);
payload inspection applies to plain HTTP.

## Management API (port 8080)

Bearer auth is enforced on everything except `/`, `/health`, and `/dashboard`
when `ZT_MGMT_TOKEN` is set.

| Endpoint | Description |
|----------|-------------|
| `GET /` | Index |
| `GET /health` | Liveness check (always public) |
| `GET /dashboard` | HTML dashboard (always public) |
| `GET /stats` | Request counts + audit chain status |
| `POST /check` | Detection-only: submit `{"text": "..."}`, get findings without side effects |
| `GET /rule-catalog` | All 27 rules with IDs, categories, severities |
| `GET /audit/chain` | Hash-chained audit log (paginated) |
| `GET /audit/verify` | Verify chain integrity |
| `GET /forensics` | Tail of forensics.jsonl |
| `GET /policy` | Current effective policy |
| `POST /policy/reload` | Reload policy file from disk |
| `GET /metrics` | Prometheus metrics |

## Testing

```bash
python test_proxy.py
# → 33/33 passed
```

Covers: HTTP forwarding, CONNECT tunnels (bidirectional), prompt-injection
blocking, PII/secret blocking (incl. Luhn negatives), warn mode headers,
domain blocklist, mgmt bearer auth, /check, rate limiting, forensic JSONL,
audit chain integrity, and stats consistency.

CI runs the same suite on Python 3.11–3.13 (`.github/workflows/ci.yml`).

## Project Structure

```
├── pyproject.toml
├── Dockerfile
├── test_proxy.py            # 33-assertion suite
├── .github/workflows/ci.yml
└── zt_gateway/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py               # CLI entry: zt-gateway
    ├── smol_app.py          # Wiring (legacy import surface)
    ├── proxy.py             # Forward proxy + CONNECT + rate limit
    ├── detect.py            # 27 rules, Luhn, redaction
    ├── policy.py            # Category actions + domain lists
    ├── audit.py             # Hash chain + forensics.jsonl
    └── manager.py           # Mgmt API, auth, /check, dashboard
```

## Comparison

| Feature | ZT Agent Proxy v1.1 | FireClaw | ClawShield | AIProxyGuard | Trylon |
|---------|:-------------------:|:--------:|:----------:|:------------:|:------:|
| Transparent HTTP proxy | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTPS CONNECT tunnels | ✅ | ✅ | ✅ | ✅ | ✅ |
| Prompt-injection rules w/ IDs | ✅ (16) | — | — | — | — |
| PII + secret + vuln rules | ✅ (11) | — | — | — | — |
| Luhn-checked credit cards | ✅ | | | ✅ | |
| Per-category actions (block/warn/log) | ✅ | | | | |
| Domain allow/block lists | ✅ | | ✅ | ✅ | |
| Mgmt API bearer auth | ✅ | | | | |
| Detection-only endpoint | ✅ | | | | |
| Tamper-evident audit chain | ✅ | | | | |
| Forensic JSONL | ✅ | | | | |
| Prometheus metrics | ✅ | | | | |
| HTML dashboard | ✅ | | | | |
| Docker + CI | ✅ | | | | |

("—" = unknown/not comparable from public docs; blank = absent. This table is
as honest as public information allows — check the competitors' current docs.)

## License

MIT
