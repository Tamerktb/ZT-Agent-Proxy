# ZT Agent Proxy

> **Transparent HTTP forward proxy for AI agents.**  
> Set `HTTP_PROXY=http://localhost:8000` and every API call your agent makes is inspected,
> rate-limited, and immutably audited — zero code changes.

## Quick Start

```bash
pip install zt-gateway
zt-gateway
# → Proxy:   http://127.0.0.1:8000  ← set this as HTTP_PROXY
# → Mgmt:    http://127.0.0.1:8080  ← stats, audit, metrics
```

Then configure your AI agent:

```bash
# opencode, Hermes, or any Python agent:
set HTTP_PROXY=http://localhost:8000
set HTTPS_PROXY=http://localhost:8000
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy-port` | 8000 | HTTP forward proxy port |
| `--mgmt-port` | 8080 | Management API port |
| `--rate-limit` | 20 | Requests/min per host |
| `--data-dir` | auto | SQLite data directory |
| `--log-level` | INFO | Log verbosity |

### What Gets Blocked

| Threat | Detection | Response |
|--------|-----------|----------|
| Prompt injection | Regex patterns ("ignore instructions", jailbreaks) | 400 |
| Data exfiltration | Credit cards, SSNs, passwords in body/response | 400 |
| Excessive requests | Per-host sliding window rate limiter | 429 |

## Architecture

```
Agent → HTTP_PROXY → ZT Agent Proxy (port 8000) → Target API
                          │
                     ┌────┴────┐
                     │ inspect │ ← prompt injection + exfiltration patterns
                     │  rate   │ ← per-host sliding window
                     │  audit  │ ← SQLite hash chain (tamper-evident)
                     └─────────┘
```

Management API at port 8080:

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness check |
| `GET /stats` | Request counts + audit chain status |
| `GET /audit/chain` | Immutable audit log (paginated) |
| `GET /audit/verify` | Verify chain integrity |
| `GET /metrics` | Prometheus metrics |

## Test

```bash
python test_proxy.py
# → 11/11 passed
```

Covers: management API, HTTP forwarding, prompt injection blocking, data exfiltration blocking, rate limiting, audit chain integrity.

## Project Structure

```
├── pyproject.toml           # pip install zt-gateway
├── test_proxy.py            # 11-test suite
└── zt_gateway/
    ├── __init__.py
    ├── __main__.py
    ├── cli.py               # CLI entry: zt-gateway
    └── smol_app.py          # Proxy core + management API
```

## License

MIT
