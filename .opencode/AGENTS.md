# ZT Agent Proxy — Project Knowledge

## Location
- `D:\zt agenticv`
- GitHub: `https://github.com/Tamerktb/ZT-Agentic-gateway.git`
- Branch: `master`

## Architecture
- Single-process HTTP forward proxy (`socketserver.ThreadingTCPServer`)
- FastAPI management app at separate port (stats, audit, health, metrics)
- Embedded SQLite audit chain (hash-linked, tamper-evident)
- No Docker, no microservices, no JWT, no Rego

## Key Changes Made This Session (Jul 14 2026)
- Stripped all unnecessary services (identity-provider, credential-vault, policy-engine, demo-agents, attack-simulator, terraform, monitoring, ui, shared/, images/, docker-compose, Makefile)
- Rewrote core as transparent HTTP proxy in `zt_gateway/smol_app.py`
- Proxy uses `socketserver.ThreadingTCPServer` with `ReusableTCPServer(allow_reuse_address=True)`
- HTTP forwarding uses synchronous `httpx.Client()` (NOT async — avoids asyncio-in-thread issues)
- Audit service embedded in smol_app.py (no separate service)
- Management API at separate port with /health, /stats, /audit/chain, /audit/verify, /metrics

## Windows Quirks
- `allow_reuse_address` must be set as CLASS variable, NOT after `__init__`
- `urllib` bypasses proxy for `127.0.0.1`/`localhost` due to `no_proxy` env var — clear it in tests
- Windows ProactorEventLoop doesn't support `reuse_port` — avoid asyncio-based proxy servers
- Use `socketserver.ThreadingTCPServer` for reliable TCP server on Windows

## Test
- `python test_proxy.py` — in-process test (proxy + mgmt + test server in threads)
- Ports: 25001 (proxy), 25002 (mgmt), 25003 (test server)
- 11 tests covering: management API, HTTP forwarding, prompt injection blocking, data exfiltration blocking, rate limiting, audit chain integrity

## CLI
- `zt-gateway` command via `zt_gateway/cli.py`
- Args: `--proxy-port`, `--mgmt-port`, `--rate-limit`, `--data-dir`, `--log-level`
- Usage: set `HTTP_PROXY=http://localhost:8000` in agent config
