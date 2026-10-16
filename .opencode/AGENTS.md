# ZT Agent Proxy — Project Knowledge

## Location
- `D:\SoloLeveling\ZT-Agent-Proxy`
- GitHub: `https://github.com/Tamerktb/ZT-Agent-Proxy`
- (Older/related repo: `D:\SoloLeveling\ZT-Agentic-gateway` — different project, don't confuse)

## Architecture
- Transparent HTTP forward proxy (`socketserver.ThreadingTCPServer`, `ReusableTCPServer(allow_reuse_address=True)`)
- FastAPI management app on a separate port (stats, audit, health, metrics, /check, policy, dashboard)
- SQLite audit chain (hash-linked, tamper-evident) + forensics.jsonl sidecar
- Package `zt_gateway` split into: `proxy`, `detect`, `policy`, `audit`, `manager`, `smol_app` (wiring/legacy imports), `cli`

## v1.1 Feature Upgrade (Oct 2026)
Added after feature audit of FireClaw / ClawShield / AIProxyGuard / Trylon:
- `detect.py` — 27 rules with stable IDs (INJ-001…016, PII-001…004, SEC-001…006, VUL-001…003), Luhn guard, redaction. **Rules compile with `re.IGNORECASE`** (v1.0 bug: capitalized "Ignore previous" never matched).
- `policy.py` — per-category actions (block/warn/log), domain allow/block lists, env overrides.
- `audit.py` — write lock around read-prev→insert (v1.0 bug: concurrent writes forked the chain).
- `manager.py` — bearer auth (`ZT_MGMT_TOKEN`), `POST /check`, rule catalog, forensics, policy, HTML dashboard.
- `proxy.py` — fixed bidirectional CONNECT (v1.0 bug: both pipe threads read from client).

## Windows Quirks
- `allow_reuse_address` must be set as a CLASS variable, NOT after `__init__`
- `urllib` bypasses proxy for `127.0.0.1`/`localhost` due to `no_proxy` env — clear it in tests
- ProactorEventLoop doesn't support `reuse_port` — avoid asyncio-based proxy servers
- Use `socketserver.ThreadingTCPServer` for reliable TCP on Windows

## Test
- `python test_proxy.py` — in-process (proxy + mgmt + test server in threads)
- Ports: 25001 (proxy), 25002 (mgmt), 25003 (test server); `ZT_RATE_LIMIT=20`
- **33/33 passing** as of Oct 2026. CI: `.github/workflows/ci.yml` (Python 3.11–3.13)

## CLI
- `zt-gateway` via `zt_gateway/cli.py`
- Args: `--proxy-port`, `--mgmt-port`, `--rate-limit`, `--policy`, `--mgmt-token`, `--allow-domain`, `--block-domain`, `--action CAT=ACT`, `--data-dir`, `--log-level`
- Usage: set `HTTP_PROXY=http://localhost:8000` in agent config

## Build / Docker
- `pip install git+https://github.com/Tamerktb/ZT-Agent-Proxy.git` (NOT PyPI — package `zt-gateway` is 404 there)
- `Dockerfile` present; expose 8000 (proxy) + 8080 (mgmt), volume `/data`
