# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-10-27

First public release on [PyPI](https://pypi.org/project/zt-gateway/).

### Added
- **27 detection rules with stable IDs** across 4 categories:
  - `injection` (INJ-001…016) — ignore-previous-instructions, jailbreaks, system-prompt extraction, tool-override
  - `pii` (PII-001…004) — credit cards (Luhn-checked), SSN, email, phone
  - `secret` (SEC-001…006) — AWS keys, GitHub tokens, OpenAI/Anthropic keys, private-key blocks, bearer tokens
  - `vuln` (VUL-001…003) — SQL injection, XSS, command injection
- **Per-category policy actions** — `block` / `warn` / `log`, independently configurable
- **Domain policy** — allow-list (default-deny when non-empty) and block-list
- **Detection-only endpoint** `POST /check` — submit text, get findings with no side effects
- **Bearer-token auth** on the management API
- **Tamper-evident audit chain** — `/audit/chain` and `/audit/verify`
- **Forensic JSONL logging**
- **HTML dashboard** and **Prometheus metrics**
- Dockerfile and GitHub Actions CI (Python 3.11–3.13)

### Changed
- Rule findings now carry stable rule IDs; `warn` mode adds `X-ZT-Warnings` and `X-ZT-Trace-Id` response headers

## [1.0.0]

- Initial version: transparent HTTP forward proxy with CONNECT tunnels, per-host sliding-window rate limiting, and a SQLite audit log
