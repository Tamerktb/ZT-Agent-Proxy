# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] — 2026-10-27

Streaming. The proxy no longer buffers responses it should be passing through.

### Added
- **Streaming passthrough.** Responses that are large or of unknown length are
  written to the client as they arrive instead of being materialised in memory.
  This is what makes the proxy usable in front of an LLM API: an SSE token
  stream now reaches the agent token-by-token rather than arriving in one lump
  at the end. Small textual responses are still buffered, so every rule sees the
  whole document.
- `ZT_STREAM_READ_TIMEOUT` (default 300s) for long-lived streams.

### Fixed
- **`iter_bytes(chunk_size=...)` silently defeated streaming.** httpx's
  `ByteChunker` accumulates until the requested chunk size is reached, so a
  45-byte SSE frame sat in the buffer until the stream ended. Streaming now uses
  `iter_bytes()` with no chunk size, which yields each network chunk as it
  arrives. Measured: time-to-first-byte 0.02s against a 2.12s stream.
- **Compressed responses were forwarded corrupt.** The body was decoded on read
  while the upstream `Content-Encoding: gzip` header was still forwarded, so a
  client would try to gunzip already-decompressed bytes. The encoding header is
  now stripped, and the stale `Content-Length` is recomputed.
- **Duplicate `Content-Length`.** An upstream `content-length` and the one the
  handler added survived as two separate headers, and clients trusted the stale
  value (surfacing as `IncompleteRead`). Header replacement is now
  case-insensitive.

### Tests
- 40 → **45 assertions**, all passing. New coverage: streaming delivers every
  chunk, streaming sets no `Content-Length`, the first byte reaches the client
  well before the stream completes, and a gzipped upstream is decoded exactly
  once with the encoding header stripped.

## [1.2.0] — 2026-10-27

Hardening release — two inspection/integrity gaps closed.

### Security
- **The audit-chain hash now covers every meaningful field.** It previously covered
  only `timestamp|method|target|decision|prev_hash`, which meant `status_code`,
  `reason`, `bytes_*`, `duration_ms` — and, most importantly, **the `rules` that
  fired** — could be altered without breaking verification. All of them are hashed now.
- **The genesis entry is verified.** `verify_chain()` used to start at index 1,
  leaving entry 0 unchecked.
- **Chunked request bodies are inspected.** A `Transfer-Encoding: chunked` request
  arrived with no `Content-Length`, so the body was never read and never scanned —
  a single-header bypass of the whole detection engine. Bodies are now decoded,
  inspected, and forwarded with a normal `Content-Length`.

### Changed
- Verification is incremental for `/stats` (which the dashboard polls) and full for
  `/audit/verify?full=1`. `entries_checked` still reports the total chain length.
- Legacy (1.0/1.1) rows still verify via the original preimage, so existing audit
  databases are not invalidated; the count is reported as `legacy_pre_1_2_entries`.
- `tail_forensics()` reads backwards from EOF instead of loading the entire file —
  cost is now proportional to `n`, not to the log size.
- Request bodies are capped at 8 MiB.

### Fixed
- `/audit/verify` no longer reports a permanent `COMPROMISED` after a value was
  tampered with and then restored.

### Tests
- 33 → **40 assertions**, all passing. New coverage: chunked-body inspection
  (blocked + clean), tamper detection on `status_code`, tamper detection on the
  `rules` column, genesis tampering, and re-validation after restore.

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
