# Changelog

All notable changes to the BlindAI Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- **Identity tokens** (BlindAI pilot S, 2026-10-06). `exchange_tokens(runtime_secret, agent_ids)`
  trades a runtime's secret for its agents' identity tokens at `/v1/cp/tokens`; `authorize` and
  `scan` take `identity_token=` and send it as `X-BlindAI-Identity` -- only when given, never empty.
  A tool call needs one on a deployment whose control plane is on. Each exchange is its own request:
  a token cache would be a cache of an identity decision.
- `blindai.wire.IDENTITY_HEADER` is held to the spec's `wire-constants.json` by `tests/test_wire.py`.
- Not published: the package name is chosen first, then 0.1.0 is published once under it.

## [Unreleased]

## [0.1.0] - 2026-09-14

Rewritten as a thin wire client. The previous code in this repository was never published and
should not be used.

### Fixed
- The client posted `{"text": ...}` to `/v1/protect`, a route that has never existed on the API.
  It now posts an `AuthorizeRequest` to `/v1/authorize`.
- `from_api_response` read `is_threat` and `final_action` — fields the server has never sent — so
  every lookup defaulted permissive and a genuine block parsed as an allow. The parser now reads
  `blocked`/`allowed` and raises on anything that is not an `AuthorizeResponse`.
- A 4xx that cannot succeed is no longer retried; only 5xx, 408 and 429 are.
- Errors carry the server's own explanation, and a 422 names the field that was wrong.

### Changed
- **No error path produces an allow.** No `continue_on_error`, no fail-open option, no collapsed
  batch verdict.
- `base_url` is required; there is no production default.
- Scope reduced to a wire client: the gates, multi-agent, policy engine, circuit breaker, caching
  and progressive rollout are not here. Several of them decided without asking the server, which is
  what this package now refuses to do.
- One runtime dependency (`httpx`). `pydantic` dropped.
- Ships `py.typed`; `mypy --strict` clean.
- Unknown request fields raise rather than being silently dropped.

### Security
- Two invariants gate every release as job dependencies of publish: a static check that only the
  response parser may produce an allow, and a behavioural test that every public call either makes
  exactly one request or raises with the decision built from that request's own response. Both are
  mutation-tested.
- The release also requires contract tests against a real deployment; a missing secret fails the
  job rather than skipping it.

### Added
- Examples folder with 5 working demos
- `AsyncToolGuard` export from main module
- `shutdown()` method alias for `close()`

## [0.1.0] - 2024-12-14

### Added
- **Core Protection**
  - `BlindAI` class as primary entry point
  - `Guard` class with full type hints and IDE autocomplete
  - `@protect` decorator for function-level security
  - `check()` method for manual threat detection
  - `check_batch()` for batch processing

- **Async Support**
  - `AsyncToolGuard` for async/await workflows
  - `check_async()` method on sync client
  - Full async context manager support

- **Threat Detection**
  - Multi-tier detection (Bloom filter → Aho-Corasick → ML)
  - Prompt injection detection
  - PII detection and redaction
  - SQL injection detection
  - Jailbreak attempt detection
  - Data exfiltration detection

- **Resilience Features**
  - Circuit breaker with configurable thresholds
  - Automatic retry with exponential backoff
  - `fail_open` mode for high availability
  - Connection pooling and keep-alive

- **Developer Experience**
  - Full type hints for IDE autocomplete
  - `py.typed` marker for type checkers
  - Comprehensive docstrings
  - Context manager support (`with` statement)

- **Testing Utilities**
  - `MockGuard` for unit testing
  - `create_test_guard()` helper function
  - Configurable mock responses

- **Event Hooks**
  - `EventHooks` for custom callbacks
  - Pre/post check hooks
  - Threat detection hooks
  - Error handling hooks

- **Exceptions**
  - `ThreatBlockedError` with threat details
  - `APIError` for API failures
  - `TimeoutError` for request timeouts
  - `ConfigurationError` for invalid config
  - `RetryExhaustedError` after max retries
  - `CircuitBreakerOpen` when circuit is open

### Security
- SSL/TLS verification enabled by default
- API key validation
- No sensitive data in error messages

## [0.0.1] - 2024-11-01

### Added
- Initial alpha release
- Basic threat detection API
- Simple decorator pattern

---

[Unreleased]: https://github.com/UseBlindAI/blindai-python/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/UseBlindAI/blindai-python/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/UseBlindAI/blindai-python/releases/tag/v0.0.1
