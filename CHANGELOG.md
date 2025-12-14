# Changelog

All notable changes to the BlindAI Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
