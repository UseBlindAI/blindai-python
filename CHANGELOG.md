# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-14

### Added
- Initial release of BlindAI Python SDK
- `BlindAI` client with `check_sync()` and `check_async()` methods
- `CheckResult` response type with threat details
- `CheckOptions` for configuring detection behavior
- Exception hierarchy: `BlindAIError`, `AuthenticationError`, `RateLimitError`, `ValidationError`, `APIError`
- Context manager support (sync and async)
- Type hints and `py.typed` marker
- Environment variable support for API key and base URL
