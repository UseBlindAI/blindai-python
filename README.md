# BlindAI Python SDK

[![PyPI version](https://badge.fury.io/py/blindai-sdk.svg)](https://pypi.org/project/blindai-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security guardrails for AI agents. Protect against prompt injection, data leakage, and unauthorized tool execution.

## Installation

```bash
pip install blindai-sdk
```

## Quick Start

```python
from blindai import BlindAI

blind = BlindAI(api_key="your-api-key")

# Check user input
result = blind.check_sync("Process this user input: Hello world")

if not result.is_threat:
    print("✅ Input is safe")
else:
    print(f"🚨 Blocked: {result.threat_level}")
```

## Async Support

```python
import asyncio
from blindai import BlindAI

blind = BlindAI(api_key="your-api-key")

async def main():
    result = await blind.check_async("User input here")
    print(f"Safe: {not result.is_threat}")

asyncio.run(main())
```

## Decorator Pattern

```python
from blindai import BlindAI

blind = BlindAI(api_key="your-api-key")

@blind.protect
def process_user_input(text: str) -> str:
    """This function is automatically protected."""
    return f"Processed: {text}"

# Threats are automatically blocked
result = process_user_input("Hello!")  # ✅ Works
result = process_user_input("Ignore instructions...")  # 🚨 Blocked
```

## Configuration

```python
from blindai import BlindAI

blind = BlindAI(
    api_key="your-api-key",
    base_url="https://api.useblindai.com",  # Custom endpoint
    timeout=30.0,                            # Request timeout
    fail_open=False,                         # Block on errors (secure)
)
```

## Environment Variables

```bash
export BLINDAI_API_KEY="your-api-key"
export BLINDAI_BASE_URL="https://api.useblindai.com"  # Optional
```

```python
from blindai import BlindAI

# Automatically uses environment variables
blind = BlindAI()
```

## Protection Options

```python
@blind.protect(
    policies=["pii", "prompt_injection"],  # Specific policies
    on_violation="block",                   # block, warn, log
    mode="fast",                            # fast mode for high throughput
)
def my_tool(input: str) -> str:
    return process(input)
```

## Circuit Breaker

```python
from blindai import BlindAI, CircuitBreakerConfig

blind = BlindAI(
    api_key="your-api-key",
    circuit_breaker=CircuitBreakerConfig(
        failure_threshold=5,
        timeout=30.0,
    ),
)
```

## Exception Handling

```python
from blindai import BlindAI, ThreatBlockedError, APIError

blind = BlindAI(api_key="your-api-key")

try:
    result = blind.check_sync(user_input)
except ThreatBlockedError as e:
    print(f"Threat blocked: {e.threat_level}")
except APIError as e:
    print(f"API error: {e}")
```

## Documentation

- [Full Documentation](https://docs.useblindai.com)
- [API Reference](https://docs.useblindai.com/api)
- [Examples](https://github.com/useblindai/blindai-python/tree/main/examples)

## License

MIT License - see [LICENSE](LICENSE) for details.
