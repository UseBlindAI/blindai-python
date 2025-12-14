# BlindAI Examples

This folder contains runnable examples demonstrating BlindAI SDK features.

## Quick Start

```bash
# Install BlindAI
pip install blindai-sdk

# Run an example
python examples/quickstart.py
```

## Examples

| File | Description |
|------|-------------|
| [quickstart.py](quickstart.py) | Basic usage, decorator pattern, threat detection |
| [async_example.py](async_example.py) | AsyncToolGuard for concurrent operations |
| [decorator_options.py](decorator_options.py) | All `@protect` decorator configuration options |
| [error_handling.py](error_handling.py) | Exception handling patterns and fail-safe modes |
| [testing_example.py](testing_example.py) | Mocking BlindAI in unit tests |

## Running Examples

All examples can be run directly:

```bash
python examples/quickstart.py
python examples/async_example.py
python examples/decorator_options.py
python examples/error_handling.py
python examples/testing_example.py
```

## Environment Setup

Set your API key before running examples:

```bash
export BLINDAI_API_KEY="your-api-key"
```

Or in your code:

```python
from blindai import BlindAI

guard = BlindAI(api_key="your-api-key")
```
