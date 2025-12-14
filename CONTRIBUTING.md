# Contributing to BlindAI Python SDK

Thank you for your interest in contributing to BlindAI! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/blindai-python.git
   cd blindai-python
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/UseBlindAI/blindai-python.git
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Install Dependencies

```bash
# Using uv (recommended)
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# Or using pip
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Verify Setup

```bash
# Run tests
pytest

# Type checking
mypy blindai

# Linting
ruff check blindai
```

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feat/add-batch-processing` - New features
- `fix/timeout-handling` - Bug fixes
- `docs/update-readme` - Documentation
- `refactor/simplify-client` - Code refactoring
- `test/add-async-tests` - Test additions

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add batch processing support
fix: handle timeout errors gracefully
docs: update installation instructions
test: add tests for circuit breaker
refactor: simplify error handling logic
chore: update dependencies
```

### Making Your Changes

1. **Create a branch**:
   ```bash
   git checkout -b feat/your-feature
   ```

2. **Make changes** and commit frequently:
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

3. **Keep your branch updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

## Pull Request Process

1. **Ensure tests pass**:
   ```bash
   pytest
   mypy blindai
   ruff check blindai
   ```

2. **Update documentation** if needed

3. **Push your branch**:
   ```bash
   git push origin feat/your-feature
   ```

4. **Open a Pull Request** on GitHub with:
   - Clear title following conventional commits
   - Description of changes
   - Link to related issues (if any)

5. **Address review feedback** promptly

### PR Checklist

- [ ] Tests pass locally
- [ ] Type hints added for new code
- [ ] Docstrings added for public APIs
- [ ] CHANGELOG.md updated (for notable changes)
- [ ] No breaking changes (or clearly documented)

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/)
- Use [ruff](https://github.com/astral-sh/ruff) for linting
- Maximum line length: 88 characters (Black default)

### Type Hints

All public APIs must have type hints:

```python
# ✅ Good
def check(self, text: str, *, context_id: Optional[str] = None) -> ProtectionResult:
    """Check text for threats."""
    ...

# ❌ Bad
def check(self, text, context_id=None):
    ...
```

### Docstrings

Use Google-style docstrings:

```python
def protect(
    self,
    func: Optional[Callable] = None,
    *,
    policies: Optional[List[str]] = None,
) -> Callable:
    """Decorator to protect a function from security threats.

    Args:
        func: Function to protect.
        policies: Security policies to enforce.

    Returns:
        Decorated function with security protection.

    Raises:
        ThreatBlockedError: If threat detected.

    Example:
        @guard.protect(policies=["pii"])
        def my_function(text: str) -> str:
            return process(text)
    """
```

### Error Handling

- Use custom exceptions from `blindai.exceptions`
- Never expose sensitive data in error messages
- Provide actionable error messages

```python
# ✅ Good
raise ConfigurationError("Invalid timeout: must be positive")

# ❌ Bad
raise ValueError("bad config")
```

## Testing

### Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=blindai --cov-report=html

# Specific test file
pytest tests/test_guard.py

# Specific test
pytest tests/test_guard.py::test_check_threat
```

### Writing Tests

- Place tests in `tests/` directory
- Mirror source structure: `blindai/guard.py` → `tests/test_guard.py`
- Use descriptive test names
- Use `MockGuard` for unit tests

```python
import pytest
from blindai import BlindAI
from blindai.testing import create_test_guard

def test_check_returns_safe_for_normal_input():
    guard = create_test_guard(default_safe=True)
    result = guard.check("Hello world")
    assert not result.is_threat

def test_protect_decorator_blocks_threats():
    guard = create_test_guard(default_safe=False)
    
    @guard.protect
    def my_func(text: str) -> str:
        return text
    
    with pytest.raises(ThreatBlockedError):
        my_func("any input")
```

## Documentation

- Update docstrings for API changes
- Update README.md for user-facing changes
- Update CHANGELOG.md for notable changes
- Add examples in `examples/` for new features

## Questions?

- Open a [GitHub Discussion](https://github.com/UseBlindAI/blindai-python/discussions)
- Check existing [Issues](https://github.com/UseBlindAI/blindai-python/issues)

Thank you for contributing! 🎉
