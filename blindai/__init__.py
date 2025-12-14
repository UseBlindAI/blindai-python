"""BlindAI Python SDK.

Security guardrails for AI agents. Protect against prompt injection,
data leakage, and unauthorized tool execution.

Example:
    ```python
    from blindai import BlindAI
    
    blind = BlindAI(api_key="your-api-key")
    
    # Sync check
    result = blind.check_sync("user input here")
    if not result.is_threat:
        print("Safe to proceed")
    
    # Or use the decorator
    @blind.protect
    def my_tool(input: str) -> str:
        return process(input)
    ```

Async Example:
    ```python
    from blindai import BlindAI
    
    blind = BlindAI(api_key="your-api-key")
    result = await blind.check_async("user input")
    ```
"""

from .circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpen,
    CircuitState,
)
from .exceptions import (
    APIError,
    BlindAIError,
    ConfigurationError,
    RetryExhaustedError,
    ThreatBlockedError,
    TimeoutError,
)
from .hooks import EventHooks, EventType, SecurityEvent
from .models import ProtectionResult, SDKConfig
from .guard import Guard
from .async_client import AsyncToolGuard
from .types import (
    # Literal types for autocomplete
    Policy,
    ViolationAction,
    ThreatLevel,
    FinalAction,
    TrustLevel,
    ToolType,
    OutputFormat,
    TierMode,
    LogStatus,
    # TypedDict types
    ThreatDetail,
    ProtectionResultDict,
    ToolMetadata,
    CheckOptions,
    ProtectOptions,
    BatchResult,
    SDKConfigDict,
    CircuitBreakerConfigDict,
    SecurityEventDict,
    ProgressMetadataDict,
    # Protocol types
    GuardProtocol,
    EventHandler,
    # Callback types
    ProgressCallback,
    ChallengeHandler,
    BlockHandler,
)

# =============================================================================
# Basalt-style aliases for cleaner API
# =============================================================================

# BlindAI is the recommended entry point (same as Guard)
BlindAI = Guard

# Add sync/async method aliases to Guard for Basalt-style API
Guard.check_sync = Guard.check  # type: ignore[attr-defined]
Guard.shutdown = Guard.close  # type: ignore[attr-defined]

__version__ = "0.1.0"

__all__ = [
    # Primary entry point (Basalt-style)
    "BlindAI",
    # Original entry points
    "Guard",
    "AsyncToolGuard",
    # Exceptions
    "BlindAIError",
    "ThreatBlockedError",
    "APIError",
    "TimeoutError",
    "ConfigurationError",
    "RetryExhaustedError",
    "CircuitBreakerOpen",
    # Models
    "ProtectionResult",
    "SDKConfig",
    # Type definitions (for IDE autocomplete)
    "Policy",
    "ViolationAction",
    "ThreatLevel",
    "FinalAction",
    "TrustLevel",
    "ToolType",
    "OutputFormat",
    "TierMode",
    "LogStatus",
    "ThreatDetail",
    "ProtectionResultDict",
    "ToolMetadata",
    "CheckOptions",
    "ProtectOptions",
    "BatchResult",
    "SDKConfigDict",
    "CircuitBreakerConfigDict",
    "SecurityEventDict",
    "ProgressMetadataDict",
    "GuardProtocol",
    "EventHandler",
    "ProgressCallback",
    "ChallengeHandler",
    "BlockHandler",
    # Event Hooks
    "EventHooks",
    "EventType",
    "SecurityEvent",
    # Circuit Breaker
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitState",
]


# Add check_async method to Guard class
def _check_async(self, content, **kwargs):
    """Async check - creates temporary async client."""
    from .async_client import AsyncToolGuard
    import asyncio
    
    async def _do_check():
        async_guard = AsyncToolGuard(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            timeout=self.config.timeout,
        )
        try:
            return await async_guard.check(content, **kwargs)
        finally:
            await async_guard.close()
    
    return _do_check()

Guard.check_async = _check_async  # type: ignore[attr-defined]
