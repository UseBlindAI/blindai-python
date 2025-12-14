"""Main AsyncToolGuard class combining all mixins."""

from typing import Optional

from ..circuit_breaker import CircuitBreakerConfig

from .base import AsyncToolGuardBase
from .http import AsyncHTTPMixin
from .check import AsyncCheckMixin
from .protect import AsyncProtectMixin


class AsyncToolGuard(
    AsyncToolGuardBase,
    AsyncHTTPMixin,
    AsyncCheckMixin,
    AsyncProtectMixin,
):
    """Async Blind AI SDK client for protecting tool calls.

    Async version of ToolGuard for high-performance async applications.

    Example:
        ```python
        guard = AsyncToolGuard(api_key="...", base_url="http://localhost:8000")

        # Protect an async function
        @guard.protect
        async def fetch_data(query: str):
            return await db.execute(query)

        # Use with context manager
        async with AsyncToolGuard(...) as guard:
            result = await guard.check("DROP TABLE users")
        ```

    Attributes:
        config: SDK configuration
        client: Async HTTP client for API requests
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:8000",
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_backoff: float = 0.5,
        fail_open: bool = False,
        verify_ssl: bool = True,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        keepalive_expiry: float = 5.0,
        circuit_breaker: Optional[CircuitBreakerConfig] = None,
    ):
        """Initialize AsyncToolGuard client.

        Args:
            api_key: API key for authentication (optional for now)
            base_url: Base URL for Blind AI API
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            retry_backoff: Backoff multiplier for retries
            fail_open: Allow on error (True) or block on error (False)
            verify_ssl: Verify SSL certificates
            max_connections: Maximum number of concurrent connections
            max_keepalive_connections: Maximum number of keepalive connections
            keepalive_expiry: Keepalive connection expiry in seconds
            circuit_breaker: Optional circuit breaker configuration for resilience

        Raises:
            ConfigurationError: If configuration is invalid
        """
        super().__init__(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            retry_backoff=retry_backoff,
            fail_open=fail_open,
            verify_ssl=verify_ssl,
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
            circuit_breaker=circuit_breaker,
        )
