"""Base class for AsyncToolGuard with initialization and lifecycle."""

import logging
from typing import Optional

import httpx

from ..circuit_breaker import CircuitBreaker, CircuitBreakerConfig
from ..exceptions import ConfigurationError
from ..models import SDKConfig

logger = logging.getLogger(__name__)


class AsyncToolGuardBase:
    """Base class providing initialization and lifecycle management."""

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
        try:
            self.config = SDKConfig(
                api_key=api_key,
                base_url=base_url,
                timeout=timeout,
                max_retries=max_retries,
                retry_backoff=retry_backoff,
                fail_open=fail_open,
                verify_ssl=verify_ssl,
            )
        except ValueError as e:
            raise ConfigurationError(f"Invalid configuration: {e}") from e

        # Configure connection pooling for high-performance async operations
        limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
        )

        # Build headers with authentication
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "blind-ai-sdk/0.1.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        # Create async HTTP client with connection pooling and authentication
        self.client = httpx.AsyncClient(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
            limits=limits,
            headers=headers,
        )

        # Initialize circuit breaker if configured
        if circuit_breaker:
            self._circuit_breaker = CircuitBreaker(circuit_breaker)
        else:
            self._circuit_breaker = None

    @property
    def circuit_breaker(self) -> Optional[CircuitBreaker]:
        """Get circuit breaker instance for monitoring.

        Returns:
            CircuitBreaker instance or None if not configured
        """
        return self._circuit_breaker

    async def close(self):
        """Close async HTTP client and cleanup resources."""
        await self.client.aclose()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
