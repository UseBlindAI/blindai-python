"""Circuit breaker pattern for Blind AI SDK.

Provides resilience against API failures by implementing the circuit breaker pattern.
When failures exceed a threshold, the circuit "opens" and fails fast without making
requests, allowing the system to recover.

Example:
    ```python
    from blindai import ToolGuard
    from blindai.circuit_breaker import CircuitBreaker, CircuitState

    # Create circuit breaker
    breaker = CircuitBreaker(
        failure_threshold=5,
        recovery_timeout=30.0,
        half_open_max_calls=3,
    )

    # Use with ToolGuard
    guard = ToolGuard(circuit_breaker=breaker)

    # Or wrap manually
    @breaker.protect
    def make_request():
        return api.call()
    ```
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional, TypeVar

T = TypeVar("T")


class CircuitState(str, Enum):
    """States of the circuit breaker."""

    CLOSED = "closed"  # Normal operation, requests flow through
    OPEN = "open"  # Failures exceeded threshold, failing fast
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker.

    Attributes:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before trying recovery
        half_open_max_calls: Max calls allowed in half-open state
        failure_exceptions: Exception types that count as failures
        exclude_exceptions: Exception types to ignore (e.g., validation errors)
    """

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3
    failure_exceptions: tuple = (Exception,)
    exclude_exceptions: tuple = ()


@dataclass
class CircuitBreakerStats:
    """Statistics for circuit breaker monitoring.

    Attributes:
        state: Current circuit state
        failure_count: Number of consecutive failures
        success_count: Number of successes in half-open state
        total_failures: Total failures since creation
        total_successes: Total successes since creation
        last_failure_time: Time of last failure
        last_success_time: Time of last success
        last_state_change: Time of last state change
        times_opened: Number of times circuit opened
    """

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    total_failures: int = 0
    total_successes: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    last_state_change: datetime = field(default_factory=datetime.utcnow)
    times_opened: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "total_failures": self.total_failures,
            "total_successes": self.total_successes,
            "last_failure_time": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_success_time": self.last_success_time.isoformat() if self.last_success_time else None,
            "last_state_change": self.last_state_change.isoformat(),
            "times_opened": self.times_opened,
        }


class CircuitOpenError(Exception):
    """Raised when circuit is open and request is rejected.

    Attributes:
        message: Error message
        retry_after: Seconds until circuit may close
        stats: Current circuit breaker stats
    """

    def __init__(
        self,
        message: str = "Circuit breaker is open",
        retry_after: Optional[float] = None,
        stats: Optional[CircuitBreakerStats] = None,
    ):
        super().__init__(message)
        self.retry_after = retry_after
        self.stats = stats


# Alias for external API
CircuitBreakerOpen = CircuitOpenError


class CircuitBreaker:
    """Circuit breaker for API resilience.

    Implements the circuit breaker pattern to prevent cascading failures
    when the API is unavailable or experiencing issues.

    States:
        CLOSED: Normal operation, all requests pass through
        OPEN: Too many failures, requests fail immediately
        HALF_OPEN: Testing recovery, limited requests allowed

    Example:
        ```python
        # Using config object
        config = CircuitBreakerConfig(failure_threshold=5)
        breaker = CircuitBreaker(config)

        # Or using individual parameters
        breaker = CircuitBreaker(
            failure_threshold=5,      # Open after 5 failures
            recovery_timeout=30.0,    # Try recovery after 30s
            half_open_max_calls=3,    # Allow 3 test calls in half-open
        )

        @breaker.protect
        def call_api():
            return requests.get("https://api.example.com")

        try:
            result = call_api()
        except CircuitOpenError as e:
            print(f"Circuit open, retry after {e.retry_after}s")
        ```

    Attributes:
        failure_threshold: Number of failures to open circuit
        recovery_timeout: Seconds to wait before trying recovery
        half_open_max_calls: Max calls allowed in half-open state
        failure_exceptions: Exception types that count as failures
    """

    def __init__(
        self,
        config_or_threshold: Optional[CircuitBreakerConfig | int] = None,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
        failure_exceptions: tuple[type[Exception], ...] = (Exception,),
        exclude_exceptions: tuple[type[Exception], ...] = (),
        on_state_change: Optional[Callable[[CircuitState, CircuitState], None]] = None,
    ):
        """Initialize circuit breaker.

        Args:
            config_or_threshold: CircuitBreakerConfig object or failure_threshold int
            recovery_timeout: Seconds to wait in open state before half-open
            half_open_max_calls: Max calls allowed during half-open testing
            failure_exceptions: Exception types that count as failures
            exclude_exceptions: Exception types to NOT count as failures
            on_state_change: Callback when state changes (old_state, new_state)
        """
        # Handle config object or individual parameters
        if isinstance(config_or_threshold, CircuitBreakerConfig):
            config = config_or_threshold
            self.failure_threshold = config.failure_threshold
            self.recovery_timeout = config.recovery_timeout
            self.half_open_max_calls = config.half_open_max_calls
            self.failure_exceptions = config.failure_exceptions
            self.exclude_exceptions = config.exclude_exceptions
        else:
            self.failure_threshold = config_or_threshold if config_or_threshold is not None else 5
            self.recovery_timeout = recovery_timeout
            self.half_open_max_calls = half_open_max_calls
            self.failure_exceptions = failure_exceptions
            self.exclude_exceptions = exclude_exceptions

        self.on_state_change = on_state_change

        # State
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._last_failure_time: Optional[float] = None
        self._last_success_time: Optional[float] = None
        self._opened_at: Optional[float] = None

        # Stats
        self._total_failures = 0
        self._total_successes = 0
        self._times_opened = 0
        self._last_state_change = time.time()

        # Thread safety
        self._lock = threading.RLock()

    @property
    def state(self) -> CircuitState:
        """Get current circuit state."""
        with self._lock:
            self._check_state_transition()
            return self._state

    @property
    def stats(self) -> CircuitBreakerStats:
        """Get current circuit breaker statistics."""
        with self._lock:
            return CircuitBreakerStats(
                state=self._state,
                failure_count=self._failure_count,
                success_count=self._success_count,
                total_failures=self._total_failures,
                total_successes=self._total_successes,
                last_failure_time=datetime.fromtimestamp(self._last_failure_time) if self._last_failure_time else None,
                last_success_time=datetime.fromtimestamp(self._last_success_time) if self._last_success_time else None,
                last_state_change=datetime.fromtimestamp(self._last_state_change),
                times_opened=self._times_opened,
            )

    def _check_state_transition(self) -> None:
        """Check if state should transition based on timeouts."""
        if self._state == CircuitState.OPEN:
            # Check if recovery timeout has passed
            if self._opened_at and (time.time() - self._opened_at) >= self.recovery_timeout:
                self._transition_to(CircuitState.HALF_OPEN)

    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new state.

        Args:
            new_state: State to transition to
        """
        old_state = self._state
        if old_state == new_state:
            return

        self._state = new_state
        self._last_state_change = time.time()

        if new_state == CircuitState.OPEN:
            self._opened_at = time.time()
            self._times_opened += 1
        elif new_state == CircuitState.HALF_OPEN:
            self._half_open_calls = 0
            self._success_count = 0
        elif new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._opened_at = None

        # Notify callback
        if self.on_state_change:
            try:
                self.on_state_change(old_state, new_state)
            except Exception:
                pass  # Don't let callback errors affect circuit breaker

    def _record_success(self) -> None:
        """Record a successful call."""
        with self._lock:
            self._total_successes += 1
            self._last_success_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                # If enough successes, close circuit
                if self._success_count >= self.half_open_max_calls:
                    self._transition_to(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                # Reset failure count on success
                self._failure_count = 0

    def _record_failure(self) -> None:
        """Record a failed call."""
        with self._lock:
            self._failure_count += 1
            self._total_failures += 1
            self._last_failure_time = time.time()

            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open reopens circuit
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                # Check if threshold reached
                if self._failure_count >= self.failure_threshold:
                    self._transition_to(CircuitState.OPEN)

    def _should_allow_request(self) -> bool:
        """Check if request should be allowed.

        Returns:
            True if request should proceed, False if circuit is open
        """
        with self._lock:
            self._check_state_transition()

            if self._state == CircuitState.CLOSED:
                return True

            if self._state == CircuitState.OPEN:
                return False

            # Half-open: allow limited requests
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False

            return True

    def _is_failure_exception(self, exc: Exception) -> bool:
        """Check if exception should count as a failure.

        Args:
            exc: The exception to check

        Returns:
            True if exception counts as failure
        """
        # Check exclusions first
        if isinstance(exc, self.exclude_exceptions):
            return False
        # Check if it's a failure type
        return isinstance(exc, self.failure_exceptions)

    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute a function with circuit breaker protection.

        Args:
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Result from function

        Raises:
            CircuitOpenError: If circuit is open
            Exception: Any exception from the function
        """
        if not self._should_allow_request():
            retry_after = None
            if self._opened_at:
                elapsed = time.time() - self._opened_at
                retry_after = max(0, self.recovery_timeout - elapsed)

            raise CircuitOpenError(
                message="Circuit breaker is open - failing fast",
                retry_after=retry_after,
                stats=self.stats,
            )

        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            if self._is_failure_exception(e):
                self._record_failure()
            raise

    def execute_with_fallback(
        self,
        func: Callable[[], T],
        fallback: Optional[Callable[[Exception], T]] = None,
    ) -> T:
        """Execute a function with circuit breaker and optional fallback.

        This is the main entry point for executing protected operations.

        Args:
            func: Zero-argument function to execute
            fallback: Optional fallback function that receives the exception

        Returns:
            Result from function or fallback

        Raises:
            CircuitBreakerOpen: If circuit is open and no fallback provided
            Exception: Any exception from the function if no fallback
        """
        try:
            return self.call(func)
        except CircuitOpenError as e:
            if fallback:
                return fallback(e)
            raise CircuitBreakerOpen(
                f"Circuit breaker is open. Retry after: {e.retry_after:.1f}s"
            ) from e
        except Exception as e:
            if fallback:
                return fallback(e)
            raise

    async def call_async(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute an async function with circuit breaker protection.

        Args:
            func: Async function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            Result from function

        Raises:
            CircuitOpenError: If circuit is open
            Exception: Any exception from the function
        """
        if not self._should_allow_request():
            retry_after = None
            if self._opened_at:
                elapsed = time.time() - self._opened_at
                retry_after = max(0, self.recovery_timeout - elapsed)

            raise CircuitOpenError(
                message="Circuit breaker is open - failing fast",
                retry_after=retry_after,
                stats=self.stats,
            )

        try:
            result = await func(*args, **kwargs)
            self._record_success()
            return result
        except Exception as e:
            if self._is_failure_exception(e):
                self._record_failure()
            raise

    async def execute_async(
        self,
        coro,
        fallback: Optional[Callable[[Exception], T]] = None,
    ) -> T:
        """Execute an awaitable with circuit breaker and optional fallback.

        This is the async entry point for executing protected operations.

        Args:
            coro: Coroutine to await
            fallback: Optional fallback function that receives the exception

        Returns:
            Result from coroutine or fallback

        Raises:
            CircuitBreakerOpen: If circuit is open and no fallback provided
            Exception: Any exception from the coroutine if no fallback
        """
        if not self._should_allow_request():
            retry_after = None
            if self._opened_at:
                elapsed = time.time() - self._opened_at
                retry_after = max(0, self.recovery_timeout - elapsed)

            error = CircuitOpenError(
                message="Circuit breaker is open - failing fast",
                retry_after=retry_after,
                stats=self.stats,
            )
            if fallback:
                return fallback(error)
            raise CircuitBreakerOpen(
                f"Circuit breaker is open. Retry after: {retry_after:.1f}s"
            ) from error

        try:
            result = await coro
            self._record_success()
            return result
        except Exception as e:
            if self._is_failure_exception(e):
                self._record_failure()
            if fallback:
                return fallback(e)
            raise

    def protect(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator to protect a function with circuit breaker.

        Args:
            func: Function to protect

        Returns:
            Wrapped function

        Example:
            ```python
            @breaker.protect
            def call_api():
                return requests.get(url)
            ```
        """
        import asyncio
        import functools

        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                return await self.call_async(func, *args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                return self.call(func, *args, **kwargs)
            return sync_wrapper

    def reset(self) -> None:
        """Reset circuit breaker to closed state."""
        with self._lock:
            self._transition_to(CircuitState.CLOSED)
            self._failure_count = 0
            self._success_count = 0
            self._half_open_calls = 0

    def force_open(self) -> None:
        """Force circuit to open state (for testing/maintenance)."""
        with self._lock:
            self._transition_to(CircuitState.OPEN)

    def force_close(self) -> None:
        """Force circuit to closed state (for recovery)."""
        with self._lock:
            self._transition_to(CircuitState.CLOSED)
