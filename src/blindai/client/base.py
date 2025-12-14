"""Blind AI SDK client - base ToolGuard class."""

import functools
import logging
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Generator, Optional, Union

import httpx

from blindai.stubs.rbac import UserContext
from ..circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpen
from ..exceptions import (
    APIError,
    ConfigurationError,
    RetryExhaustedError,
    ThreatBlockedError,
    TimeoutError,
)
from ..hooks import (
    EventHooks,
    EventType,
    SecurityEvent,
    create_error_event,
    create_event_from_result,
)
from ..models import ProtectionResult, SDKConfig

from .protect import ProtectMixin
from .tools import ToolsMixin
from .http import HTTPMixin

logger = logging.getLogger(__name__)


@dataclass
class ProgressMetadata:
    """Metadata provided with progress callbacks.
    
    Attributes:
        threats_detected: Number of threats detected so far
        blocked_count: Number of items blocked so far
        avg_latency_ms: Average processing time per item
        total_latency_ms: Total processing time so far
        current_item_preview: Preview of current item text (truncated)
        current_index: Index of current item being processed
        errors_count: Number of errors encountered
    """
    threats_detected: int = 0
    blocked_count: int = 0
    avg_latency_ms: float = 0.0
    total_latency_ms: float = 0.0
    current_item_preview: Optional[str] = None
    current_index: Optional[int] = None
    errors_count: int = 0
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "threats_detected": self.threats_detected,
            "blocked_count": self.blocked_count,
            "avg_latency_ms": self.avg_latency_ms,
            "total_latency_ms": self.total_latency_ms,
            "current_item_preview": self.current_item_preview,
            "current_index": self.current_index,
            "errors_count": self.errors_count,
        }


# Type alias for progress callback
ProgressCallback = Union[
    Callable[[int, int], None],  # Simple: (completed, total)
    Callable[[int, int, Optional[ProgressMetadata]], None],  # With metadata
]


class SessionContext:
    """Context object for session-scoped security checks.
    
    Holds session ID, user context, and metadata that apply to all checks
    within a guard.context() block.
    
    Attributes:
        session_id: Unique session identifier
        user: Optional user context for RBAC
        metadata: Additional metadata for all checks
    """
    
    def __init__(
        self,
        session_id: str,
        user: Optional["UserContext"] = None,
        metadata: Optional[dict[str, Any]] = None,
    ):
        self.session_id = session_id
        self.user = user
        self.metadata = metadata or {}
    
    def __repr__(self) -> str:
        return (
            f"SessionContext(session_id={self.session_id!r}, "
            f"user={self.user!r}, metadata={self.metadata!r})"
        )


class ToolGuard(ProtectMixin, ToolsMixin, HTTPMixin):
    """Blind AI SDK client for protecting tool calls.

    Provides easy integration for protecting tool/function calls from threats
    like SQL injection, prompt injection, and PII disclosure.

    Example:
        ```python
        guard = ToolGuard(api_key="your-api-key")

        # Protect a function
        @guard.protect
        def execute_sql(query: str):
            return db.execute(query)

        # This will be blocked
        try:
            result = execute_sql("DROP TABLE users")
        except ThreatBlockedError as e:
            print(f"Blocked: {e}")

        # Register event hooks
        @guard.on_block
        def handle_blocked(event):
            send_alert(event.threat_level)
        ```

    Attributes:
        config: SDK configuration
        client: HTTP client for API requests
        hooks: Event hooks for callbacks
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://web-production-b14fb.up.railway.app",
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_backoff: float = 0.5,
        fail_open: bool = False,
        verify_ssl: bool = True,
        circuit_breaker: Optional[CircuitBreakerConfig] = None,
    ):
        """Initialize ToolGuard client.

        Args:
            api_key: API key for authentication (optional for now)
            base_url: Base URL for Blind AI API
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            retry_backoff: Backoff multiplier for retries
            fail_open: Allow on error (True) or block on error (False)
            verify_ssl: Verify SSL certificates
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

        # Build headers with authentication
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "blind-ai-sdk/0.1.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        # Create HTTP client with authentication headers
        self.client = httpx.Client(
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            verify=self.config.verify_ssl,
            headers=headers,
        )

        # Initialize event hooks
        self.hooks = EventHooks()

        # Initialize circuit breaker if configured
        if circuit_breaker:
            self._circuit_breaker = CircuitBreaker(circuit_breaker)
        else:
            self._circuit_breaker = None
        
        # Thread-local storage for session context
        self._local = threading.local()
        
        # Track registered tools to avoid duplicate registrations
        self._registered_tools: set[str] = set()
        self._registration_lock = threading.Lock()

    @property
    def circuit_breaker(self) -> Optional[CircuitBreaker]:
        """Get circuit breaker instance for monitoring.

        Returns:
            CircuitBreaker instance or None if not configured

        Example:
            ```python
            guard = ToolGuard(circuit_breaker=CircuitBreakerConfig())
            print(f"Circuit state: {guard.circuit_breaker.state}")
            print(f"Health: {guard.circuit_breaker.health}")
            ```
        """
        return self._circuit_breaker

    # Event hook decorators
    def on_block(self, handler: Callable[[SecurityEvent], None]) -> Callable:
        """Register a handler for blocked requests.

        Args:
            handler: Callback function that receives SecurityEvent

        Returns:
            The handler (for use as decorator)

        Example:
            ```python
            @guard.on_block
            def handle_blocked(event):
                send_security_alert(event.threat_level, event.threats_detected)
            ```
        """
        return self.hooks.on_block(handler)

    def on_challenge(self, handler: Callable[[SecurityEvent], Optional[bool]]) -> Callable:
        """Register a handler for challenged requests.

        Challenge handlers can return True to approve or False to deny.

        Args:
            handler: Callback function that receives SecurityEvent

        Returns:
            The handler (for use as decorator)

        Example:
            ```python
            @guard.on_challenge
            def handle_challenge(event):
                return get_user_approval(event.text)
            ```
        """
        return self.hooks.on_challenge(handler)

    def on_allow(self, handler: Callable[[SecurityEvent], None]) -> Callable:
        """Register a handler for allowed requests.

        Args:
            handler: Callback function that receives SecurityEvent

        Returns:
            The handler (for use as decorator)

        Example:
            ```python
            @guard.on_allow
            def handle_allow(event):
                log_access(event.user_id, event.tool_name)
            ```
        """
        return self.hooks.on_allow(handler)

    def on_error(self, handler: Callable[[SecurityEvent], None]) -> Callable:
        """Register a handler for errors.

        Args:
            handler: Callback function that receives SecurityEvent

        Returns:
            The handler (for use as decorator)

        Example:
            ```python
            @guard.on_error
            def handle_error(event):
                log_error(event.error)
            ```
        """
        return self.hooks.on_error(handler)

    # Session/Context Management
    @contextmanager
    def session(self, session_id: Optional[str] = None) -> Generator[str, None, None]:
        """Context manager for automatic session tracking.
        
        All checks within this context automatically use the session ID
        for multi-turn conversation tracking and chain pattern detection.
        
        Args:
            session_id: Optional session ID (auto-generated if not provided)
            
        Yields:
            The session ID being used
            
        Example:
            ```python
            with guard.session() as session_id:
                # All checks automatically use this session
                result1 = guard.check("query 1")  # Uses session_id
                result2 = guard.check("query 2")  # Uses same session_id
                
            # Or with explicit session ID
            with guard.session("user-123-conversation") as sid:
                guard.check("SELECT * FROM users")
            ```
        """
        sid = session_id or str(uuid.uuid4())
        old_session = getattr(self._local, 'session_id', None)
        self._local.session_id = sid
        try:
            yield sid
        finally:
            self._local.session_id = old_session
    
    @contextmanager
    def context(
        self,
        context_id: Optional[str] = None,
        user: Optional[UserContext] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Generator["SessionContext", None, None]:
        """Context manager for full request context.
        
        Sets session ID, user context, and metadata for all checks within the block.
        
        Args:
            context_id: Optional context/session ID (auto-generated if not provided)
            user: Optional user context for RBAC
            metadata: Optional metadata to include with all checks
            
        Yields:
            SessionContext object with the active context details
            
        Example:
            ```python
            user = UserContext(user_id="user-123", roles=["analyst"])
            
            with guard.context(user=user, metadata={"source": "web"}) as ctx:
                print(f"Session: {ctx.session_id}")
                
                # All checks include user and metadata automatically
                guard.check("SELECT * FROM users")
                guard.check("DELETE FROM logs")
            ```
        """
        ctx = SessionContext(
            session_id=context_id or str(uuid.uuid4()),
            user=user,
            metadata=metadata or {},
        )
        
        # Save old context
        old_session = getattr(self._local, 'session_id', None)
        old_user = getattr(self._local, 'user', None)
        old_metadata = getattr(self._local, 'metadata', None)
        
        # Set new context
        self._local.session_id = ctx.session_id
        self._local.user = ctx.user
        self._local.metadata = ctx.metadata
        
        try:
            yield ctx
        finally:
            # Restore old context
            self._local.session_id = old_session
            self._local.user = old_user
            self._local.metadata = old_metadata
    
    def _get_effective_context(
        self,
        context_id: Optional[str],
        user: Optional[UserContext],
        metadata: Optional[dict[str, Any]],
    ) -> tuple[Optional[str], Optional[UserContext], dict[str, Any]]:
        """Get effective context by merging explicit args with thread-local context.
        
        Explicit arguments take precedence over thread-local context.
        """
        effective_context_id = context_id or getattr(self._local, 'session_id', None)
        effective_user = user or getattr(self._local, 'user', None)
        
        # Merge metadata (thread-local as base, explicit overwrites)
        effective_metadata = dict(getattr(self._local, 'metadata', None) or {})
        if metadata:
            effective_metadata.update(metadata)
        
        return effective_context_id, effective_user, effective_metadata

    def close(self):
        """Close HTTP client and cleanup resources.

        Important: Always call close() when done or use context manager.

        Example:
            ```python
            # Manual cleanup
            guard = ToolGuard()
            try:
                guard.check("some text")
            finally:
                guard.close()

            # Better: use context manager
            with ToolGuard() as guard:
                guard.check("some text")
            ```
        """
        if hasattr(self, 'client') and self.client:
            self.client.close()
            self._closed = True

    def __enter__(self):
        """Context manager entry."""
        self._closed = False
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def __del__(self):
        """Destructor - warn if client not properly closed."""
        if hasattr(self, '_closed') and not self._closed:
            import warnings
            warnings.warn(
                "ToolGuard client was not properly closed. "
                "Use 'with ToolGuard() as guard:' or call guard.close()",
                ResourceWarning,
                stacklevel=2
            )
        if hasattr(self, 'client'):
            try:
                self.client.close()
            except Exception:
                pass
