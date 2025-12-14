"""Session tracking middleware for Blind AI SDK.

Provides session management, behavior tracking, and anomaly detection
for AI agent runtime protection.

Example:
    ```python
    from blindai import ToolGuard
    from blindai.middleware.session import (
        SessionMiddleware,
        SessionGuard,
        SessionConfig,
    )
    
    # Create session-enabled guard
    guard = SessionGuard(
        base_url="http://localhost:8000",
        api_key="your-api-key",
        session_config=SessionConfig(
            user_id="user-123",
            auto_create=True,
            track_behavior=True,
            detect_anomalies=True,
        ),
    )
    
    # Use with automatic session tracking
    @guard.protect
    def send_email(to: str, subject: str, body: str):
        # Automatically tracked in session
        return email_client.send(to, subject, body)
    
    # Check session anomalies
    anomalies = guard.get_anomalies()
    
    # Get session summary
    summary = guard.get_session_summary()
    ```
"""

import logging
import time
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

from ..client import ToolGuard
from ..models import ProtectionResult

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class SessionConfig:
    """Configuration for session middleware.
    
    Attributes:
        user_id: User identifier for session lookup
        session_id: Specific session ID to use
        auto_create: Automatically create session if not exists
        track_behavior: Enable behavior tracking
        detect_anomalies: Enable anomaly detection
        check_rate_limits: Enable rate limit checking
        context: Initial session context
        metadata: Session metadata
        ttl: Session TTL in seconds
        raise_on_rate_limit: Raise exception on rate limit exceeded
        raise_on_anomaly: Raise exception on high-risk anomaly
        anomaly_threshold: Risk level threshold for exceptions (1-4)
    """
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    auto_create: bool = True
    track_behavior: bool = True
    detect_anomalies: bool = True
    check_rate_limits: bool = True
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    ttl: Optional[int] = None
    raise_on_rate_limit: bool = True
    raise_on_anomaly: bool = False
    anomaly_threshold: int = 3  # HIGH risk level


class SessionRateLimitError(Exception):
    """Raised when session rate limit is exceeded."""
    
    def __init__(
        self,
        message: str,
        session_id: str,
        usage: dict[str, Any],
    ):
        super().__init__(message)
        self.session_id = session_id
        self.usage = usage


class SessionAnomalyError(Exception):
    """Raised when session anomaly is detected above threshold."""
    
    def __init__(
        self,
        message: str,
        session_id: str,
        anomalies: list[dict],
        risk_level: str,
    ):
        super().__init__(message)
        self.session_id = session_id
        self.anomalies = anomalies
        self.risk_level = risk_level


@dataclass
class SessionState:
    """Current session state."""
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    created_at: Optional[float] = None
    last_activity: Optional[float] = None
    context: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    rate_limit_usage: dict[str, Any] = field(default_factory=dict)
    anomalies: list[dict] = field(default_factory=list)
    risk_level: str = "none"


class SessionMiddleware:
    """Middleware for session tracking in SDK calls.
    
    Wraps tool guard to add session context and tracking.
    
    Example:
        ```python
        guard = ToolGuard(base_url="http://localhost:8000")
        middleware = SessionMiddleware(
            guard,
            config=SessionConfig(user_id="user-123"),
        )
        
        # Now calls are tracked in session
        result = await middleware.check("DROP TABLE users")
        ```
    """
    
    def __init__(
        self,
        guard: ToolGuard,
        config: Optional[SessionConfig] = None,
    ):
        """Initialize session middleware.
        
        Args:
            guard: Underlying tool guard
            config: Session configuration
        """
        self.guard = guard
        self.config = config or SessionConfig()
        self._state = SessionState()
        self._initialized = False
    
    @property
    def session_id(self) -> Optional[str]:
        """Get current session ID."""
        return self._state.session_id
    
    @property
    def state(self) -> SessionState:
        """Get current session state."""
        return self._state
    
    def initialize(self) -> bool:
        """Initialize session.
        
        Creates or retrieves session based on configuration.
        
        Returns:
            True if session is ready
        """
        if self._initialized and self._state.session_id:
            return True
        
        try:
            # Try to get or create session
            response = self.guard.client.post(
                "/v1/session/get-or-create",
                json={
                    "user_id": self.config.user_id,
                    "ttl": self.config.ttl,
                    "context": self.config.context,
                    "metadata": self.config.metadata,
                },
            )
            
            if response.status_code == 200:
                data = response.json()
                self._state.session_id = data["session_id"]
                self._state.user_id = data.get("user_id")
                self._state.created_at = data.get("created_at")
                self._state.last_activity = data.get("last_activity")
                self._state.context = data.get("context", {})
                self._state.stats = data.get("stats", {})
                self._initialized = True
                logger.info(f"Session initialized: {self._state.session_id}")
                return True
            
            logger.warning(f"Failed to initialize session: {response.status_code}")
            return False
            
        except Exception as e:
            logger.error(f"Error initializing session: {e}")
            return False
    
    def _ensure_session(self) -> bool:
        """Ensure session is initialized."""
        if not self._initialized and self.config.auto_create:
            return self.initialize()
        return self._initialized
    
    def record_event(
        self,
        event_type: str,
        data: dict[str, Any],
        threat_detected: bool = False,
        risk_level: str = "none",
    ) -> bool:
        """Record an event in the session.
        
        Args:
            event_type: Type of event
            data: Event data
            threat_detected: Whether threat was detected
            risk_level: Risk level
            
        Returns:
            True if recorded successfully
        """
        if not self._ensure_session():
            return False
        
        try:
            response = self.guard.client.post(
                f"/v1/session/{self._state.session_id}/events",
                json={
                    "event_type": event_type,
                    "data": data,
                    "threat_detected": threat_detected,
                    "risk_level": risk_level,
                },
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error recording event: {e}")
            return False
    
    def check_rate_limit(
        self,
        tool_name: Optional[str] = None,
        cost: int = 1,
    ) -> dict[str, Any]:
        """Check rate limit for session.
        
        Args:
            tool_name: Optional tool name for specific limits
            cost: Request cost
            
        Returns:
            Rate limit usage information
            
        Raises:
            SessionRateLimitError: If rate limit exceeded and raise_on_rate_limit is True
        """
        if not self._ensure_session() or not self.config.check_rate_limits:
            return {"enabled": False}
        
        try:
            params = {"cost": cost}
            if tool_name:
                params["tool_name"] = tool_name
            
            response = self.guard.client.post(
                f"/v1/session/{self._state.session_id}/rate-limit/check",
                params=params,
            )
            
            if response.status_code == 200:
                usage = response.json()
                self._state.rate_limit_usage = usage
                
                if not usage.get("within_limit", True) and self.config.raise_on_rate_limit:
                    raise SessionRateLimitError(
                        f"Rate limit exceeded for session {self._state.session_id}",
                        self._state.session_id,
                        usage,
                    )
                
                return usage
            
            return {"error": f"Failed with status {response.status_code}"}
            
        except SessionRateLimitError:
            raise
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return {"error": str(e)}
    
    def detect_anomalies(self) -> list[dict]:
        """Detect anomalies in session.
        
        Returns:
            List of detected anomalies
            
        Raises:
            SessionAnomalyError: If high-risk anomaly detected and raise_on_anomaly is True
        """
        if not self._ensure_session() or not self.config.detect_anomalies:
            return []
        
        try:
            response = self.guard.client.get(
                f"/v1/session/{self._state.session_id}/anomalies",
            )
            
            if response.status_code == 200:
                anomalies = response.json()
                self._state.anomalies = anomalies
                
                # Check for high-risk anomalies
                risk_values = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                max_risk = "none"
                
                for anomaly in anomalies:
                    level = anomaly.get("risk_level", "none")
                    if risk_values.get(level, 0) > risk_values.get(max_risk, 0):
                        max_risk = level
                
                self._state.risk_level = max_risk
                
                if (
                    self.config.raise_on_anomaly
                    and risk_values.get(max_risk, 0) >= self.config.anomaly_threshold
                ):
                    raise SessionAnomalyError(
                        f"High-risk anomaly detected in session {self._state.session_id}",
                        self._state.session_id,
                        anomalies,
                        max_risk,
                    )
                
                return anomalies
            
            return []
            
        except SessionAnomalyError:
            raise
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return []
    
    def get_context(self) -> dict[str, Any]:
        """Get session context."""
        if not self._ensure_session():
            return {}
        
        try:
            response = self.guard.client.get(
                f"/v1/session/{self._state.session_id}/context",
            )
            if response.status_code == 200:
                self._state.context = response.json()
                return self._state.context
            return {}
        except Exception as e:
            logger.error(f"Error getting context: {e}")
            return {}
    
    def update_context(self, updates: dict[str, Any]) -> bool:
        """Update session context.
        
        Args:
            updates: Context updates to apply
            
        Returns:
            True if updated successfully
        """
        if not self._ensure_session():
            return False
        
        try:
            response = self.guard.client.put(
                f"/v1/session/{self._state.session_id}/context",
                json={"updates": updates},
            )
            if response.status_code == 200:
                self._state.context.update(updates)
                return True
            return False
        except Exception as e:
            logger.error(f"Error updating context: {e}")
            return False
    
    def get_summary(self) -> dict[str, Any]:
        """Get comprehensive session summary.
        
        Returns:
            Session summary including behavior, anomalies, rate limits
        """
        if not self._ensure_session():
            return {"error": "Session not initialized"}
        
        try:
            response = self.guard.client.get(
                f"/v1/session/{self._state.session_id}/summary",
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"Failed with status {response.status_code}"}
        except Exception as e:
            logger.error(f"Error getting summary: {e}")
            return {"error": str(e)}
    
    def check(
        self,
        input_text: str,
        tool_name: Optional[str] = None,
        **kwargs,
    ) -> ProtectionResult:
        """Check input with session tracking.
        
        Args:
            input_text: Text to check
            tool_name: Optional tool name for rate limiting
            **kwargs: Additional arguments for guard.check()
            
        Returns:
            Protection result
        """
        self._ensure_session()
        
        # Check rate limit first
        if self.config.check_rate_limits:
            self.check_rate_limit(tool_name)
        
        # Do the actual check
        result = self.guard.check(input_text, **kwargs)
        
        # Record event
        if self.config.track_behavior:
            self.record_event(
                event_type="tool_check",
                data={
                    "tool": tool_name,
                    "input_length": len(input_text),
                    "is_threat": result.is_threat,
                    "threat_type": result.threat_type,
                },
                threat_detected=result.is_threat,
                risk_level="high" if result.is_threat else "none",
            )
        
        # Check for anomalies after recording
        if self.config.detect_anomalies:
            self.detect_anomalies()
        
        return result
    
    def end(self) -> bool:
        """End the session.
        
        Returns:
            True if ended successfully
        """
        if not self._state.session_id:
            return True
        
        try:
            response = self.guard.client.delete(
                f"/v1/session/{self._state.session_id}",
            )
            self._state = SessionState()
            self._initialized = False
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False


class SessionGuard(ToolGuard):
    """Tool guard with integrated session tracking.
    
    Extends ToolGuard with session management, behavior tracking,
    and anomaly detection capabilities.
    
    Example:
        ```python
        guard = SessionGuard(
            base_url="http://localhost:8000",
            api_key="your-api-key",
            session_config=SessionConfig(
                user_id="user-123",
                track_behavior=True,
                detect_anomalies=True,
            ),
        )
        
        # Protected function with session tracking
        @guard.protect
        def query_database(sql: str):
            return db.execute(sql)
        
        # Each call is tracked in the session
        result = query_database("SELECT * FROM users")
        
        # Check session status
        print(guard.risk_level)  # "none" | "low" | "medium" | "high" | "critical"
        print(guard.get_anomalies())
        
        # End session
        guard.end_session()
        ```
    """
    
    def __init__(
        self,
        session_config: Optional[SessionConfig] = None,
        **kwargs,
    ):
        """Initialize session guard.
        
        Args:
            session_config: Session configuration
            **kwargs: Arguments passed to ToolGuard
        """
        super().__init__(**kwargs)
        self.session_config = session_config or SessionConfig()
        self._middleware = SessionMiddleware(self, self.session_config)
    
    @property
    def session_id(self) -> Optional[str]:
        """Get current session ID."""
        return self._middleware.session_id
    
    @property
    def session_state(self) -> SessionState:
        """Get current session state."""
        return self._middleware.state
    
    @property
    def risk_level(self) -> str:
        """Get current risk level."""
        return self._middleware.state.risk_level
    
    @property
    def anomalies(self) -> list[dict]:
        """Get detected anomalies."""
        return self._middleware.state.anomalies
    
    def start_session(
        self,
        user_id: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> bool:
        """Start or reset session.
        
        Args:
            user_id: Optional user ID override
            context: Optional context override
            
        Returns:
            True if session started
        """
        if user_id:
            self._middleware.config.user_id = user_id
        if context:
            self._middleware.config.context = context
        
        return self._middleware.initialize()
    
    def end_session(self) -> bool:
        """End current session.
        
        Returns:
            True if ended successfully
        """
        return self._middleware.end()
    
    def get_context(self) -> dict[str, Any]:
        """Get session context."""
        return self._middleware.get_context()
    
    def update_context(self, updates: dict[str, Any]) -> bool:
        """Update session context."""
        return self._middleware.update_context(updates)
    
    def get_anomalies(self) -> list[dict]:
        """Get detected anomalies."""
        return self._middleware.detect_anomalies()
    
    def get_session_summary(self) -> dict[str, Any]:
        """Get comprehensive session summary."""
        return self._middleware.get_summary()
    
    def check_rate_limit(
        self,
        tool_name: Optional[str] = None,
        cost: int = 1,
    ) -> dict[str, Any]:
        """Check rate limit for session."""
        return self._middleware.check_rate_limit(tool_name, cost)
    
    def record_event(
        self,
        event_type: str,
        data: dict[str, Any],
        threat_detected: bool = False,
        risk_level: str = "none",
    ) -> bool:
        """Record a custom event in the session."""
        return self._middleware.record_event(
            event_type, data, threat_detected, risk_level
        )
    
    def check(self, input_text: str, **kwargs) -> ProtectionResult:
        """Check input with session tracking.
        
        Overrides parent check to add session tracking.
        """
        return self._middleware.check(input_text, **kwargs)
    
    def protect(
        self,
        func: Optional[F] = None,
        *,
        tool_name: Optional[str] = None,
        track: bool = True,
    ) -> F:
        """Decorator to protect a function with session tracking.
        
        Args:
            func: Function to protect
            tool_name: Tool name for rate limiting (defaults to func name)
            track: Whether to track calls in session
            
        Returns:
            Protected function
        """
        def decorator(fn: F) -> F:
            _tool_name = tool_name or fn.__name__
            
            @wraps(fn)
            def wrapper(*args, **kwargs):
                # Ensure session is initialized
                self._middleware._ensure_session()
                
                # Check rate limit
                if self.session_config.check_rate_limits:
                    self._middleware.check_rate_limit(_tool_name)
                
                # Extract input for protection check
                input_text = ""
                if args:
                    input_text = str(args[0])
                elif kwargs:
                    first_value = next(iter(kwargs.values()), "")
                    input_text = str(first_value)
                
                # Do protection check
                result = self._middleware.guard.check(input_text)
                
                # Record event
                if track and self.session_config.track_behavior:
                    self._middleware.record_event(
                        event_type="tool_call",
                        data={
                            "tool": _tool_name,
                            "args_count": len(args),
                            "kwargs_keys": list(kwargs.keys()),
                            "is_threat": result.is_threat,
                            "threat_type": result.threat_type,
                        },
                        threat_detected=result.is_threat,
                        risk_level="high" if result.is_threat else "none",
                    )
                
                # Check for anomalies
                if self.session_config.detect_anomalies:
                    self._middleware.detect_anomalies()
                
                # Block if threat
                if result.is_threat:
                    from ..exceptions import ThreatBlockedError
                    raise ThreatBlockedError(
                        f"Threat blocked: {result.threat_type}",
                        threat_level=result.threat_level,
                        threat_type=result.threat_type,
                    )
                
                return fn(*args, **kwargs)
            
            return wrapper  # type: ignore
        
        if func is not None:
            return decorator(func)
        return decorator  # type: ignore


# Async support
class AsyncSessionMiddleware:
    """Async version of session middleware."""
    
    def __init__(
        self,
        guard,  # AsyncToolGuard
        config: Optional[SessionConfig] = None,
    ):
        """Initialize async session middleware.
        
        Args:
            guard: Underlying async tool guard
            config: Session configuration
        """
        self.guard = guard
        self.config = config or SessionConfig()
        self._state = SessionState()
        self._initialized = False
    
    @property
    def session_id(self) -> Optional[str]:
        """Get current session ID."""
        return self._state.session_id
    
    async def initialize(self) -> bool:
        """Initialize session asynchronously."""
        if self._initialized and self._state.session_id:
            return True
        
        try:
            response = await self.guard.client.post(
                "/v1/session/get-or-create",
                json={
                    "user_id": self.config.user_id,
                    "ttl": self.config.ttl,
                    "context": self.config.context,
                    "metadata": self.config.metadata,
                },
            )
            
            if response.status_code == 200:
                data = response.json()
                self._state.session_id = data["session_id"]
                self._state.user_id = data.get("user_id")
                self._state.created_at = data.get("created_at")
                self._state.context = data.get("context", {})
                self._initialized = True
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error initializing session: {e}")
            return False
    
    async def record_event(
        self,
        event_type: str,
        data: dict[str, Any],
        threat_detected: bool = False,
        risk_level: str = "none",
    ) -> bool:
        """Record an event asynchronously."""
        if not self._initialized and self.config.auto_create:
            await self.initialize()
        
        if not self._state.session_id:
            return False
        
        try:
            response = await self.guard.client.post(
                f"/v1/session/{self._state.session_id}/events",
                json={
                    "event_type": event_type,
                    "data": data,
                    "threat_detected": threat_detected,
                    "risk_level": risk_level,
                },
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error recording event: {e}")
            return False
    
    async def check(
        self,
        input_text: str,
        tool_name: Optional[str] = None,
        **kwargs,
    ) -> ProtectionResult:
        """Check input with session tracking asynchronously."""
        if not self._initialized and self.config.auto_create:
            await self.initialize()
        
        # Do the actual check
        result = await self.guard.check(input_text, **kwargs)
        
        # Record event
        if self.config.track_behavior:
            await self.record_event(
                event_type="tool_check",
                data={
                    "tool": tool_name,
                    "input_length": len(input_text),
                    "is_threat": result.is_threat,
                },
                threat_detected=result.is_threat,
                risk_level="high" if result.is_threat else "none",
            )
        
        return result
    
    async def end(self) -> bool:
        """End the session asynchronously."""
        if not self._state.session_id:
            return True
        
        try:
            response = await self.guard.client.delete(
                f"/v1/session/{self._state.session_id}",
            )
            self._state = SessionState()
            self._initialized = False
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error ending session: {e}")
            return False
