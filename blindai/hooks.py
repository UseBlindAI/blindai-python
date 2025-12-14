"""Event hooks system for Blind AI SDK.

Provides a way to register callbacks for various events like blocked requests,
challenges, and successful checks.

Example:
    ```python
    from blindai import ToolGuard
    from blindai.hooks import EventHooks

    guard = ToolGuard()

    # Register event handlers
    @guard.on_block
    def handle_blocked(event):
        print(f"Blocked: {event.threat_level}")
        send_alert(event)

    @guard.on_challenge
    def handle_challenge(event):
        return get_user_approval(event)

    @guard.on_allow
    def handle_allow(event):
        log_access(event)
    ```
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union


class EventType(str, Enum):
    """Types of events that can be hooked."""

    BLOCK = "block"
    CHALLENGE = "challenge"
    ALLOW = "allow"
    ERROR = "error"
    BEFORE_CHECK = "before_check"
    AFTER_CHECK = "after_check"


@dataclass
class SecurityEvent:
    """Event data passed to hook callbacks.

    Attributes:
        event_type: Type of event (block, challenge, allow, error)
        timestamp: When the event occurred
        text: The text that was checked (may be truncated for privacy)
        action: The action taken (block, challenge, allow, log)
        threat_level: Severity level if threat detected
        threats_detected: List of detected threats
        confidence: Detection confidence score
        latency_ms: Processing time in milliseconds
        context_id: Session/conversation context ID
        tool_name: Name of the tool being protected
        user_id: User ID if available
        metadata: Additional metadata
        result: Full ProtectionResult object
        error: Exception if event_type is ERROR
    """

    event_type: EventType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    text: str = ""
    action: str = ""
    threat_level: str = "none"
    threats_detected: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    latency_ms: float = 0.0
    context_id: Optional[str] = None
    tool_name: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Any] = None
    error: Optional[Exception] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "text_preview": self.text[:100] + "..." if len(self.text) > 100 else self.text,
            "action": self.action,
            "threat_level": self.threat_level,
            "threats_detected": self.threats_detected,
            "confidence": self.confidence,
            "latency_ms": self.latency_ms,
            "context_id": self.context_id,
            "tool_name": self.tool_name,
            "user_id": self.user_id,
            "metadata": self.metadata,
            "error": str(self.error) if self.error else None,
        }


# Type alias for event handlers
EventHandler = Callable[[SecurityEvent], Optional[bool]]


class EventHooks:
    """Manages event hooks for the Blind AI SDK.

    Provides registration and dispatching of event handlers for various
    security events like blocks, challenges, and allows.

    Example:
        ```python
        hooks = EventHooks()

        # Register handlers
        hooks.on_block(lambda e: print(f"Blocked: {e.threat_level}"))
        hooks.on_challenge(lambda e: input("Approve? ") == "yes")

        # Dispatch events
        hooks.dispatch(EventType.BLOCK, event)
        ```
    """

    def __init__(self):
        """Initialize event hooks."""
        self._handlers: Dict[EventType, List[EventHandler]] = {
            event_type: [] for event_type in EventType
        }

    def register(
        self,
        event_type: EventType,
        handler: EventHandler,
    ) -> None:
        """Register an event handler.

        Args:
            event_type: Type of event to handle
            handler: Callback function that receives SecurityEvent
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def unregister(
        self,
        event_type: EventType,
        handler: EventHandler,
    ) -> bool:
        """Unregister an event handler.

        Args:
            event_type: Type of event
            handler: Handler to remove

        Returns:
            True if handler was found and removed
        """
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            return True
        return False

    def clear(self, event_type: Optional[EventType] = None) -> None:
        """Clear event handlers.

        Args:
            event_type: Specific event type to clear, or None for all
        """
        if event_type:
            self._handlers[event_type] = []
        else:
            for et in EventType:
                self._handlers[et] = []

    def dispatch(
        self,
        event_type: EventType,
        event: SecurityEvent,
    ) -> List[Any]:
        """Dispatch an event to all registered handlers.

        Args:
            event_type: Type of event
            event: Event data

        Returns:
            List of return values from handlers
        """
        results = []
        for handler in self._handlers.get(event_type, []):
            try:
                result = handler(event)
                results.append(result)
            except Exception as e:
                # Log but don't fail on handler errors
                import warnings
                warnings.warn(f"Event handler error: {e}")
                results.append(None)
        return results

    async def dispatch_async(
        self,
        event_type: EventType,
        event: SecurityEvent,
    ) -> List[Any]:
        """Dispatch an event to handlers asynchronously.

        Args:
            event_type: Type of event
            event: Event data

        Returns:
            List of return values from handlers
        """
        import asyncio

        results = []
        for handler in self._handlers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(handler):
                    result = await handler(event)
                else:
                    result = handler(event)
                results.append(result)
            except Exception as e:
                import warnings
                warnings.warn(f"Event handler error: {e}")
                results.append(None)
        return results

    # Decorator methods for convenient registration
    def on_block(self, handler: EventHandler) -> EventHandler:
        """Decorator to register a block event handler.

        Example:
            ```python
            @hooks.on_block
            def handle_block(event):
                send_security_alert(event)
            ```
        """
        self.register(EventType.BLOCK, handler)
        return handler

    def on_challenge(self, handler: EventHandler) -> EventHandler:
        """Decorator to register a challenge event handler.

        Challenge handlers can return True to approve or False to deny.

        Example:
            ```python
            @hooks.on_challenge
            def handle_challenge(event):
                return get_user_approval(event.text)
            ```
        """
        self.register(EventType.CHALLENGE, handler)
        return handler

    def on_allow(self, handler: EventHandler) -> EventHandler:
        """Decorator to register an allow event handler.

        Example:
            ```python
            @hooks.on_allow
            def handle_allow(event):
                log_access(event.user_id, event.tool_name)
            ```
        """
        self.register(EventType.ALLOW, handler)
        return handler

    def on_error(self, handler: EventHandler) -> EventHandler:
        """Decorator to register an error event handler.

        Example:
            ```python
            @hooks.on_error
            def handle_error(event):
                log_error(event.error)
                alert_ops_team(event)
            ```
        """
        self.register(EventType.ERROR, handler)
        return handler

    def on_before_check(self, handler: EventHandler) -> EventHandler:
        """Decorator to register a before-check event handler.

        Called before each protection check.

        Example:
            ```python
            @hooks.on_before_check
            def handle_before(event):
                start_timer(event.context_id)
            ```
        """
        self.register(EventType.BEFORE_CHECK, handler)
        return handler

    def on_after_check(self, handler: EventHandler) -> EventHandler:
        """Decorator to register an after-check event handler.

        Called after each protection check (success or failure).

        Example:
            ```python
            @hooks.on_after_check
            def handle_after(event):
                record_metrics(event)
            ```
        """
        self.register(EventType.AFTER_CHECK, handler)
        return handler


def create_event_from_result(
    result: Any,
    text: str,
    latency_ms: float,
    context_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    user_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> SecurityEvent:
    """Create a SecurityEvent from a ProtectionResult.

    Args:
        result: ProtectionResult from check
        text: Input text that was checked
        latency_ms: Processing time
        context_id: Optional context ID
        tool_name: Optional tool name
        user_id: Optional user ID
        metadata: Optional additional metadata

    Returns:
        SecurityEvent instance
    """
    # Determine event type from action
    action = getattr(result, "final_action", "allow")
    if action == "block":
        event_type = EventType.BLOCK
    elif action == "challenge":
        event_type = EventType.CHALLENGE
    else:
        event_type = EventType.ALLOW

    return SecurityEvent(
        event_type=event_type,
        text=text,
        action=action,
        threat_level=getattr(result, "threat_level", "none"),
        threats_detected=getattr(result, "threats_detected", []),
        confidence=getattr(result, "confidence", 0.0),
        latency_ms=latency_ms,
        context_id=context_id,
        tool_name=tool_name,
        user_id=user_id,
        metadata=metadata or {},
        result=result,
    )


def create_error_event(
    error: Exception,
    text: str,
    context_id: Optional[str] = None,
    tool_name: Optional[str] = None,
    user_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> SecurityEvent:
    """Create a SecurityEvent for an error.

    Args:
        error: The exception that occurred
        text: Input text that was being checked
        context_id: Optional context ID
        tool_name: Optional tool name
        user_id: Optional user ID
        metadata: Optional additional metadata

    Returns:
        SecurityEvent instance
    """
    return SecurityEvent(
        event_type=EventType.ERROR,
        text=text,
        context_id=context_id,
        tool_name=tool_name,
        user_id=user_id,
        metadata=metadata or {},
        error=error,
    )
