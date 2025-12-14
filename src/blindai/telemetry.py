"""SDK Telemetry Integration.

Provides automatic telemetry integration for SDK clients:
- Automatic metrics collection
- Event emission
- Distributed tracing support
"""

import logging
import time
import functools
from typing import Optional, Dict, Any, Callable, TypeVar
from dataclasses import dataclass, field

from ..core.observability.metrics import get_metrics_collector, MetricsCollector
from ..core.observability.events import (
    get_event_exporter,
    EventExporter,
    SecurityEvent,
    EventType,
    EventSeverity,
)

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class TelemetryConfig:
    """Telemetry configuration.
    
    Attributes:
        enabled: Enable telemetry
        service_name: Service name for identification
        collect_metrics: Collect metrics
        emit_events: Emit events
        trace_requests: Enable distributed tracing
        sample_rate: Event sampling rate (0.0 to 1.0)
        extra_labels: Additional labels for metrics
    """
    enabled: bool = True
    service_name: str = "blindai-sdk"
    collect_metrics: bool = True
    emit_events: bool = True
    trace_requests: bool = False
    sample_rate: float = 1.0
    extra_labels: Dict[str, str] = field(default_factory=dict)


class SDKTelemetry:
    """Telemetry integration for SDK.
    
    Automatically collects metrics and emits events
    for SDK operations.
    
    Example:
        ```python
        from blindai.telemetry import SDKTelemetry, TelemetryConfig
        
        # Configure telemetry
        telemetry = SDKTelemetry(TelemetryConfig(
            service_name="my-service",
            extra_labels={"env": "production"},
        ))
        
        # Record a check
        telemetry.record_check(
            duration_ms=45.2,
            agent_id="agent-1",
            threat_detected=True,
            threat_level="high",
        )
        
        # Wrap a function with telemetry
        @telemetry.instrument("sql_check")
        def check_sql(query):
            return guard.check(query)
        ```
    """
    
    def __init__(
        self,
        config: Optional[TelemetryConfig] = None,
        metrics: Optional[MetricsCollector] = None,
        events: Optional[EventExporter] = None,
    ):
        """Initialize SDK telemetry.
        
        Args:
            config: Telemetry configuration
            metrics: Metrics collector instance
            events: Event exporter instance
        """
        self.config = config or TelemetryConfig()
        self._metrics = metrics
        self._events = events
        
        # Track request context
        self._active_spans: Dict[str, Dict[str, Any]] = {}
    
    @property
    def metrics(self) -> MetricsCollector:
        """Get metrics collector (lazy initialization)."""
        if self._metrics is None:
            self._metrics = get_metrics_collector()
        return self._metrics
    
    @property
    def events(self) -> EventExporter:
        """Get event exporter (lazy initialization)."""
        if self._events is None:
            self._events = get_event_exporter()
        return self._events
    
    def record_check(
        self,
        duration_ms: float,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        threat_detected: bool = False,
        threat_level: Optional[str] = None,
        cached: bool = False,
        fast_mode: bool = False,
        error: Optional[str] = None,
        **extra_data,
    ) -> None:
        """Record a security check.
        
        Args:
            duration_ms: Check duration in milliseconds
            agent_id: Agent identifier
            session_id: Session identifier
            threat_detected: Whether threat was detected
            threat_level: Threat level if detected
            cached: Whether result was cached
            fast_mode: Whether fast mode was used
            error: Error message if any
            **extra_data: Additional data to include
        """
        if not self.config.enabled:
            return
        
        labels = {
            **self.config.extra_labels,
            "service": self.config.service_name,
        }
        if agent_id:
            labels["agent_id"] = agent_id
        
        # Record metrics
        if self.config.collect_metrics:
            # Request count
            status = "error" if error else ("blocked" if threat_detected else "success")
            self.metrics.increment(
                "blindai_requests_total",
                labels={**labels, "status": status},
            )
            
            # Duration
            self.metrics.observe(
                "blindai_request_duration_seconds",
                duration_ms / 1000,
                labels=labels,
            )
            
            # Threat detection
            if threat_detected:
                self.metrics.increment(
                    "blindai_threats_detected_total",
                    labels={**labels, "threat_level": threat_level or "unknown"},
                )
            
            # Cache metrics
            if cached:
                self.metrics.increment("blindai_cache_hits_total", labels=labels)
            else:
                self.metrics.increment("blindai_cache_misses_total", labels=labels)
            
            # Error tracking
            if error:
                self.metrics.increment(
                    "blindai_errors_total",
                    labels={**labels, "error_type": "check_error"},
                )
        
        # Emit event
        if self.config.emit_events:
            import random
            if random.random() <= self.config.sample_rate:
                event_type = EventType.THREAT_DETECTED if threat_detected else EventType.REQUEST
                severity = EventSeverity.WARNING if threat_detected else EventSeverity.INFO
                
                if error:
                    event_type = EventType.ERROR
                    severity = EventSeverity.ERROR
                
                event = SecurityEvent(
                    event_type=event_type,
                    severity=severity,
                    agent_id=agent_id,
                    session_id=session_id,
                    data={
                        "duration_ms": duration_ms,
                        "threat_detected": threat_detected,
                        "threat_level": threat_level,
                        "cached": cached,
                        "fast_mode": fast_mode,
                        "error": error,
                        "service": self.config.service_name,
                        **extra_data,
                    },
                )
                
                self.events.emit(event)
    
    def record_session_event(
        self,
        event_type: str,
        session_id: str,
        agent_id: Optional[str] = None,
        **data,
    ) -> None:
        """Record a session event.
        
        Args:
            event_type: Type of session event
            session_id: Session identifier
            agent_id: Agent identifier
            **data: Additional event data
        """
        if not self.config.enabled or not self.config.emit_events:
            return
        
        # Map event type
        type_map = {
            "created": EventType.SESSION_CREATED,
            "expired": EventType.SESSION_EXPIRED,
            "anomaly": EventType.ANOMALY_DETECTED,
        }
        
        event = SecurityEvent(
            event_type=type_map.get(event_type, EventType.REQUEST),
            severity=EventSeverity.INFO if event_type == "created" else EventSeverity.WARNING,
            agent_id=agent_id,
            session_id=session_id,
            data={"session_event": event_type, **data},
        )
        
        self.events.emit(event)
        
        # Update metrics
        if self.config.collect_metrics:
            if event_type == "created":
                self.metrics.set_gauge("blindai_active_sessions", 1, increment=True)
            elif event_type == "expired":
                self.metrics.set_gauge("blindai_active_sessions", -1, increment=True)
    
    def record_agent_event(
        self,
        event_type: str,
        agent_id: str,
        target_agent_id: Optional[str] = None,
        **data,
    ) -> None:
        """Record a multi-agent event.
        
        Args:
            event_type: Type of agent event
            agent_id: Source agent identifier
            target_agent_id: Target agent identifier
            **data: Additional event data
        """
        if not self.config.enabled:
            return
        
        # Map event type
        type_map = {
            "registered": EventType.AGENT_REGISTERED,
            "communication": EventType.AGENT_COMMUNICATION,
            "attack_detected": EventType.ATTACK_DETECTED,
        }
        
        severity = EventSeverity.WARNING if event_type == "attack_detected" else EventSeverity.INFO
        
        event = SecurityEvent(
            event_type=type_map.get(event_type, EventType.REQUEST),
            severity=severity,
            agent_id=agent_id,
            data={
                "agent_event": event_type,
                "target_agent_id": target_agent_id,
                **data,
            },
        )
        
        if self.config.emit_events:
            self.events.emit(event)
        
        # Update metrics
        if self.config.collect_metrics:
            if event_type == "registered":
                self.metrics.set_gauge("blindai_active_agents", 1, increment=True)
            elif event_type == "attack_detected":
                self.metrics.increment(
                    "blindai_attacks_detected_total",
                    labels={"attack_type": data.get("attack_type", "unknown")},
                )
    
    def start_span(
        self,
        name: str,
        agent_id: Optional[str] = None,
        session_id: Optional[str] = None,
        **attributes,
    ) -> str:
        """Start a tracing span.
        
        Args:
            name: Span name
            agent_id: Agent identifier
            session_id: Session identifier
            **attributes: Span attributes
            
        Returns:
            Span ID
        """
        import uuid
        span_id = str(uuid.uuid4())[:8]
        
        self._active_spans[span_id] = {
            "name": name,
            "start_time": time.time(),
            "agent_id": agent_id,
            "session_id": session_id,
            "attributes": attributes,
        }
        
        return span_id
    
    def end_span(
        self,
        span_id: str,
        error: Optional[str] = None,
        **attributes,
    ) -> None:
        """End a tracing span.
        
        Args:
            span_id: Span ID from start_span
            error: Error message if any
            **attributes: Additional attributes
        """
        if span_id not in self._active_spans:
            return
        
        span = self._active_spans.pop(span_id)
        duration_ms = (time.time() - span["start_time"]) * 1000
        
        # Record as check
        self.record_check(
            duration_ms=duration_ms,
            agent_id=span.get("agent_id"),
            session_id=span.get("session_id"),
            error=error,
            span_name=span["name"],
            **span["attributes"],
            **attributes,
        )
    
    def instrument(
        self,
        name: Optional[str] = None,
        record_args: bool = False,
    ) -> Callable[[F], F]:
        """Decorator to instrument a function.
        
        Args:
            name: Span name (defaults to function name)
            record_args: Whether to record function arguments
            
        Returns:
            Decorated function
        """
        def decorator(func: F) -> F:
            span_name = name or func.__name__
            
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                attributes = {}
                if record_args:
                    attributes["args"] = str(args)[:100]
                    attributes["kwargs"] = str(kwargs)[:100]
                
                span_id = self.start_span(span_name, **attributes)
                
                try:
                    result = func(*args, **kwargs)
                    self.end_span(span_id)
                    return result
                except Exception as e:
                    self.end_span(span_id, error=str(e))
                    raise
            
            return wrapper  # type: ignore
        
        return decorator
    
    def instrument_async(
        self,
        name: Optional[str] = None,
        record_args: bool = False,
    ) -> Callable[[F], F]:
        """Decorator to instrument an async function.
        
        Args:
            name: Span name (defaults to function name)
            record_args: Whether to record function arguments
            
        Returns:
            Decorated function
        """
        def decorator(func: F) -> F:
            span_name = name or func.__name__
            
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                attributes = {}
                if record_args:
                    attributes["args"] = str(args)[:100]
                    attributes["kwargs"] = str(kwargs)[:100]
                
                span_id = self.start_span(span_name, **attributes)
                
                try:
                    result = await func(*args, **kwargs)
                    self.end_span(span_id)
                    return result
                except Exception as e:
                    self.end_span(span_id, error=str(e))
                    raise
            
            return wrapper  # type: ignore
        
        return decorator


# Global telemetry instance
_global_telemetry: Optional[SDKTelemetry] = None


def get_telemetry(config: Optional[TelemetryConfig] = None) -> SDKTelemetry:
    """Get the global SDK telemetry instance.
    
    Args:
        config: Optional configuration for first initialization
        
    Returns:
        SDKTelemetry instance
    """
    global _global_telemetry
    if _global_telemetry is None:
        _global_telemetry = SDKTelemetry(config)
    return _global_telemetry


def reset_telemetry() -> None:
    """Reset the global telemetry instance."""
    global _global_telemetry
    _global_telemetry = None


class TelemetryMixin:
    """Mixin to add telemetry to SDK clients.
    
    Add this mixin to any SDK client class to enable
    automatic telemetry collection.
    
    Example:
        ```python
        class MyGuard(TelemetryMixin, BaseGuard):
            def check(self, content):
                with self._telemetry_span("check"):
                    return super().check(content)
        ```
    """
    
    _telemetry: Optional[SDKTelemetry] = None
    _telemetry_config: Optional[TelemetryConfig] = None
    
    def enable_telemetry(
        self,
        config: Optional[TelemetryConfig] = None,
    ) -> None:
        """Enable telemetry for this client.
        
        Args:
            config: Telemetry configuration
        """
        self._telemetry_config = config or TelemetryConfig()
        self._telemetry = SDKTelemetry(self._telemetry_config)
    
    def disable_telemetry(self) -> None:
        """Disable telemetry for this client."""
        self._telemetry = None
        self._telemetry_config = None
    
    @property
    def telemetry(self) -> Optional[SDKTelemetry]:
        """Get telemetry instance."""
        return self._telemetry
    
    def _record_check(
        self,
        duration_ms: float,
        **kwargs,
    ) -> None:
        """Record a check operation."""
        if self._telemetry:
            self._telemetry.record_check(duration_ms=duration_ms, **kwargs)
    
    def _telemetry_span(self, name: str, **attributes):
        """Context manager for telemetry span."""
        class TelemetrySpan:
            def __init__(span_self, telemetry: Optional[SDKTelemetry], name: str, **attrs):
                span_self.telemetry = telemetry
                span_self.name = name
                span_self.attributes = attrs
                span_self.span_id: Optional[str] = None
            
            def __enter__(span_self):
                if span_self.telemetry:
                    span_self.span_id = span_self.telemetry.start_span(
                        span_self.name, **span_self.attributes
                    )
                return span_self
            
            def __exit__(span_self, exc_type, exc_val, exc_tb):
                if span_self.telemetry and span_self.span_id:
                    error = str(exc_val) if exc_val else None
                    span_self.telemetry.end_span(span_self.span_id, error=error)
                return False
        
        return TelemetrySpan(self._telemetry, name, **attributes)
