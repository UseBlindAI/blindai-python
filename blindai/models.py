"""Data models for Blind AI SDK."""

from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional

# Valid values for type checking and runtime validation
VALID_ACTIONS = ("allow", "log", "warn", "challenge", "block")
VALID_THREAT_LEVELS = ("none", "low", "medium", "high", "critical")


@dataclass
class ProtectionResult:
    """Result from protection check.

    Attributes:
        is_threat: Whether a threat was detected
        threat_level: Threat severity level ("none", "low", "medium", "high", "critical")
        final_action: Recommended action ("allow", "log", "warn", "challenge", "block")
        confidence: Detection confidence (0.0 to 1.0)
        threats_detected: List of specific threats found
        processing_time_ms: Processing time in milliseconds
        metadata: Additional metadata
        request_id: Unique request ID for debugging/support

    Example:
        Basic usage::

            result = guard.check("user input")
            
            if result.is_threat:
                print(f"Threat: {result.threat_level}")
                print(f"Confidence: {result.confidence:.0%}")
            
            # Helper methods
            if result.is_blocked():
                raise SecurityError("Request blocked")
            
            if result.is_allowed():
                process(input)

        Accessing threat details::

            for threat in result.threats_detected:
                print(f"  - {threat['type']}: {threat.get('detail', '')}")
    """

    is_threat: bool
    threat_level: str  # Literal["none", "low", "medium", "high", "critical"]
    final_action: str  # Literal["allow", "log", "warn", "challenge", "block"]
    confidence: float
    threats_detected: List[dict[str, Any]] = field(default_factory=list)
    processing_time_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""

    # --- Helper Methods ---

    def is_allowed(self) -> bool:
        """Check if request was allowed.

        Returns:
            True if final_action is "allow" or "log"

        Example:
            if result.is_allowed():
                execute_query(sql)
        """
        return self.final_action in ("allow", "log")

    def is_blocked(self) -> bool:
        """Check if request was blocked.

        Returns:
            True if final_action is "block"

        Example:
            if result.is_blocked():
                raise SecurityError(f"Blocked: {result.reason}")
        """
        return self.final_action == "block"

    def is_challenged(self) -> bool:
        """Check if request requires human review/challenge.

        Returns:
            True if final_action is "challenge"

        Example:
            if result.is_challenged():
                approved = await get_human_approval(result)
                if not approved:
                    raise SecurityError("Challenge denied")
        """
        return self.final_action == "challenge"

    def is_warned(self) -> bool:
        """Check if request triggered a warning.

        Returns:
            True if final_action is "warn"

        Example:
            if result.is_warned():
                logger.warning(f"Security warning: {result.reason}")
        """
        return self.final_action == "warn"

    @property
    def reason(self) -> str:
        """Human-readable explanation of the result.

        Returns:
            Description of why the action was taken

        Example:
            print(f"Result: {result.reason}")
            # → "Blocked: HIGH threat (PROMPT_INJECTION detected with 95% confidence)"
        """
        if not self.is_threat:
            return "No threats detected"

        threat_types = [t.get("type", "UNKNOWN") for t in self.threats_detected]
        threat_str = ", ".join(threat_types) if threat_types else "unknown threat"

        if self.final_action == "block":
            return f"Blocked: {self.threat_level.upper()} threat ({threat_str} detected with {self.confidence:.0%} confidence)"
        elif self.final_action == "challenge":
            return f"Challenge required: {self.threat_level.upper()} threat ({threat_str})"
        elif self.final_action == "warn":
            return f"Warning: {self.threat_level.upper()} threat ({threat_str})"
        else:
            return f"Allowed with {self.threat_level} risk ({threat_str})"

    @property
    def latency_ms(self) -> float:
        """Alias for processing_time_ms for API compatibility.

        Returns:
            Processing time in milliseconds
        """
        return self.processing_time_ms

    @classmethod
    def from_api_response(cls, response: dict) -> "ProtectionResult":
        """Create ProtectionResult from API response.

        Args:
            response: API response dictionary

        Returns:
            ProtectionResult instance

        Example:
            response = api.post("/v1/protect", json={"text": "..."})
            result = ProtectionResult.from_api_response(response.json())
        """
        return cls(
            is_threat=response.get("is_threat", False),
            threat_level=response.get("threat_level", "none"),
            final_action=response.get("final_action", "allow"),
            confidence=response.get("confidence", 0.0),
            threats_detected=response.get("threats_detected", []),
            processing_time_ms=response.get("processing_time_ms", 0.0),
            metadata=response.get("metadata", {}),
            request_id=response.get("request_id", response.get("trace_id", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization.

        Returns:
            Dictionary representation of the result
        """
        return {
            "is_threat": self.is_threat,
            "threat_level": self.threat_level,
            "final_action": self.final_action,
            "confidence": self.confidence,
            "threats_detected": self.threats_detected,
            "processing_time_ms": self.processing_time_ms,
            "metadata": self.metadata,
            "request_id": self.request_id,
        }


@dataclass
class SDKConfig:
    """Configuration for Blind AI SDK.

    Attributes:
        api_key: API key for authentication
        base_url: Base URL for API
        timeout: Request timeout in seconds
        max_retries: Maximum number of retry attempts
        retry_backoff: Backoff multiplier for retries
        fail_open: Allow on error (True) or block on error (False)
        verify_ssl: Verify SSL certificates
    """

    api_key: Optional[str] = None
    base_url: str = "http://localhost:8000"
    timeout: float = 10.0
    max_retries: int = 3
    retry_backoff: float = 0.5
    fail_open: bool = False
    verify_ssl: bool = True

    def __post_init__(self):
        """Validate configuration."""
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.retry_backoff < 0:
            raise ValueError("retry_backoff must be non-negative")
