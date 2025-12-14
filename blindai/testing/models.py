"""Data models for testing utilities."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MockConfig:
    """Configuration for mock mode behavior.
    
    Attributes:
        is_threat: Whether to report as threat
        threat_level: Threat level to return ("none", "low", "medium", "high", "critical")
        final_action: Action to take ("allow", "block", "challenge")
        threats_detected: List of threat types to report
        confidence: Confidence score (0.0 to 1.0)
        latency_ms: Simulated latency in milliseconds
        raise_error: If set, raise this exception instead of returning result
    """
    is_threat: bool = False
    threat_level: str = "none"
    final_action: str = "allow"
    threats_detected: List[str] = field(default_factory=list)
    confidence: float = 0.0
    latency_ms: float = 1.0
    raise_error: Optional[Exception] = None
    
    @classmethod
    def allow(cls) -> "MockConfig":
        """Create config that allows all requests."""
        return cls(is_threat=False, threat_level="none", final_action="allow")
    
    @classmethod
    def block(cls, threat_level: str = "high", threats: Optional[List[str]] = None) -> "MockConfig":
        """Create config that blocks all requests."""
        return cls(
            is_threat=True,
            threat_level=threat_level,
            final_action="block",
            threats_detected=threats or ["mock_threat"],
            confidence=0.95,
        )
    
    @classmethod
    def challenge(cls, threat_level: str = "medium") -> "MockConfig":
        """Create config that challenges all requests."""
        return cls(
            is_threat=True,
            threat_level=threat_level,
            final_action="challenge",
            threats_detected=["requires_review"],
            confidence=0.7,
        )


@dataclass
class RecordedCheck:
    """A recorded security check for replay/analysis.
    
    Attributes:
        timestamp: When the check occurred
        text: Input text that was checked
        context_id: Context ID if provided
        metadata: Metadata if provided
        user_id: User ID if provided
        result: The protection result
        latency_ms: How long the check took
    """
    timestamp: str
    text: str
    context_id: Optional[str]
    metadata: Optional[Dict[str, Any]]
    user_id: Optional[str]
    result: Dict[str, Any]
    latency_ms: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "text": self.text,
            "context_id": self.context_id,
            "metadata": self.metadata,
            "user_id": self.user_id,
            "result": self.result,
            "latency_ms": self.latency_ms,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RecordedCheck":
        """Create from dictionary."""
        return cls(
            timestamp=data["timestamp"],
            text=data["text"],
            context_id=data.get("context_id"),
            metadata=data.get("metadata"),
            user_id=data.get("user_id"),
            result=data["result"],
            latency_ms=data.get("latency_ms", 0.0),
        )
