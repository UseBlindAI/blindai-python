"""Replay guard for deterministic testing from recorded checks."""

import json
from typing import Any, Dict, List, Optional

from ..exceptions import ThreatBlockedError
from ..models import ProtectionResult
from .models import RecordedCheck


class ReplayGuard:
    """Guard that replays recorded checks for deterministic testing.
    
    Uses previously recorded checks to provide deterministic responses.
    
    Example:
        ```python
        from blindai.testing import ReplayGuard
        
        # Load recordings and replay
        guard = ReplayGuard.from_file("test_cases.json")
        
        # Checks return recorded results
        result = guard.check("SELECT * FROM users")
        ```
    """
    
    def __init__(self, recordings: List[RecordedCheck]):
        """Initialize replay guard.
        
        Args:
            recordings: List of recorded checks to replay
        """
        self.recordings = recordings
        self._index = 0
        self._by_text: Dict[str, RecordedCheck] = {
            r.text: r for r in recordings
        }
    
    @classmethod
    def from_file(cls, filepath: str) -> "ReplayGuard":
        """Create replay guard from recording file.
        
        Args:
            filepath: Path to recordings JSON file
            
        Returns:
            ReplayGuard instance
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        recordings = [
            RecordedCheck.from_dict(r)
            for r in data.get("recordings", [])
        ]
        
        return cls(recordings)
    
    def check(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
    ) -> ProtectionResult:
        """Replay recorded check result.
        
        First tries to match by exact text, then falls back to sequential replay.
        
        Args:
            text: Text to check
            context_id: Ignored
            metadata: Ignored
            user: Ignored
            
        Returns:
            Recorded ProtectionResult
        """
        # Try exact text match first
        if text in self._by_text:
            recording = self._by_text[text]
        elif self._index < len(self.recordings):
            # Fall back to sequential
            recording = self.recordings[self._index]
            self._index += 1
        else:
            # No more recordings, return safe default
            return ProtectionResult(
                is_threat=False,
                threat_level="none",
                final_action="allow",
                threats_detected=[],
                confidence=0.0,
                processing_time_ms=0,
                metadata={"replay": True, "no_recording": True},
            )
        
        result = ProtectionResult(
            is_threat=recording.result.get("is_threat", False),
            threat_level=recording.result.get("threat_level", "none"),
            final_action=recording.result.get("final_action", "allow"),
            threats_detected=recording.result.get("threats_detected", []),
            confidence=recording.result.get("confidence", 0.0),
            processing_time_ms=recording.latency_ms,
            metadata={"replay": True},
        )
        
        # Raise if blocked
        if result.final_action == "block":
            raise ThreatBlockedError(
                message=f"Replay blocked: {result.threat_level}",
                threat_level=result.threat_level,
                threats=result.threats_detected,
                response={"replay": True},
            )
        
        return result
    
    def reset(self) -> None:
        """Reset replay index to beginning."""
        self._index = 0
