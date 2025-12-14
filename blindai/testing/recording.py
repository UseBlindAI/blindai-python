"""Recording guard for capturing checks for later analysis."""

import json
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..exceptions import ThreatBlockedError
from ..models import ProtectionResult
from .models import RecordedCheck

logger = logging.getLogger(__name__)


class RecordingGuard:
    """Guard wrapper that records all checks for later analysis.
    
    Wraps a real guard and records all inputs and outputs.
    
    Example:
        ```python
        from blindai import ToolGuard
        from blindai.testing import RecordingGuard
        
        # Wrap real guard with recording
        real_guard = ToolGuard(base_url="http://localhost:8000")
        guard = RecordingGuard(real_guard)
        
        # Use normally
        guard.check("SELECT * FROM users")
        guard.check("DROP TABLE users")
        
        # Export recordings
        guard.export_recordings("test_cases.json")
        
        # Or get recordings directly
        for recording in guard.recordings:
            print(f"{recording.text} -> {recording.result['final_action']}")
        ```
    """
    
    def __init__(self, guard: Any):
        """Initialize recording guard.
        
        Args:
            guard: The underlying guard to wrap (ToolGuard or AsyncToolGuard)
        """
        self.guard = guard
        self.recordings: List[RecordedCheck] = []
    
    def check(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
    ) -> ProtectionResult:
        """Check with recording.
        
        Args:
            text: Text to check
            context_id: Optional context ID
            metadata: Optional metadata
            user: Optional user context
            
        Returns:
            ProtectionResult from underlying guard
        """
        start_time = time.perf_counter()
        result = None
        error = None
        
        try:
            result = self.guard.check(
                text=text,
                context_id=context_id,
                metadata=metadata,
                user=user,
            )
            return result
        except ThreatBlockedError as e:
            error = e
            # Create result from error for recording
            result = ProtectionResult(
                is_threat=True,
                threat_level=e.threat_level,
                final_action="block",
                threats_detected=e.threats,
                confidence=0.95,
                processing_time_ms=0,
                metadata={"blocked": True},
            )
            raise
        finally:
            latency_ms = (time.perf_counter() - start_time) * 1000
            
            # Record the check
            if result:
                self.recordings.append(RecordedCheck(
                    timestamp=datetime.utcnow().isoformat(),
                    text=text,
                    context_id=context_id,
                    metadata=metadata,
                    user_id=user.user_id if user and hasattr(user, 'user_id') else None,
                    result={
                        "is_threat": result.is_threat,
                        "threat_level": result.threat_level,
                        "final_action": result.final_action,
                        "threats_detected": result.threats_detected,
                        "confidence": result.confidence,
                    },
                    latency_ms=latency_ms,
                ))
    
    def check_batch(
        self,
        items: List[Dict[str, Any]],
        fail_fast: bool = False,
        parallel: bool = True,
    ) -> List[ProtectionResult]:
        """Batch check with recording.
        
        Args:
            items: List of check items
            fail_fast: Stop on first threat
            parallel: Use parallel execution
            
        Returns:
            List of ProtectionResults
        """
        # Record each item individually for detailed tracking
        results = []
        for item in items:
            try:
                result = self.check(
                    text=item["text"],
                    context_id=item.get("context_id"),
                    metadata=item.get("metadata"),
                    user=item.get("user"),
                )
                results.append(result)
            except ThreatBlockedError as e:
                if fail_fast:
                    raise
                results.append(ProtectionResult(
                    is_threat=True,
                    threat_level=e.threat_level,
                    final_action="block",
                    threats_detected=e.threats,
                    confidence=0.95,
                    processing_time_ms=0,
                    metadata={"blocked": True},
                ))
        return results
    
    def export_recordings(self, filepath: str) -> None:
        """Export recordings to JSON file.
        
        Args:
            filepath: Path to output file
        """
        data = {
            "exported_at": datetime.utcnow().isoformat(),
            "total_checks": len(self.recordings),
            "recordings": [r.to_dict() for r in self.recordings],
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported {len(self.recordings)} recordings to {filepath}")
    
    def import_recordings(self, filepath: str) -> None:
        """Import recordings from JSON file.
        
        Args:
            filepath: Path to input file
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        self.recordings = [
            RecordedCheck.from_dict(r)
            for r in data.get("recordings", [])
        ]
        
        logger.info(f"Imported {len(self.recordings)} recordings from {filepath}")
    
    def clear_recordings(self) -> None:
        """Clear all recordings."""
        self.recordings.clear()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of recordings.
        
        Returns:
            Dictionary with recording statistics
        """
        if not self.recordings:
            return {"total": 0}
        
        threats = [r for r in self.recordings if r.result.get("is_threat")]
        blocked = [r for r in self.recordings if r.result.get("final_action") == "block"]
        
        latencies = [r.latency_ms for r in self.recordings]
        
        return {
            "total": len(self.recordings),
            "threats_detected": len(threats),
            "blocked": len(blocked),
            "allowed": len(self.recordings) - len(blocked),
            "latency_avg_ms": sum(latencies) / len(latencies),
            "latency_max_ms": max(latencies),
            "latency_min_ms": min(latencies),
            "threat_levels": {
                level: sum(1 for r in self.recordings if r.result.get("threat_level") == level)
                for level in ["none", "low", "medium", "high", "critical"]
            },
        }
    
    # Delegate other attributes to underlying guard
    def __getattr__(self, name: str) -> Any:
        return getattr(self.guard, name)
