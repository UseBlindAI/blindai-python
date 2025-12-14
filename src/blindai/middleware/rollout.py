"""Progressive rollout components for SDK middleware."""

import hashlib
import logging
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class RolloutConfig:
    """Configuration for progressive rollout.
    
    Attributes:
        percentage: Percentage of traffic to protect (0-100)
        user_hash_func: Function to hash user ID for consistent bucketing
        sticky: If True, same user always gets same treatment
        ramp_schedule: Optional schedule for automatic ramp-up
        fallback_action: Action when not in rollout ("allow" or "log_only")
    """
    percentage: float = 100.0
    user_hash_func: Optional[Callable[[str], int]] = None
    sticky: bool = True
    ramp_schedule: Optional[List[Tuple[float, float]]] = None  # [(hours, percentage), ...]
    fallback_action: str = "allow"


class ProgressiveRollout:
    """Progressive rollout controller for gradual feature enablement.
    
    Allows gradually rolling out protection to a percentage of traffic.
    
    Example:
        ```python
        # Start with 10% of traffic
        rollout = ProgressiveRollout(RolloutConfig(percentage=10))
        
        # Check if user should be protected
        if rollout.is_enabled(user_id="user-123"):
            result = guard.check(text)
        else:
            # Skip protection for this user
            pass
        
        # Increase rollout
        rollout.set_percentage(50)
        ```
    """
    
    def __init__(self, config: RolloutConfig):
        """Initialize rollout controller.
        
        Args:
            config: Rollout configuration
        """
        self.config = config
        self._percentage = config.percentage
        self._start_time = time.monotonic()
        self._lock = threading.Lock()
        
        # Stats
        self._total_checks = 0
        self._enabled_checks = 0
    
    def _hash_user(self, user_id: str) -> int:
        """Hash user ID to bucket (0-99)."""
        if self.config.user_hash_func:
            return self.config.user_hash_func(user_id) % 100
        
        # Default: SHA256 hash
        hash_bytes = hashlib.sha256(user_id.encode()).digest()
        return int.from_bytes(hash_bytes[:4], 'big') % 100
    
    def _get_current_percentage(self) -> float:
        """Get current percentage, accounting for ramp schedule."""
        if not self.config.ramp_schedule:
            return self._percentage
        
        elapsed_hours = (time.monotonic() - self._start_time) / 3600
        
        current_percentage = self._percentage
        for hours, percentage in sorted(self.config.ramp_schedule):
            if elapsed_hours >= hours:
                current_percentage = percentage
        
        return current_percentage
    
    def is_enabled(self, user_id: Optional[str] = None) -> bool:
        """Check if protection is enabled for this request.
        
        Args:
            user_id: Optional user ID for sticky bucketing
            
        Returns:
            True if protection should be applied
        """
        with self._lock:
            self._total_checks += 1
            
            percentage = self._get_current_percentage()
            
            if percentage >= 100:
                self._enabled_checks += 1
                return True
            
            if percentage <= 0:
                return False
            
            if user_id and self.config.sticky:
                # Sticky: same user always gets same treatment
                bucket = self._hash_user(user_id)
                enabled = bucket < percentage
            else:
                # Random: each request independently sampled
                enabled = random.random() * 100 < percentage
            
            if enabled:
                self._enabled_checks += 1
            
            return enabled
    
    def set_percentage(self, percentage: float) -> None:
        """Update rollout percentage.
        
        Args:
            percentage: New percentage (0-100)
        """
        if not 0 <= percentage <= 100:
            raise ValueError("Percentage must be between 0 and 100")
        
        with self._lock:
            old = self._percentage
            self._percentage = percentage
            logger.info(f"Rollout percentage changed: {old}% -> {percentage}%")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rollout statistics.
        
        Returns:
            Dictionary with rollout stats
        """
        with self._lock:
            return {
                "current_percentage": self._get_current_percentage(),
                "configured_percentage": self._percentage,
                "total_checks": self._total_checks,
                "enabled_checks": self._enabled_checks,
                "actual_percentage": (
                    (self._enabled_checks / self._total_checks * 100)
                    if self._total_checks > 0 else 0
                ),
            }
