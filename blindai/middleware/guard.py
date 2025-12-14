"""Middleware guard wrapper combining rate limiting, caching, and rollout."""

import logging
from typing import Any, Dict, Optional

from ..models import ProtectionResult
from .cache import CacheConfig, ResultCache
from .rate_limit import RateLimitConfig, RateLimiter, RateLimitExceeded
from .rollout import RolloutConfig, ProgressiveRollout

logger = logging.getLogger(__name__)


class MiddlewareGuard:
    """Guard wrapper with rate limiting, caching, and rollout support.
    
    Wraps any guard with middleware capabilities.
    
    Example:
        ```python
        from blindai import ToolGuard
        from blindai.middleware import (
            MiddlewareGuard,
            RateLimitConfig,
            CacheConfig,
            RolloutConfig,
        )
        
        guard = ToolGuard(base_url="http://localhost:8000")
        
        middleware_guard = MiddlewareGuard(
            guard=guard,
            rate_limit=RateLimitConfig(requests_per_minute=100),
            cache=CacheConfig(ttl_seconds=300),
            rollout=RolloutConfig(percentage=50),
        )
        
        # Use like normal guard
        result = middleware_guard.check("SELECT * FROM users", user_id="user-123")
        ```
    """
    
    def __init__(
        self,
        guard: Any,
        rate_limit: Optional[RateLimitConfig] = None,
        cache: Optional[CacheConfig] = None,
        rollout: Optional[RolloutConfig] = None,
    ):
        """Initialize middleware guard.
        
        Args:
            guard: Underlying guard to wrap
            rate_limit: Rate limiting configuration
            cache: Caching configuration
            rollout: Progressive rollout configuration
        """
        self.guard = guard
        
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit else None
        self.cache = ResultCache(cache) if cache else None
        self.rollout = ProgressiveRollout(rollout) if rollout else None
    
    def check(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
        tool_name: Optional[str] = None,
    ) -> ProtectionResult:
        """Check with middleware applied.
        
        Args:
            text: Text to check
            context_id: Optional context ID
            metadata: Optional metadata
            user: Optional user context
            tool_name: Optional tool name for rate limiting
            
        Returns:
            ProtectionResult
            
        Raises:
            RateLimitExceeded: If rate limit exceeded
            ThreatBlockedError: If threat detected
        """
        user_id = user.user_id if user and hasattr(user, 'user_id') else None
        
        # Check rollout
        if self.rollout and not self.rollout.is_enabled(user_id):
            # Not in rollout - return safe result
            logger.debug(f"Rollout: skipping check for user {user_id}")
            return ProtectionResult(
                is_threat=False,
                threat_level="none",
                final_action="allow",
                threats_detected=[],
                confidence=0.0,
                processing_time_ms=0,
                metadata={"rollout_skipped": True},
            )
        
        # Check rate limit
        if self.rate_limiter:
            if not self.rate_limiter.check(tool_name=tool_name, user_id=user_id):
                status = self.rate_limiter.get_status(tool_name, user_id)
                raise RateLimitExceeded(
                    message="Rate limit exceeded",
                    retry_after_seconds=status.get("global", {}).get("reset_seconds"),
                )
        
        # Check cache
        if self.cache:
            cached = self.cache.get(text, context_id)
            if cached:
                logger.debug("Returning cached result")
                return cached
        
        # Make actual check
        result = self.guard.check(
            text=text,
            context_id=context_id,
            metadata=metadata,
            user=user,
        )
        
        # Cache result
        if self.cache:
            self.cache.set(text, result, context_id)
        
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get middleware statistics.
        
        Returns:
            Dictionary with all middleware stats
        """
        stats = {}
        
        if self.rate_limiter:
            stats["rate_limit"] = self.rate_limiter.get_status()
        
        if self.cache:
            stats["cache"] = self.cache.get_stats()
        
        if self.rollout:
            stats["rollout"] = self.rollout.get_stats()
        
        return stats
    
    # Delegate other attributes to underlying guard
    def __getattr__(self, name: str) -> Any:
        return getattr(self.guard, name)
