"""Rate limiting components for SDK middleware."""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..exceptions import BlindAIError

logger = logging.getLogger(__name__)


class RateLimitExceeded(BlindAIError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after_seconds: Optional[float] = None,
    ):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class TokenBucket:
    """Token bucket rate limiter.
    
    Implements the token bucket algorithm for rate limiting.
    Tokens are added at a constant rate up to a maximum capacity.
    
    Example:
        ```python
        # 100 requests per minute
        bucket = TokenBucket(rate=100, per_seconds=60)
        
        if bucket.consume():
            # Request allowed
            process_request()
        else:
            # Rate limited
            raise RateLimitExceeded()
        ```
    """
    
    def __init__(
        self,
        rate: int,
        per_seconds: float = 60.0,
        burst: Optional[int] = None,
    ):
        """Initialize token bucket.
        
        Args:
            rate: Number of tokens (requests) allowed per time period
            per_seconds: Time period in seconds (default: 60 = per minute)
            burst: Maximum burst capacity (default: same as rate)
        """
        self.rate = rate
        self.per_seconds = per_seconds
        self.capacity = burst or rate
        self.tokens = float(self.capacity)
        self.last_update = time.monotonic()
        self._lock = threading.Lock()
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * (self.rate / self.per_seconds)
        )
        self.last_update = now
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if rate limited
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def wait_time(self, tokens: int = 1) -> float:
        """Get time to wait until tokens are available.
        
        Args:
            tokens: Number of tokens needed
            
        Returns:
            Seconds to wait (0 if tokens available now)
        """
        with self._lock:
            self._refill()
            if self.tokens >= tokens:
                return 0.0
            needed = tokens - self.tokens
            return needed / (self.rate / self.per_seconds)
    
    @property
    def available(self) -> float:
        """Get current available tokens."""
        with self._lock:
            self._refill()
            return self.tokens


class SlidingWindowRateLimiter:
    """Sliding window rate limiter.
    
    More accurate than token bucket for strict rate limiting.
    Tracks actual request timestamps within the window.
    
    Example:
        ```python
        # 100 requests per minute with sliding window
        limiter = SlidingWindowRateLimiter(limit=100, window_seconds=60)
        
        if limiter.allow():
            process_request()
        ```
    """
    
    def __init__(self, limit: int, window_seconds: float = 60.0):
        """Initialize sliding window limiter.
        
        Args:
            limit: Maximum requests per window
            window_seconds: Window size in seconds
        """
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: List[float] = []
        self._lock = threading.Lock()
    
    def _cleanup(self) -> None:
        """Remove expired timestamps."""
        cutoff = time.monotonic() - self.window_seconds
        self.requests = [t for t in self.requests if t > cutoff]
    
    def allow(self) -> bool:
        """Check if request is allowed.
        
        Returns:
            True if allowed, False if rate limited
        """
        with self._lock:
            self._cleanup()
            if len(self.requests) < self.limit:
                self.requests.append(time.monotonic())
                return True
            return False
    
    def remaining(self) -> int:
        """Get remaining requests in current window."""
        with self._lock:
            self._cleanup()
            return max(0, self.limit - len(self.requests))
    
    def reset_time(self) -> float:
        """Get seconds until oldest request expires."""
        with self._lock:
            self._cleanup()
            if not self.requests:
                return 0.0
            oldest = min(self.requests)
            return max(0.0, (oldest + self.window_seconds) - time.monotonic())


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting.
    
    Attributes:
        requests_per_minute: Maximum requests per minute
        burst_size: Maximum burst capacity (default: 2x rate)
        per_tool_limits: Optional per-tool rate limits
        per_user_limits: Optional per-user rate limits
        algorithm: Rate limiting algorithm ("token_bucket" or "sliding_window")
    """
    requests_per_minute: int = 100
    burst_size: Optional[int] = None
    per_tool_limits: Optional[Dict[str, int]] = None
    per_user_limits: Optional[Dict[str, int]] = None
    algorithm: str = "token_bucket"


class RateLimiter:
    """Composite rate limiter with per-tool and per-user limits.
    
    Example:
        ```python
        config = RateLimitConfig(
            requests_per_minute=100,
            per_tool_limits={"dangerous_tool": 10},
            per_user_limits={"free_tier": 20},
        )
        limiter = RateLimiter(config)
        
        # Check rate limit
        if not limiter.check(tool_name="my_tool", user_id="user-123"):
            raise RateLimitExceeded()
        ```
    """
    
    def __init__(self, config: RateLimitConfig):
        """Initialize rate limiter.
        
        Args:
            config: Rate limit configuration
        """
        self.config = config
        
        # Global limiter
        if config.algorithm == "sliding_window":
            self._global = SlidingWindowRateLimiter(
                limit=config.requests_per_minute,
                window_seconds=60.0,
            )
        else:
            self._global = TokenBucket(
                rate=config.requests_per_minute,
                per_seconds=60.0,
                burst=config.burst_size,
            )
        
        # Per-tool limiters
        self._tool_limiters: Dict[str, Any] = {}
        
        # Per-user limiters
        self._user_limiters: Dict[str, Any] = {}
        
        self._lock = threading.Lock()
    
    def _get_tool_limiter(self, tool_name: str) -> Optional[Any]:
        """Get or create per-tool limiter."""
        if not self.config.per_tool_limits:
            return None
        
        limit = self.config.per_tool_limits.get(tool_name)
        if limit is None:
            return None
        
        with self._lock:
            if tool_name not in self._tool_limiters:
                if self.config.algorithm == "sliding_window":
                    self._tool_limiters[tool_name] = SlidingWindowRateLimiter(limit, 60.0)
                else:
                    self._tool_limiters[tool_name] = TokenBucket(limit, 60.0)
            return self._tool_limiters[tool_name]
    
    def _get_user_limiter(self, user_id: str) -> Optional[Any]:
        """Get or create per-user limiter."""
        if not self.config.per_user_limits:
            return None
        
        # Check for user-specific limit or default
        limit = self.config.per_user_limits.get(user_id)
        if limit is None:
            limit = self.config.per_user_limits.get("default")
        if limit is None:
            return None
        
        with self._lock:
            if user_id not in self._user_limiters:
                if self.config.algorithm == "sliding_window":
                    self._user_limiters[user_id] = SlidingWindowRateLimiter(limit, 60.0)
                else:
                    self._user_limiters[user_id] = TokenBucket(limit, 60.0)
            return self._user_limiters[user_id]
    
    def check(
        self,
        tool_name: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> bool:
        """Check if request is allowed by all applicable rate limits.
        
        Args:
            tool_name: Optional tool name for per-tool limits
            user_id: Optional user ID for per-user limits
            
        Returns:
            True if allowed, False if any limit exceeded
        """
        # Check global limit
        if isinstance(self._global, TokenBucket):
            if not self._global.consume():
                return False
        else:
            if not self._global.allow():
                return False
        
        # Check per-tool limit
        if tool_name:
            tool_limiter = self._get_tool_limiter(tool_name)
            if tool_limiter:
                if isinstance(tool_limiter, TokenBucket):
                    if not tool_limiter.consume():
                        return False
                else:
                    if not tool_limiter.allow():
                        return False
        
        # Check per-user limit
        if user_id:
            user_limiter = self._get_user_limiter(user_id)
            if user_limiter:
                if isinstance(user_limiter, TokenBucket):
                    if not user_limiter.consume():
                        return False
                else:
                    if not user_limiter.allow():
                        return False
        
        return True
    
    def get_status(
        self,
        tool_name: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get current rate limit status.
        
        Returns:
            Dictionary with remaining requests and reset times
        """
        status = {"global": {}}
        
        if isinstance(self._global, TokenBucket):
            status["global"]["remaining"] = int(self._global.available)
            status["global"]["reset_seconds"] = self._global.wait_time()
        else:
            status["global"]["remaining"] = self._global.remaining()
            status["global"]["reset_seconds"] = self._global.reset_time()
        
        if tool_name:
            tool_limiter = self._get_tool_limiter(tool_name)
            if tool_limiter:
                if isinstance(tool_limiter, TokenBucket):
                    status["tool"] = {
                        "remaining": int(tool_limiter.available),
                        "reset_seconds": tool_limiter.wait_time(),
                    }
                else:
                    status["tool"] = {
                        "remaining": tool_limiter.remaining(),
                        "reset_seconds": tool_limiter.reset_time(),
                    }
        
        return status
