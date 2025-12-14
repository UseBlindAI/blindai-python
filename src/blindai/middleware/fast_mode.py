"""Fast Mode SDK middleware.

Provides SDK integration for fast mode detection with local caching
and tiered detection.
"""

import hashlib
import time
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, Union

from ..exceptions import ThreatBlockedError
from ..models import ProtectionResult

F = TypeVar("F", bound=Callable[..., Any])


@dataclass
class FastModeConfig:
    """Configuration for fast mode middleware.
    
    Attributes:
        enable_local_cache: Enable local result caching
        cache_size: Maximum cache entries
        cache_ttl_seconds: Cache TTL in seconds
        enable_whitelist: Enable local whitelist
        whitelist_patterns: List of regex patterns to whitelist
        enable_quick_block: Enable quick blocklist
        block_patterns: List of patterns to quick block
        fallback_to_api: Fall back to API if local detection fails
        api_timeout_ms: API timeout in milliseconds
    """
    enable_local_cache: bool = True
    cache_size: int = 1000
    cache_ttl_seconds: float = 300.0
    enable_whitelist: bool = True
    whitelist_patterns: list[str] = field(default_factory=list)
    enable_quick_block: bool = True
    block_patterns: list[str] = field(default_factory=list)
    fallback_to_api: bool = True
    api_timeout_ms: float = 50.0


@dataclass
class LocalCacheEntry:
    """Local cache entry."""
    result: "FastModeLocalResult"
    created_at: float
    ttl: float
    
    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl


@dataclass
class FastModeLocalResult:
    """Result from local fast mode detection."""
    is_safe: bool
    is_threat: bool
    confidence: float
    tier: str
    latency_ms: float
    pattern_name: Optional[str] = None
    description: str = ""
    
    def to_protection_result(self) -> ProtectionResult:
        """Convert to ProtectionResult."""
        return ProtectionResult(
            is_threat=self.is_threat,
            threat_level="high" if self.is_threat else "none",
            final_action="block" if self.is_threat else "allow",
            confidence=self.confidence,
            threats_detected=[{
                "pattern": self.pattern_name,
                "description": self.description,
            }] if self.is_threat else [],
            processing_time_ms=self.latency_ms,
            metadata={"fast_mode_tier": self.tier},
        )


class FastModeMiddleware:
    """Fast mode middleware for SDK clients.
    
    Provides local tiered detection before falling back to API.
    
    Example:
        ```python
        from blindai import ToolGuard
        from blindai.middleware.fast_mode import FastModeMiddleware, FastModeConfig
        
        guard = ToolGuard(api_key="your-key")
        fast_mode = FastModeMiddleware(
            config=FastModeConfig(
                whitelist_patterns=[r"SELECT .* FROM users WHERE id = \d+"],
            )
        )
        
        # Use with guard
        @guard.protect()
        @fast_mode.check
        def query_database(sql: str):
            return db.execute(sql)
        ```
    """
    
    # Default quick block patterns (high-confidence threats)
    DEFAULT_BLOCK_PATTERNS = [
        r";\s*drop\s+table",
        r";\s*delete\s+from",
        r"union\s+select",
        r"'\s*or\s+'1'\s*=\s*'1",
        r"ignore\s+previous\s+instructions",
        r"disregard\s+your\s+instructions",
        r"forget\s+your\s+instructions",
        r"jailbreak",
        r"<\|im_start\|>",
    ]
    
    # Default whitelist patterns (known-safe)
    DEFAULT_WHITELIST_PATTERNS = [
        r"SELECT\s+[\w\s,\*\.]+\s+FROM\s+\w+\s+WHERE\s+(?:id|user_id)\s*=\s*\d+",
        r"SELECT\s+COUNT\(\*\)\s+FROM\s+\w+",
        r"SELECT\s+[\w\s,\*\.]+\s+FROM\s+\w+\s+LIMIT\s+\d+",
    ]
    
    def __init__(self, config: Optional[FastModeConfig] = None) -> None:
        """Initialize fast mode middleware.
        
        Args:
            config: Middleware configuration
        """
        self.config = config or FastModeConfig()
        self._cache: dict[str, LocalCacheEntry] = {}
        self._compiled_whitelist: list[tuple[str, Any]] = []
        self._compiled_blocklist: list[tuple[str, Any]] = []
        self._stats = {
            "checks": 0,
            "cache_hits": 0,
            "whitelist_hits": 0,
            "block_hits": 0,
            "api_fallbacks": 0,
        }
        
        # Compile patterns
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for fast matching."""
        import re
        
        # Compile whitelist patterns
        patterns = self.DEFAULT_WHITELIST_PATTERNS + self.config.whitelist_patterns
        for pattern in patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_whitelist.append((pattern, compiled))
            except re.error:
                pass
        
        # Compile block patterns
        patterns = self.DEFAULT_BLOCK_PATTERNS + self.config.block_patterns
        for pattern in patterns:
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                self._compiled_blocklist.append((pattern, compiled))
            except re.error:
                pass
    
    def _get_cache_key(self, text: str) -> str:
        """Generate cache key."""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()[:32]
    
    def _check_cache(self, text: str) -> Optional[FastModeLocalResult]:
        """Check local cache."""
        if not self.config.enable_local_cache:
            return None
        
        cache_key = self._get_cache_key(text)
        entry = self._cache.get(cache_key)
        
        if entry is None:
            return None
        
        if entry.is_expired:
            del self._cache[cache_key]
            return None
        
        self._stats["cache_hits"] += 1
        return entry.result
    
    def _cache_result(self, text: str, result: FastModeLocalResult) -> None:
        """Cache a result."""
        if not self.config.enable_local_cache:
            return
        
        cache_key = self._get_cache_key(text)
        
        if len(self._cache) >= self.config.cache_size:
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        
        self._cache[cache_key] = LocalCacheEntry(
            result=result,
            created_at=time.time(),
            ttl=self.config.cache_ttl_seconds,
        )
    
    def _check_whitelist(self, text: str) -> Optional[FastModeLocalResult]:
        """Check against whitelist patterns."""
        if not self.config.enable_whitelist:
            return None
        
        for pattern_str, compiled in self._compiled_whitelist:
            if compiled.fullmatch(text):
                self._stats["whitelist_hits"] += 1
                return FastModeLocalResult(
                    is_safe=True,
                    is_threat=False,
                    confidence=0.99,
                    tier="whitelist",
                    latency_ms=0.05,
                    pattern_name=pattern_str,
                    description="Whitelist match",
                )
        return None
    
    def _check_blocklist(self, text: str) -> Optional[FastModeLocalResult]:
        """Check against blocklist patterns."""
        if not self.config.enable_quick_block:
            return None
        
        for pattern_str, compiled in self._compiled_blocklist:
            if compiled.search(text):
                self._stats["block_hits"] += 1
                return FastModeLocalResult(
                    is_safe=False,
                    is_threat=True,
                    confidence=0.95,
                    tier="quick_block",
                    latency_ms=0.1,
                    pattern_name=pattern_str,
                    description="Quick block pattern match",
                )
        return None
    
    def detect(self, text: str) -> FastModeLocalResult:
        """Perform local fast mode detection.
        
        Args:
            text: Text to analyze
            
        Returns:
            Local detection result
        """
        start_time = time.perf_counter()
        self._stats["checks"] += 1
        
        # Check cache
        cached = self._check_cache(text)
        if cached is not None:
            return cached
        
        # Check whitelist (safe patterns)
        whitelist_result = self._check_whitelist(text)
        if whitelist_result is not None:
            self._cache_result(text, whitelist_result)
            return whitelist_result
        
        # Check blocklist (threat patterns)
        block_result = self._check_blocklist(text)
        if block_result is not None:
            self._cache_result(text, block_result)
            return block_result
        
        # No match - unknown
        latency_ms = (time.perf_counter() - start_time) * 1000
        return FastModeLocalResult(
            is_safe=False,
            is_threat=False,
            confidence=0.0,
            tier="unknown",
            latency_ms=latency_ms,
            description="No local match - requires API check",
        )
    
    def check(self, func: F) -> F:
        """Decorator to add fast mode checking before function execution.
        
        Args:
            func: Function to wrap
            
        Returns:
            Wrapped function
        """
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get text from first string argument
            text = None
            for arg in args:
                if isinstance(arg, str):
                    text = arg
                    break
            
            if text is None:
                for key, value in kwargs.items():
                    if isinstance(value, str):
                        text = value
                        break
            
            if text is not None:
                result = self.detect(text)
                
                if result.is_threat:
                    raise ThreatBlockedError(
                        message=f"Fast mode blocked: {result.description}",
                        threat_level="high",
                        action="block",
                        confidence=result.confidence,
                    )
            
            return func(*args, **kwargs)
        
        return wrapper  # type: ignore
    
    async def check_async(self, func: F) -> F:
        """Async decorator for fast mode checking.
        
        Args:
            func: Async function to wrap
            
        Returns:
            Wrapped async function
        """
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get text from first string argument
            text = None
            for arg in args:
                if isinstance(arg, str):
                    text = arg
                    break
            
            if text is None:
                for key, value in kwargs.items():
                    if isinstance(value, str):
                        text = value
                        break
            
            if text is not None:
                result = self.detect(text)
                
                if result.is_threat:
                    raise ThreatBlockedError(
                        message=f"Fast mode blocked: {result.description}",
                        threat_level="high",
                        action="block",
                        confidence=result.confidence,
                    )
            
            return await func(*args, **kwargs)
        
        return wrapper  # type: ignore
    
    def add_whitelist_pattern(self, pattern: str) -> bool:
        """Add a pattern to the whitelist.
        
        Args:
            pattern: Regex pattern
            
        Returns:
            True if added successfully
        """
        import re
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._compiled_whitelist.append((pattern, compiled))
            self.config.whitelist_patterns.append(pattern)
            return True
        except re.error:
            return False
    
    def add_block_pattern(self, pattern: str) -> bool:
        """Add a pattern to the blocklist.
        
        Args:
            pattern: Regex pattern
            
        Returns:
            True if added successfully
        """
        import re
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self._compiled_blocklist.append((pattern, compiled))
            self.config.block_patterns.append(pattern)
            return True
        except re.error:
            return False
    
    def clear_cache(self) -> int:
        """Clear the local cache.
        
        Returns:
            Number of entries cleared
        """
        count = len(self._cache)
        self._cache.clear()
        return count
    
    @property
    def stats(self) -> dict[str, Any]:
        """Get middleware statistics."""
        total = self._stats["checks"]
        return {
            **self._stats,
            "cache_hit_rate": self._stats["cache_hits"] / total if total > 0 else 0.0,
            "whitelist_hit_rate": self._stats["whitelist_hits"] / total if total > 0 else 0.0,
            "block_hit_rate": self._stats["block_hits"] / total if total > 0 else 0.0,
            "whitelist_count": len(self._compiled_whitelist),
            "blocklist_count": len(self._compiled_blocklist),
        }


class FastModeGuard:
    """Fast mode guard combining local detection with API fallback.
    
    Example:
        ```python
        from blindai.middleware.fast_mode import FastModeGuard
        
        guard = FastModeGuard(
            api_key="your-key",
            base_url="http://localhost:8000",
        )
        
        @guard.protect
        def query_database(sql: str):
            return db.execute(sql)
        ```
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:8000",
        config: Optional[FastModeConfig] = None,
    ) -> None:
        """Initialize fast mode guard.
        
        Args:
            api_key: API key for fallback API calls
            base_url: Base URL for API
            config: Fast mode configuration
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.config = config or FastModeConfig()
        self._middleware = FastModeMiddleware(config=self.config)
        self._http_client: Optional[Any] = None
    
    def _get_http_client(self) -> Any:
        """Get or create HTTP client."""
        if self._http_client is None:
            import httpx
            self._http_client = httpx.Client(
                base_url=self.base_url,
                timeout=self.config.api_timeout_ms / 1000,
            )
        return self._http_client
    
    def _call_api(self, text: str) -> ProtectionResult:
        """Call the fast mode API.
        
        Args:
            text: Text to analyze
            
        Returns:
            Protection result from API
        """
        client = self._get_http_client()
        
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        response = client.post(
            "/v1/fast-mode/detect",
            json={"text": text},
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()
        
        return ProtectionResult(
            is_threat=data["is_threat"],
            threat_level="high" if data["is_threat"] else "none",
            final_action="block" if data["is_threat"] else "allow",
            confidence=data["confidence"],
            threats_detected=[{
                "pattern": data.get("pattern_name"),
                "description": data.get("description"),
            }] if data["is_threat"] else [],
            processing_time_ms=data["latency_ms"],
            metadata={"fast_mode_tier": data["tier"]},
        )
    
    def check(self, text: str) -> ProtectionResult:
        """Check text using fast mode with API fallback.
        
        Args:
            text: Text to analyze
            
        Returns:
            Protection result
        """
        # Local detection first
        local_result = self._middleware.detect(text)
        
        # If we have a confident result, return it
        if local_result.is_threat or local_result.is_safe:
            return local_result.to_protection_result()
        
        # Fall back to API
        if self.config.fallback_to_api:
            try:
                self._middleware._stats["api_fallbacks"] += 1
                return self._call_api(text)
            except Exception:
                # If API fails, be conservative
                return ProtectionResult(
                    is_threat=False,
                    threat_level="unknown",
                    final_action="allow",
                    confidence=0.0,
                    processing_time_ms=local_result.latency_ms,
                    metadata={"error": "API fallback failed"},
                )
        
        return local_result.to_protection_result()
    
    def protect(self, func: F) -> F:
        """Decorator to protect a function with fast mode.
        
        Args:
            func: Function to protect
            
        Returns:
            Protected function
        """
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get text from first string argument
            text = None
            for arg in args:
                if isinstance(arg, str):
                    text = arg
                    break
            
            if text is None:
                for key, value in kwargs.items():
                    if isinstance(value, str):
                        text = value
                        break
            
            if text is not None:
                result = self.check(text)
                
                if result.is_threat:
                    raise ThreatBlockedError(
                        message=f"Fast mode blocked threat",
                        threat_level=result.threat_level,
                        action=result.final_action,
                        confidence=result.confidence,
                    )
            
            return func(*args, **kwargs)
        
        return wrapper  # type: ignore
    
    @property
    def stats(self) -> dict[str, Any]:
        """Get guard statistics."""
        return self._middleware.stats
    
    def close(self) -> None:
        """Close HTTP client."""
        if self._http_client is not None:
            self._http_client.close()
            self._http_client = None
