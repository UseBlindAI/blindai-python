"""Semantic caching middleware for SDK.

Provides semantic similarity caching for the ToolGuard SDK,
making BlindAI faster than using no security at all.
"""

import logging
from typing import Any, Dict, Optional

from ..models import ProtectionResult
from ...core.cache import (
    SemanticCache,
    SemanticCacheConfig,
    CacheBackend,
    CacheResult,
    create_semantic_cache,
)

logger = logging.getLogger(__name__)


class SemanticCacheConfig:
    """Configuration for semantic caching middleware.
    
    Attributes:
        enabled: Enable semantic caching
        similarity_threshold: Minimum similarity for cache hit (0.0-1.0)
        max_entries: Maximum cache entries
        ttl_seconds: Entry time-to-live
        cache_threats: Whether to cache threat results
        backend: Cache backend ('memory' or 'qdrant')
        qdrant_url: Qdrant server URL (if using qdrant backend)
        poisoning_prevention: Enable cache poisoning prevention
    """
    
    def __init__(
        self,
        enabled: bool = True,
        similarity_threshold: float = 0.92,
        max_entries: int = 100000,
        ttl_seconds: float = 3600.0,
        cache_threats: bool = False,
        backend: str = "memory",
        qdrant_url: Optional[str] = None,
        poisoning_prevention: bool = True,
    ):
        self.enabled = enabled
        self.similarity_threshold = similarity_threshold
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self.cache_threats = cache_threats
        self.backend = backend
        self.qdrant_url = qdrant_url
        self.poisoning_prevention = poisoning_prevention


class SemanticResultCache:
    """Semantic similarity cache for protection results.
    
    Uses embeddings and vector similarity for intelligent caching.
    Similar queries return cached results even if not identical.
    
    Example:
        ```python
        from blindai.middleware.semantic import SemanticResultCache, SemanticCacheConfig
        
        cache = SemanticResultCache(SemanticCacheConfig(
            similarity_threshold=0.92,
            backend="memory",
        ))
        
        # First check
        result = cache.get("SELECT * FROM users WHERE id=1")  # Miss
        cache.set("SELECT * FROM users WHERE id=1", protection_result)
        
        # Similar query hits cache
        result = cache.get("SELECT * FROM users WHERE id=2")  # Hit! (semantic match)
        ```
    """
    
    def __init__(self, config: SemanticCacheConfig):
        """Initialize semantic cache.
        
        Args:
            config: Cache configuration
        """
        self.config = config
        
        # Create underlying semantic cache
        self._cache = create_semantic_cache(
            backend=config.backend,
            similarity_threshold=config.similarity_threshold,
            max_entries=config.max_entries,
            ttl_seconds=config.ttl_seconds,
            qdrant_url=config.qdrant_url,
            poisoning_prevention=config.poisoning_prevention,
        )
        
        # Statistics
        self._threat_cache_skips = 0
    
    def get(
        self,
        text: str,
        context_id: Optional[str] = None,
    ) -> Optional[ProtectionResult]:
        """Get cached result for semantically similar text.
        
        Args:
            text: Input text
            context_id: Optional context ID
            
        Returns:
            Cached ProtectionResult or None if not found
        """
        if not self.config.enabled:
            return None
        
        # Build query with context
        query = f"{context_id}:{text}" if context_id else text
        
        result = self._cache.get(query)
        
        if result.hit and result.entry:
            # Reconstruct ProtectionResult from cached data
            cached_data = result.entry.response
            
            if isinstance(cached_data, ProtectionResult):
                logger.debug(
                    f"Semantic cache hit: similarity={result.similarity:.3f}, "
                    f"lookup_time={result.lookup_time_ms:.2f}ms"
                )
                return cached_data
            elif isinstance(cached_data, dict):
                # Reconstruct from dict
                logger.debug(
                    f"Semantic cache hit (dict): similarity={result.similarity:.3f}"
                )
                return ProtectionResult(**cached_data)
        
        return None
    
    def set(
        self,
        text: str,
        result: ProtectionResult,
        context_id: Optional[str] = None,
        source: Optional[str] = None,
    ) -> bool:
        """Cache a protection result.
        
        Args:
            text: Input text
            result: Protection result to cache
            context_id: Optional context ID
            source: Optional source identifier
            
        Returns:
            True if cached successfully
        """
        if not self.config.enabled:
            return False
        
        # Don't cache threats unless explicitly enabled
        if result.is_threat and not self.config.cache_threats:
            self._threat_cache_skips += 1
            logger.debug("Skipping cache for threat result")
            return False
        
        # Build query with context
        query = f"{context_id}:{text}" if context_id else text
        
        # Convert result to dict for storage
        result_dict = {
            "is_threat": result.is_threat,
            "threat_level": result.threat_level,
            "final_action": result.final_action,
            "threats_detected": [
                t.__dict__ if hasattr(t, '__dict__') else t
                for t in result.threats_detected
            ],
            "confidence": result.confidence,
            "processing_time_ms": result.processing_time_ms,
            "metadata": result.metadata,
        }
        
        success = self._cache.set(
            query,
            result_dict,
            metadata={"context_id": context_id} if context_id else None,
            source=source,
        )
        
        if success:
            logger.debug(f"Cached result for text: {text[:50]}...")
        
        return success
    
    def invalidate(self, text: str, context_id: Optional[str] = None) -> bool:
        """Invalidate a cache entry.
        
        Args:
            text: Input text
            context_id: Optional context ID
            
        Returns:
            True if entry was invalidated
        """
        query = f"{context_id}:{text}" if context_id else text
        return self._cache.invalidate(query)
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        self._threat_cache_skips = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        stats = self._cache.get_stats()
        stats["threat_cache_skips"] = self._threat_cache_skips
        return stats


class SemanticMiddlewareGuard:
    """Guard wrapper with semantic caching support.
    
    Provides intelligent caching based on semantic similarity,
    combined with optional rate limiting and rollout.
    
    Example:
        ```python
        from blindai import ToolGuard
        from blindai.middleware.semantic import (
            SemanticMiddlewareGuard,
            SemanticCacheConfig,
        )
        
        guard = ToolGuard(base_url="http://localhost:8000")
        
        semantic_guard = SemanticMiddlewareGuard(
            guard=guard,
            cache_config=SemanticCacheConfig(
                similarity_threshold=0.92,
                backend="memory",
            ),
        )
        
        # First call - cache miss
        result1 = semantic_guard.check("What is user 123's email?")
        
        # Similar query - cache hit!
        result2 = semantic_guard.check("What is user 456's email?")
        ```
    """
    
    def __init__(
        self,
        guard: Any,
        cache_config: Optional[SemanticCacheConfig] = None,
    ):
        """Initialize semantic middleware guard.
        
        Args:
            guard: Underlying guard to wrap
            cache_config: Semantic cache configuration
        """
        self.guard = guard
        
        if cache_config:
            self.cache = SemanticResultCache(cache_config)
        else:
            self.cache = None
    
    def check(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
        tool_name: Optional[str] = None,
    ) -> ProtectionResult:
        """Check with semantic caching.
        
        Args:
            text: Text to check
            context_id: Optional context ID
            metadata: Optional metadata
            user: Optional user context
            tool_name: Optional tool name
            
        Returns:
            ProtectionResult
        """
        user_id = user.user_id if user and hasattr(user, 'user_id') else None
        
        # Check semantic cache
        if self.cache:
            cached = self.cache.get(text, context_id)
            if cached:
                logger.debug("Returning semantically cached result")
                # Add metadata indicating cache hit
                cached.metadata = {
                    **(cached.metadata or {}),
                    "semantic_cache_hit": True,
                }
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
            self.cache.set(text, result, context_id, source=user_id)
        
        return result
    
    async def acheck(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
        tool_name: Optional[str] = None,
    ) -> ProtectionResult:
        """Async check with semantic caching.
        
        Args:
            text: Text to check
            context_id: Optional context ID
            metadata: Optional metadata
            user: Optional user context
            tool_name: Optional tool name
            
        Returns:
            ProtectionResult
        """
        # Same logic as sync for now (embeddings are CPU-bound)
        return self.check(text, context_id, metadata, user, tool_name)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get middleware statistics.
        
        Returns:
            Dictionary with cache stats
        """
        stats = {}
        
        if self.cache:
            stats["semantic_cache"] = self.cache.get_stats()
        
        return stats
    
    # Delegate other attributes to underlying guard
    def __getattr__(self, name: str) -> Any:
        return getattr(self.guard, name)
