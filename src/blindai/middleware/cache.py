"""Caching components for SDK middleware."""

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..models import ProtectionResult

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """A cached protection result."""
    result: ProtectionResult
    created_at: float
    hits: int = 0


@dataclass
class CacheConfig:
    """Configuration for result caching.
    
    Attributes:
        enabled: Whether caching is enabled
        ttl_seconds: Time-to-live for cache entries
        max_size: Maximum number of cached entries
        cache_threats: Whether to cache threat results (default: False for safety)
        similarity_enabled: Enable semantic similarity matching
        similarity_threshold: Minimum similarity score for cache hit (0.0-1.0)
    """
    enabled: bool = True
    ttl_seconds: float = 300.0  # 5 minutes
    max_size: int = 1000
    cache_threats: bool = False  # Don't cache threats by default
    similarity_enabled: bool = False
    similarity_threshold: float = 0.95


class ResultCache:
    """LRU cache for protection results.
    
    Caches results to avoid redundant API calls for identical inputs.
    
    Example:
        ```python
        cache = ResultCache(CacheConfig(ttl_seconds=300))
        
        # Check cache
        cached = cache.get("SELECT * FROM users")
        if cached:
            return cached
        
        # Make API call
        result = guard.check(text)
        
        # Cache result
        cache.set(text, result)
        ```
    """
    
    def __init__(self, config: CacheConfig):
        """Initialize cache.
        
        Args:
            config: Cache configuration
        """
        self.config = config
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order: List[str] = []  # For LRU eviction
        self._lock = threading.Lock()
        
        # Optional: similarity index for semantic caching
        self._embeddings: Dict[str, List[float]] = {}
    
    def _hash_key(self, text: str, context_id: Optional[str] = None) -> str:
        """Generate cache key from text and context."""
        key_data = text
        if context_id:
            key_data = f"{context_id}:{text}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:32]
    
    def _is_expired(self, entry: CacheEntry) -> bool:
        """Check if cache entry is expired."""
        return (time.monotonic() - entry.created_at) > self.config.ttl_seconds
    
    def _evict_if_needed(self) -> None:
        """Evict oldest entries if cache is full."""
        while len(self._cache) >= self.config.max_size and self._access_order:
            oldest_key = self._access_order.pop(0)
            self._cache.pop(oldest_key, None)
            self._embeddings.pop(oldest_key, None)
    
    def _update_access(self, key: str) -> None:
        """Update access order for LRU."""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def get(
        self,
        text: str,
        context_id: Optional[str] = None,
    ) -> Optional[ProtectionResult]:
        """Get cached result.
        
        Args:
            text: Input text
            context_id: Optional context ID
            
        Returns:
            Cached ProtectionResult or None if not found/expired
        """
        if not self.config.enabled:
            return None
        
        key = self._hash_key(text, context_id)
        
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                # Try similarity matching if enabled
                if self.config.similarity_enabled:
                    similar_result = self._find_similar(text)
                    if similar_result:
                        return similar_result
                return None
            
            if self._is_expired(entry):
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                return None
            
            entry.hits += 1
            self._update_access(key)
            
            logger.debug(f"Cache hit for key {key[:8]}... (hits: {entry.hits})")
            return entry.result
    
    def set(
        self,
        text: str,
        result: ProtectionResult,
        context_id: Optional[str] = None,
    ) -> None:
        """Cache a result.
        
        Args:
            text: Input text
            result: Protection result to cache
            context_id: Optional context ID
        """
        if not self.config.enabled:
            return
        
        # Don't cache threats unless explicitly enabled
        if result.is_threat and not self.config.cache_threats:
            return
        
        key = self._hash_key(text, context_id)
        
        with self._lock:
            self._evict_if_needed()
            
            self._cache[key] = CacheEntry(
                result=result,
                created_at=time.monotonic(),
            )
            self._update_access(key)
            
            logger.debug(f"Cached result for key {key[:8]}...")
    
    def _find_similar(self, text: str) -> Optional[ProtectionResult]:
        """Find similar cached result using embeddings.
        
        Note: Requires external embedding function to be set.
        """
        # Placeholder for semantic similarity
        # In production, this would use sentence embeddings
        return None
    
    def invalidate(self, text: str, context_id: Optional[str] = None) -> bool:
        """Invalidate a specific cache entry.
        
        Args:
            text: Input text
            context_id: Optional context ID
            
        Returns:
            True if entry was found and removed
        """
        key = self._hash_key(text, context_id)
        
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._embeddings.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache stats
        """
        with self._lock:
            total_hits = sum(e.hits for e in self._cache.values())
            return {
                "size": len(self._cache),
                "max_size": self.config.max_size,
                "total_hits": total_hits,
                "ttl_seconds": self.config.ttl_seconds,
            }
