"""Check methods for async client."""

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

from blindai.stubs.rbac import UserContext
from ..exceptions import APIError, ThreatBlockedError
from ..models import ProtectionResult

if TYPE_CHECKING:
    from .client import AsyncToolGuard

logger = logging.getLogger(__name__)


class AsyncCheckMixin:
    """Mixin providing check methods for threat detection."""

    async def check(
        self: "AsyncToolGuard",
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        user: Optional[UserContext] = None,
    ) -> ProtectionResult:
        """Check text for threats asynchronously.

        Args:
            text: Text to check
            context_id: Optional context ID for multi-turn tracking
            metadata: Optional metadata
            user: Optional user context for RBAC

        Returns:
            ProtectionResult with detection details

        Raises:
            ThreatBlockedError: If threat detected and action is BLOCK
            APIError: If API request fails
            TimeoutError: If request times out
            RetryExhaustedError: If all retries exhausted
        """
        # Prepare request
        request_data = {
            "text": text,
        }
        if context_id:
            request_data["context_id"] = context_id
        if metadata:
            request_data["metadata"] = metadata
        if user:
            request_data["user"] = user.to_dict()

        # Make request with retries
        response_data = await self._request_with_retry(
            method="POST",
            url="/v1/protect",
            json=request_data,
        )

        # Parse response
        result = ProtectionResult.from_api_response(response_data)

        # Handle blocking
        if result.final_action == "block":
            raise ThreatBlockedError(
                message=f"Threat detected: {result.threat_level}",
                threat_level=result.threat_level,
                threats=result.threats_detected,
                response=response_data,
            )

        return result

    async def check_batch(
        self: "AsyncToolGuard",
        items: list[dict[str, Any]],
        fail_fast: bool = False,
        max_concurrency: int = 10,
        on_progress: Optional[Union[Callable[[int, int], None], Callable[[int, int], Any]]] = None,
    ) -> list[ProtectionResult]:
        """Check multiple texts for threats in a batch asynchronously.
        
        More efficient than calling check() multiple times. Uses concurrent
        async requests for maximum throughput.
        
        Args:
            items: List of check items, each containing:
                - text (required): Text to check
                - context_id (optional): Context ID for multi-turn tracking
                - metadata (optional): Additional metadata
                - user (optional): UserContext for RBAC
            fail_fast: If True, stop on first threat and raise ThreatBlockedError
            max_concurrency: Maximum number of concurrent checks (default 10)
            on_progress: Optional callback function(completed, total) for progress updates.
                        Can be sync or async function.
            
        Returns:
            List of ProtectionResult objects in same order as input
            
        Raises:
            ThreatBlockedError: If fail_fast=True and a threat is detected
            ValueError: If items list is empty or invalid
        """
        if not items:
            raise ValueError("Items list cannot be empty")
        
        # Validate items
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"Item {i} must be a dictionary")
            if "text" not in item:
                raise ValueError(f"Item {i} missing required 'text' field")
        
        # Try batch API first
        try:
            return await self._check_batch_api(items, fail_fast, on_progress)
        except APIError as e:
            # If batch endpoint not available, fall back to concurrent checks
            if "404" in str(e) or "not found" in str(e).lower():
                logger.debug("Batch API not available, falling back to concurrent checks")
                return await self._check_batch_concurrent(items, fail_fast, max_concurrency, on_progress)
            raise
    
    async def _call_progress(
        self: "AsyncToolGuard",
        on_progress: Optional[Union[Callable[[int, int], None], Callable[[int, int], Any]]],
        completed: int,
        total: int,
    ) -> None:
        """Call progress callback, handling both sync and async callbacks."""
        if on_progress is None:
            return
        
        result = on_progress(completed, total)
        # If it's a coroutine, await it
        if asyncio.iscoroutine(result):
            await result
    
    async def _check_batch_api(
        self: "AsyncToolGuard",
        items: list[dict[str, Any]],
        fail_fast: bool,
        on_progress: Optional[Union[Callable[[int, int], None], Callable[[int, int], Any]]] = None,
    ) -> list[ProtectionResult]:
        """Check batch using dedicated batch API endpoint."""
        batch_items = [
            {
                "text": item["text"],
                **({"context_id": item["context_id"]} if "context_id" in item else {}),
                **({"metadata": item["metadata"]} if "metadata" in item else {}),
                **({"user": item["user"].to_dict()} if "user" in item else {}),
            }
            for item in items
        ]
        
        request_data = {
            "items": batch_items,
            "fail_fast": fail_fast,
        }
        
        start_time = time.perf_counter()
        
        response_data = await self._request_with_retry(
            method="POST",
            url="/v1/protect/batch",
            json=request_data,
        )
        
        latency_ms = (time.perf_counter() - start_time) * 1000
        
        # Parse results
        results = []
        for i, result_data in enumerate(response_data.get("results", [])):
            result = ProtectionResult.from_api_response(result_data)
            results.append(result)
            
            if fail_fast and result.final_action == "block":
                raise ThreatBlockedError(
                    message=f"Batch item {i} blocked: {result.threat_level}",
                    threat_level=result.threat_level,
                    threats=result.threats_detected,
                    response=result_data,
                )
        
        logger.debug(f"Async batch check completed: {len(results)} items in {latency_ms:.1f}ms")
        
        # Call progress callback with completion
        await self._call_progress(on_progress, len(results), len(items))
        
        return results
    
    async def _check_batch_concurrent(
        self: "AsyncToolGuard",
        items: list[dict[str, Any]],
        fail_fast: bool,
        max_concurrency: int,
        on_progress: Optional[Union[Callable[[int, int], None], Callable[[int, int], Any]]] = None,
    ) -> list[ProtectionResult]:
        """Fallback: check items concurrently using semaphore."""
        semaphore = asyncio.Semaphore(max_concurrency)
        results: list[Optional[ProtectionResult]] = [None] * len(items)
        cancel_event = asyncio.Event() if fail_fast else None
        completed_count = 0
        total = len(items)
        progress_lock = asyncio.Lock()
        
        async def report_progress() -> None:
            """Report progress with lock."""
            nonlocal completed_count
            async with progress_lock:
                completed_count += 1
                await self._call_progress(on_progress, completed_count, total)
        
        async def check_item(index: int, item: dict) -> None:
            if cancel_event and cancel_event.is_set():
                return
            
            async with semaphore:
                if cancel_event and cancel_event.is_set():
                    return
                
                try:
                    result = await self.check(
                        text=item["text"],
                        context_id=item.get("context_id"),
                        metadata=item.get("metadata"),
                        user=item.get("user"),
                    )
                    results[index] = result
                    
                    # Report progress
                    await report_progress()
                    
                    if fail_fast and result.final_action == "block":
                        if cancel_event:
                            cancel_event.set()
                        raise ThreatBlockedError(
                            message=f"Batch item {index} blocked: {result.threat_level}",
                            threat_level=result.threat_level,
                            threats=result.threats_detected,
                            response={},
                        )
                except ThreatBlockedError:
                    raise
                except Exception:
                    # Still report progress on error
                    await report_progress()
                    raise
        
        # Create tasks for all items
        tasks = [
            asyncio.create_task(check_item(i, item))
            for i, item in enumerate(items)
        ]
        
        try:
            # Wait for all tasks (or until one raises)
            await asyncio.gather(*tasks, return_exceptions=not fail_fast)
        except ThreatBlockedError:
            # Cancel remaining tasks
            for task in tasks:
                task.cancel()
            raise
        
        # Filter out None results
        return [r for r in results if r is not None]
