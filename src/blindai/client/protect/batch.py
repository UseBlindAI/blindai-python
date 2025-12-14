"""Batch checking methods for threat detection."""

import concurrent.futures
import inspect
import logging
import threading
import time
from typing import Any, Callable, Optional

from ...exceptions import ThreatBlockedError
from ...models import ProtectionResult

logger = logging.getLogger(__name__)


class BatchMixin:
    """Mixin providing batch checking methods."""

    def check_batch(
        self,
        items: list[dict[str, Any]],
        fail_fast: bool = False,
        parallel: bool = True,
        on_progress: Optional[Callable] = None,
    ) -> list[ProtectionResult]:
        """Check multiple texts for threats in a batch.
        
        Args:
            items: List of check items with text, context_id, metadata, user
            fail_fast: If True, stop on first threat
            parallel: If True, process items in parallel
            on_progress: Optional callback for progress updates
            
        Returns:
            List of ProtectionResult objects
            
        Raises:
            ThreatBlockedError: If fail_fast=True and a threat is detected
            ValueError: If items list is empty or invalid
        """
        if not items:
            raise ValueError("Items list cannot be empty")
        
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(f"Item {i} must be a dictionary")
            if "text" not in item:
                raise ValueError(f"Item {i} missing required 'text' field")
        
        # Try batch API first
        try:
            return self._check_batch_api(items, fail_fast, on_progress)
        except Exception as e:
            from ...exceptions import APIError
            if isinstance(e, APIError) and ("404" in str(e) or "not found" in str(e).lower()):
                logger.debug("Batch API not available, falling back to individual checks")
                return self._check_batch_fallback(items, fail_fast, parallel, on_progress)
            raise
    
    def _check_batch_api(
        self,
        items: list[dict[str, Any]],
        fail_fast: bool,
        on_progress: Optional[Callable[[int, int], None]] = None,
    ) -> list[ProtectionResult]:
        """Check batch using dedicated batch API endpoint."""
        batch_items = []
        for item in items:
            effective_context_id, effective_user, effective_metadata = self._get_effective_context(
                item.get("context_id"),
                item.get("user"),
                item.get("metadata"),
            )
            
            batch_item = {"text": item["text"]}
            if effective_context_id:
                batch_item["context_id"] = effective_context_id
            if effective_metadata:
                batch_item["metadata"] = effective_metadata
            if effective_user:
                batch_item["user"] = effective_user.to_dict()
            
            batch_items.append(batch_item)
        
        request_data = {
            "items": batch_items,
            "fail_fast": fail_fast,
        }
        
        start_time = time.perf_counter()
        
        try:
            response_data = self._request_with_retry(
                method="POST",
                url="/v1/protect/batch",
                json=request_data,
            )
            
            latency_ms = (time.perf_counter() - start_time) * 1000
            
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
            
            logger.debug(f"Batch check completed: {len(results)} items in {latency_ms:.1f}ms")
            
            if on_progress:
                on_progress(len(results), len(items))
            
            return results
            
        except ThreatBlockedError:
            raise
        except Exception as e:
            logger.error(f"Batch API check failed: {e}")
            raise
    
    def _check_batch_fallback(
        self,
        items: list[dict[str, Any]],
        fail_fast: bool,
        parallel: bool,
        on_progress: Optional[Callable] = None,
    ) -> list[ProtectionResult]:
        """Fallback: check items individually (optionally in parallel)."""
        from ..base import ProgressMetadata
        
        results: list[Optional[ProtectionResult]] = [None] * len(items)
        errors: list[Optional[Exception]] = [None] * len(items)
        completed_count = 0
        total = len(items)
        progress_lock = threading.Lock()
        
        threats_detected = 0
        blocked_count = 0
        total_latency_ms = 0.0
        errors_count = 0
        
        accepts_metadata = False
        if on_progress:
            try:
                sig = inspect.signature(on_progress)
                accepts_metadata = len(sig.parameters) >= 3
            except (ValueError, TypeError):
                pass
        
        def build_metadata(current_index: Optional[int] = None) -> ProgressMetadata:
            current_preview = None
            if current_index is not None and current_index < len(items):
                text = items[current_index].get("text", "")
                current_preview = text[:50] + "..." if len(text) > 50 else text
            
            return ProgressMetadata(
                threats_detected=threats_detected,
                blocked_count=blocked_count,
                avg_latency_ms=total_latency_ms / completed_count if completed_count > 0 else 0.0,
                total_latency_ms=total_latency_ms,
                current_item_preview=current_preview,
                current_index=current_index,
                errors_count=errors_count,
            )
        
        def check_item(index: int, item: dict) -> tuple[int, ProtectionResult, float]:
            item_start = time.perf_counter()
            result = self.check(
                text=item["text"],
                context_id=item.get("context_id"),
                metadata=item.get("metadata"),
                user=item.get("user"),
            )
            item_latency = (time.perf_counter() - item_start) * 1000
            return index, result, item_latency
        
        nonlocal_vars = {
            'completed_count': completed_count,
            'threats_detected': threats_detected,
            'blocked_count': blocked_count,
            'total_latency_ms': total_latency_ms,
            'errors_count': errors_count,
        }
        
        if parallel and len(items) > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(items), 10)) as executor:
                futures = {
                    executor.submit(check_item, i, item): i
                    for i, item in enumerate(items)
                }
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        index, result, item_latency = future.result()
                        results[index] = result
                        
                        with progress_lock:
                            nonlocal_vars['completed_count'] += 1
                            nonlocal_vars['total_latency_ms'] += item_latency
                            if result.is_threat:
                                nonlocal_vars['threats_detected'] += 1
                            if result.final_action == "block":
                                nonlocal_vars['blocked_count'] += 1
                        
                        if on_progress:
                            with progress_lock:
                                if accepts_metadata:
                                    metadata = ProgressMetadata(
                                        threats_detected=nonlocal_vars['threats_detected'],
                                        blocked_count=nonlocal_vars['blocked_count'],
                                        avg_latency_ms=nonlocal_vars['total_latency_ms'] / nonlocal_vars['completed_count'] if nonlocal_vars['completed_count'] > 0 else 0.0,
                                        total_latency_ms=nonlocal_vars['total_latency_ms'],
                                        current_item_preview=items[index].get("text", "")[:50],
                                        current_index=index,
                                        errors_count=nonlocal_vars['errors_count'],
                                    )
                                    on_progress(nonlocal_vars['completed_count'], total, metadata)
                                else:
                                    on_progress(nonlocal_vars['completed_count'], total)
                        
                        if fail_fast and result.final_action == "block":
                            for f in futures:
                                f.cancel()
                            raise ThreatBlockedError(
                                message=f"Batch item {index} blocked: {result.threat_level}",
                                threat_level=result.threat_level,
                                threats=result.threats_detected,
                                response={},
                            )
                    except ThreatBlockedError:
                        raise
                    except Exception as e:
                        index = futures[future]
                        errors[index] = e
                        with progress_lock:
                            nonlocal_vars['completed_count'] += 1
                            nonlocal_vars['errors_count'] += 1
                        if on_progress:
                            with progress_lock:
                                on_progress(nonlocal_vars['completed_count'], total)
                        if fail_fast:
                            raise
        else:
            for i, item in enumerate(items):
                try:
                    _, result, item_latency = check_item(i, item)
                    results[i] = result
                    
                    completed_count += 1
                    total_latency_ms += item_latency
                    if result.is_threat:
                        threats_detected += 1
                    if result.final_action == "block":
                        blocked_count += 1
                    
                    if on_progress:
                        if accepts_metadata:
                            metadata = build_metadata(i)
                            on_progress(completed_count, total, metadata)
                        else:
                            on_progress(completed_count, total)
                    
                    if fail_fast and result.final_action == "block":
                        raise ThreatBlockedError(
                            message=f"Batch item {i} blocked: {result.threat_level}",
                            threat_level=result.threat_level,
                            threats=result.threats_detected,
                            response={},
                        )
                except ThreatBlockedError:
                    raise
                except Exception as e:
                    errors[i] = e
                    completed_count += 1
                    errors_count += 1
                    if on_progress:
                        if accepts_metadata:
                            metadata = build_metadata(i)
                            on_progress(completed_count, total, metadata)
                        else:
                            on_progress(completed_count, total)
                    if fail_fast:
                        raise
        
        for i, error in enumerate(errors):
            if error is not None:
                logger.warning(f"Batch item {i} failed: {error}")
        
        return [r for r in results if r is not None]
