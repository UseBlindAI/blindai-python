"""HTTP request handling with retry logic for async client."""

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx

from ..exceptions import APIError, RetryExhaustedError, TimeoutError

if TYPE_CHECKING:
    from .client import AsyncToolGuard

logger = logging.getLogger(__name__)


class AsyncHTTPMixin:
    """Mixin providing async HTTP request methods with retry logic."""

    async def _request_with_retry(
        self: "AsyncToolGuard",
        method: str,
        url: str,
        **kwargs,
    ) -> dict:
        """Make async HTTP request with retry logic and circuit breaker.

        Args:
            method: HTTP method
            url: URL path
            **kwargs: Additional request arguments

        Returns:
            Response JSON data

        Raises:
            APIError: If request fails
            TimeoutError: If request times out
            RetryExhaustedError: If all retries exhausted
            CircuitBreakerOpen: If circuit breaker is open
        """
        # If circuit breaker is configured, use it
        if self._circuit_breaker:
            # Define fallback for fail_open mode
            def fallback(error: Exception) -> dict:
                return {
                    "is_threat": False,
                    "threat_level": "none",
                    "final_action": "allow",
                    "confidence": 0.0,
                    "threats_detected": [],
                    "processing_time_ms": 0.0,
                    "metadata": {
                        "error": str(error),
                        "fail_mode": "circuit_breaker",
                        "circuit_state": self._circuit_breaker.state.value,
                    },
                }

            # For async, we need to wrap the coroutine in a sync function
            # The circuit breaker will run in the same event loop
            return await self._circuit_breaker.execute_async(
                self._do_request_with_retry(method, url, **kwargs),
                fallback=fallback if self.config.fail_open else None,
            )
        else:
            return await self._do_request_with_retry(method, url, **kwargs)

    async def _do_request_with_retry(
        self: "AsyncToolGuard",
        method: str,
        url: str,
        **kwargs,
    ) -> dict:
        """Internal method to make async HTTP request with retry logic.

        Args:
            method: HTTP method
            url: URL path
            **kwargs: Additional request arguments

        Returns:
            Response JSON data

        Raises:
            APIError: If request fails
            TimeoutError: If request times out
            RetryExhaustedError: If all retries exhausted
        """
        last_error = None
        attempts = 0

        for attempt in range(self.config.max_retries + 1):
            attempts = attempt + 1

            try:
                response = await self.client.request(method, url, **kwargs)
                response.raise_for_status()
                return response.json()

            except httpx.TimeoutException as e:
                last_error = e
                if attempt == self.config.max_retries:
                    if self.config.fail_open:
                        # Return safe default
                        return {
                            "is_threat": False,
                            "threat_level": "none",
                            "final_action": "allow",
                            "confidence": 0.0,
                            "threats_detected": [],
                            "processing_time_ms": 0.0,
                            "metadata": {"error": "timeout", "fail_mode": "open"},
                        }
                    raise TimeoutError("Request timed out") from e

            except httpx.HTTPStatusError as e:
                last_error = e
                if attempt == self.config.max_retries:
                    if self.config.fail_open and e.response.status_code >= 500:
                        # Return safe default for server errors
                        return {
                            "is_threat": False,
                            "threat_level": "none",
                            "final_action": "allow",
                            "confidence": 0.0,
                            "threats_detected": [],
                            "processing_time_ms": 0.0,
                            "metadata": {
                                "error": f"HTTP {e.response.status_code}",
                                "fail_mode": "open",
                            },
                        }
                    raise APIError(
                        message=f"API request failed: {e.response.status_code}",
                        status_code=e.response.status_code,
                        response=e.response.json() if e.response.text else None,
                    ) from e

            except httpx.RequestError as e:
                last_error = e
                if attempt == self.config.max_retries:
                    if self.config.fail_open:
                        # Return safe default
                        return {
                            "is_threat": False,
                            "threat_level": "none",
                            "final_action": "allow",
                            "confidence": 0.0,
                            "threats_detected": [],
                            "processing_time_ms": 0.0,
                            "metadata": {"error": str(e), "fail_mode": "open"},
                        }
                    raise APIError(f"Request failed: {e}") from e

            # Exponential backoff
            if attempt < self.config.max_retries:
                sleep_time = self.config.retry_backoff * (2**attempt)
                await asyncio.sleep(sleep_time)

        # Should not reach here, but handle gracefully
        raise RetryExhaustedError(
            message=f"All {attempts} retry attempts exhausted",
            attempts=attempts,
            last_error=last_error,
        )
