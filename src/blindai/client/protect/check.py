"""Main check method for threat detection."""

import logging
import time
from typing import Any, Optional

from blindai.stubs.rbac import UserContext
from ...exceptions import ThreatBlockedError
from ...hooks import EventType, SecurityEvent, create_error_event, create_event_from_result
from ...models import ProtectionResult

logger = logging.getLogger(__name__)


class CheckMixin:
    """Mixin providing the check() method."""

    def check(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        user: Optional[UserContext] = None,
    ) -> ProtectionResult:
        """Check text for threats.

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
        """
        # Get effective context
        effective_context_id, effective_user, effective_metadata = self._get_effective_context(
            context_id, user, metadata
        )
        
        # Prepare request
        request_data = {"text": text}
        if effective_context_id:
            request_data["context_id"] = effective_context_id
        if effective_metadata:
            request_data["metadata"] = effective_metadata
        if effective_user:
            request_data["user"] = effective_user.to_dict()

        start_time = time.perf_counter()

        # Dispatch before_check event
        before_event = SecurityEvent(
            event_type=EventType.BEFORE_CHECK,
            text=text,
            context_id=effective_context_id,
            user_id=effective_user.user_id if effective_user else None,
            metadata=effective_metadata,
        )
        self.hooks.dispatch(EventType.BEFORE_CHECK, before_event)

        try:
            # Make request with retries
            response_data = self._request_with_retry(
                method="POST",
                url="/v1/protect",
                json=request_data,
            )

            # Parse response
            result = ProtectionResult.from_api_response(response_data)
            latency_ms = (time.perf_counter() - start_time) * 1000

            # Create event from result
            event = create_event_from_result(
                result=result,
                text=text,
                latency_ms=latency_ms,
                context_id=effective_context_id,
                user_id=effective_user.user_id if effective_user else None,
                metadata=effective_metadata,
            )

            # Dispatch appropriate event based on action
            if result.final_action == "block":
                self.hooks.dispatch(EventType.BLOCK, event)
                raise ThreatBlockedError(
                    message=f"Threat detected: {result.threat_level}",
                    threat_level=result.threat_level,
                    threats=result.threats_detected,
                    response=response_data,
                )
            elif result.final_action == "challenge":
                challenge_results = self.hooks.dispatch(EventType.CHALLENGE, event)
                if any(r is False for r in challenge_results):
                    raise ThreatBlockedError(
                        message=f"Challenge denied: {result.threat_level}",
                        threat_level=result.threat_level,
                        threats=result.threats_detected,
                        response=response_data,
                    )
            else:
                self.hooks.dispatch(EventType.ALLOW, event)

            self.hooks.dispatch(EventType.AFTER_CHECK, event)
            return result

        except ThreatBlockedError:
            raise

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            error_event = create_error_event(
                error=e,
                text=text,
                context_id=effective_context_id,
                user_id=effective_user.user_id if effective_user else None,
                metadata=effective_metadata,
            )
            self.hooks.dispatch(EventType.ERROR, error_event)
            raise
