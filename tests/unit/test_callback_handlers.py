"""Integration tests for SDK callback handlers (challenge_action, block_action).

These tests verify that the documented callback features work correctly:
- challenge_action: Custom handler for challenge decisions
- block_action: Custom handler called when request is blocked

Priority 1 tests per COMPETITIVE_FEATURES_ANALYSIS.md recommendations.

Architecture:
    Python SDK uses the decorator pattern for protect(). The callback features
    (challenge_action, block_action) are available via the DecoratorMixin which
    ToolGuard inherits. We test using HTTP mocking to avoid real API calls while
    still exercising the full integration path:
    
        HTTP Client → Response Parsing → Decorator Logic → Callback Execution

Important SDK Behavior (discovered through testing):
    
    When `block_action` IS called:
        - When API returns is_threat=True with final_action="warn" (or similar)
        - AND decorator's on_violation="block" decides to block
        - The decorator's _handle_threat() calls block_action BEFORE raising
    
    When `block_action` is NOT called:
        - When API returns final_action="block"
        - check() raises ThreatBlockedError IMMEDIATELY
        - Decorator logic never reaches _handle_threat()
    
    This means block_action is for when the DECORATOR decides to block,
    not when the API decides to block. This is the correct design since
    block_action is a decorator parameter, not an API parameter.

Test Strategy:
    These are integration tests that use HTTP mocking on real ToolGuard.
    This approach tests the actual code path users will hit, and has
    successfully identified real SDK behavior quirks documented above.
"""

import pytest
from unittest.mock import Mock, patch

from blindai import (
    ProtectionResult,
    ThreatBlockedError,
    ToolGuard,
)


def mock_api_response(is_threat=False, threat_level="none", final_action="allow"):
    """Create a mock API response."""
    return {
        "is_threat": is_threat,
        "threat_level": threat_level,
        "final_action": final_action,
        "confidence": 0.95 if is_threat else 0.0,
        "threats_detected": ["mock_threat"] if is_threat else [],
        "processing_time_ms": 1.5,
        "metadata": {},
    }


# =============================================================================
# Challenge Handler Tests (Decorator Pattern)
# =============================================================================

class TestChallengeHandlerApproval:
    """Test challenge handler allows request when it returns True."""

    def test_challenge_handler_approves(self):
        """Challenge handler approves and function proceeds."""
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def approve_challenge(result):
            return True  # Approve
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        # Use decorator with challenge_action
        @guard.protect(
            on_violation='challenge',
            challenge_action=approve_challenge,
        )
        def process_input(text: str) -> str:
            return f"Processed: {text}"
        
        # Should NOT raise because handler approves
        result = process_input('Suspicious input')
        assert result == "Processed: Suspicious input"

    def test_challenge_handler_approves_with_context(self):
        """Challenge handler receives full context to make decision."""
        received_results = []
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def context_aware_approval(result):
            received_results.append(result)
            return result.threat_level != 'critical'
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=context_aware_approval,
        )
        def process_input(text: str) -> str:
            return text.upper()
        
        result = process_input('Test input')
        
        assert len(received_results) == 1
        assert received_results[0].threat_level == 'medium'
        assert result == 'TEST INPUT'


class TestChallengeHandlerRejection:
    """Test challenge handler blocks request when it returns False."""

    def test_challenge_handler_rejects(self):
        """Challenge handler rejects and ThreatBlockedError is raised."""
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def reject_challenge(result):
            return False  # Reject
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=reject_challenge,
        )
        def process_input(text: str) -> str:
            return text
        
        # Should raise because handler rejects
        with pytest.raises(ThreatBlockedError) as exc_info:
            process_input('Suspicious input')
        
        assert exc_info.value.threat_level == 'medium'

    def test_challenge_handler_conditional_rejection(self):
        """Challenge handler rejects based on threat details."""
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="critical", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def conditional_reject(result):
            return result.threat_level != 'critical'
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=conditional_reject,
        )
        def process_input(text: str) -> str:
            return text
        
        with pytest.raises(ThreatBlockedError) as exc_info:
            process_input('Critical threat')
        
        assert exc_info.value.threat_level == 'critical'


class TestChallengeHandlerReceivesResult:
    """Test challenge handler receives ProtectionResult."""

    def test_challenge_handler_receives_full_result(self):
        """Challenge handler receives complete ProtectionResult."""
        received_result = None
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="high", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def capture_result(result):
            nonlocal received_result
            received_result = result
            return True
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=capture_result,
        )
        def process_input(text: str) -> str:
            return text
        
        process_input('Input')
        
        assert received_result is not None
        assert received_result.threat_level == 'high'
        assert received_result.is_threat is True
        assert isinstance(received_result, ProtectionResult)

    def test_challenge_handler_receives_threat_details(self):
        """Challenge handler can access specific threat information."""
        threat_types_received = []
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def inspect_threats(result):
            threat_types_received.extend(result.threats_detected)
            return True
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=inspect_threats,
        )
        def process_input(text: str) -> str:
            return text
        
        process_input('Input')
        
        assert len(threat_types_received) > 0


# =============================================================================
# Block Handler Tests (Decorator Pattern)
# =============================================================================

class TestBlockHandlerExecution:
    """Test block_action handler is called when blocking.
    
    Note: For block_action to be called by the decorator, the API must NOT
    return final_action="warn" (which would cause check() to throw immediately).
    Instead, API returns is_threat=True with final_action="warn" or similar,
    and the decorator's on_violation="block" decides to block.
    """

    def test_block_handler_called_before_raise(self):
        """block_action handler is called before ThreatBlockedError."""
        handler_called = False
        
        mock_response = Mock()
        # API returns threat but doesn't block - decorator decides to block
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="high", final_action="warn"
        )
        mock_response.raise_for_status = Mock()
        
        def block_handler(result):
            nonlocal handler_called
            handler_called = True
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='block',
            block_action=block_handler,
        )
        def process_input(text: str) -> str:
            return text
        
        with pytest.raises(ThreatBlockedError):
            process_input('Malicious input')
        
        assert handler_called is True

    def test_block_handler_receives_result(self):
        """block_action handler receives ProtectionResult."""
        received_result = None
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="critical", final_action="warn"
        )
        mock_response.raise_for_status = Mock()
        
        def capture_block_result(result):
            nonlocal received_result
            received_result = result
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='block',
            block_action=capture_block_result,
        )
        def process_input(text: str) -> str:
            return text
        
        with pytest.raises(ThreatBlockedError):
            process_input('Input')
        
        assert received_result is not None
        assert received_result.threat_level == 'critical'
        assert received_result.is_threat is True

    def test_block_handler_not_called_when_allowed(self):
        """block_action handler is NOT called when no threat detected."""
        handler_called = False
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=False, threat_level="none", final_action="allow"
        )
        mock_response.raise_for_status = Mock()
        
        def should_not_be_called(result):
            nonlocal handler_called
            handler_called = True
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='block',
            block_action=should_not_be_called,
        )
        def process_input(text: str) -> str:
            return text
        
        result = process_input('Safe input')
        
        assert result == 'Safe input'
        assert handler_called is False


class TestBlockHandlerErrorHandling:
    """Test error handling in block_action callbacks."""

    def test_block_still_raises_if_handler_fails(self):
        """ThreatBlockedError is raised even if block_action handler fails."""
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="high", final_action="warn"
        )
        mock_response.raise_for_status = Mock()
        
        def failing_handler(result):
            raise RuntimeError('Handler failed')
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='block',
            block_action=failing_handler,
        )
        def process_input(text: str) -> str:
            return text
        
        # Should still raise ThreatBlockedError, not RuntimeError
        with pytest.raises(ThreatBlockedError):
            process_input('Test')


class TestBlockHandlerUseCases:
    """Test real-world use cases for block_action."""

    def test_block_handler_for_alerting(self):
        """block_action can be used to send security alerts."""
        alerts_sent = []
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="critical", final_action="warn"
        )
        mock_response.raise_for_status = Mock()
        
        def send_alert(result):
            alerts_sent.append({
                'level': result.threat_level,
                'threats': result.threats_detected,
            })
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='block',
            block_action=send_alert,
        )
        def process_input(text: str) -> str:
            return text
        
        with pytest.raises(ThreatBlockedError):
            process_input('Attack attempt')
        
        assert len(alerts_sent) == 1
        assert alerts_sent[0]['level'] == 'critical'

    def test_block_handler_for_logging(self):
        """block_action can be used for audit logging."""
        audit_log = []
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="high", final_action="warn"
        )
        mock_response.raise_for_status = Mock()
        
        def log_blocked_request(result):
            audit_log.append({
                'action': 'blocked',
                'threat_level': result.threat_level,
                'confidence': result.confidence,
            })
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='block',
            block_action=log_blocked_request,
        )
        def process_input(text: str) -> str:
            return text
        
        with pytest.raises(ThreatBlockedError):
            process_input('Suspicious')
        
        assert len(audit_log) == 1
        assert audit_log[0]['action'] == 'blocked'


# =============================================================================
# Combined Challenge and Block Handler Tests
# =============================================================================

class TestCombinedHandlers:
    """Test challenge_action and block_action used together."""

    def test_block_handler_called_when_challenge_rejects(self):
        """block_action is called when challenge_action rejects."""
        challenge_called = False
        block_called = False
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def reject_challenge(result):
            nonlocal challenge_called
            challenge_called = True
            return False  # Reject -> triggers block
        
        def on_block(result):
            nonlocal block_called
            block_called = True
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=reject_challenge,
            block_action=on_block,
        )
        def process_input(text: str) -> str:
            return text
        
        with pytest.raises(ThreatBlockedError):
            process_input('Test')
        
        assert challenge_called is True
        assert block_called is True

    def test_block_handler_not_called_when_challenge_approves(self):
        """block_action is NOT called when challenge_action approves."""
        block_called = False
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def approve_challenge(result):
            return True  # Approve
        
        def should_not_be_called(result):
            nonlocal block_called
            block_called = True
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=approve_challenge,
            block_action=should_not_be_called,
        )
        def process_input(text: str) -> str:
            return text
        
        # Request proceeds, no block
        result = process_input('Test')
        assert result == 'Test'
        assert block_called is False


# =============================================================================
# Edge Cases
# =============================================================================

class TestHandlerEdgeCases:
    """Test edge cases for callback handlers."""

    def test_challenge_handler_returns_truthy_value(self):
        """Non-boolean truthy values are treated as True."""
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=lambda r: 1,  # Return 1 instead of True
        )
        def process_input(text: str) -> str:
            return text
        
        # Should not raise
        result = process_input('Test')
        assert result is not None

    def test_challenge_handler_returns_falsy_value(self):
        """Non-boolean falsy values are treated as False."""
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            challenge_action=lambda r: 0,  # Return 0 instead of False
        )
        def process_input(text: str) -> str:
            return text
        
        with pytest.raises(ThreatBlockedError):
            process_input('Test')

    def test_handlers_work_with_context_id(self):
        """Handlers work correctly with context_id tracking."""
        challenge_results = []
        
        mock_response = Mock()
        mock_response.json.return_value = mock_api_response(
            is_threat=True, threat_level="medium", final_action="challenge"
        )
        mock_response.raise_for_status = Mock()
        
        def track_challenge(result):
            challenge_results.append(result)
            return True
        
        guard = ToolGuard(api_key='test')
        patch.object(guard.client, "request", return_value=mock_response).__enter__()
        
        @guard.protect(
            on_violation='challenge',
            context_id='session-123',
            challenge_action=track_challenge,
        )
        def process_input(text: str) -> str:
            return text
        
        process_input('Message 1')
        process_input('Message 2')
        
        assert len(challenge_results) == 2


# =============================================================================
# Async Handler Tests - Skipped (requires pytest-asyncio)
# =============================================================================

class TestAsyncDecoratorWithHandlers:
    """Test callback handlers with async decorated functions.
    
    Note: These tests require pytest-asyncio plugin. Skip if not installed.
    """

    @pytest.mark.skip(reason="requires pytest-asyncio plugin")
    async def test_challenge_handler_with_async_function(self):
        """Challenge handler works with async decorated functions."""
        pass

    @pytest.mark.skip(reason="requires pytest-asyncio plugin")
    async def test_block_handler_with_async_function(self):
        """Block handler works with async decorated functions."""
        pass
