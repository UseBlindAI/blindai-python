"""Unit tests for SDK client."""

import pytest
from unittest.mock import Mock, patch

from blindai import (
    APIError,
    ConfigurationError,
    ProtectionResult,
    ThreatBlockedError,
    ToolGuard,
)


class TestToolGuardInitialization:
    """Test ToolGuard initialization."""

    def test_default_initialization(self):
        """Test initialization with defaults."""
        guard = ToolGuard()

        assert guard.config.base_url == "http://localhost:8000"
        assert guard.config.timeout == 10.0
        assert guard.config.max_retries == 3
        assert guard.config.fail_open is False
        assert guard.client is not None

    def test_custom_initialization(self):
        """Test initialization with custom config."""
        guard = ToolGuard(
            api_key="test-key",
            base_url="https://api.blindai.dev",
            timeout=5.0,
            max_retries=5,
            fail_open=True,
        )

        assert guard.config.api_key == "test-key"
        assert guard.config.base_url == "https://api.blindai.dev"
        assert guard.config.timeout == 5.0
        assert guard.config.max_retries == 5
        assert guard.config.fail_open is True

    def test_invalid_timeout(self):
        """Test initialization with invalid timeout."""
        with pytest.raises(ConfigurationError):
            ToolGuard(timeout=-1.0)

    def test_invalid_max_retries(self):
        """Test initialization with invalid max_retries."""
        with pytest.raises(ConfigurationError):
            ToolGuard(max_retries=-1)

    def test_context_manager(self):
        """Test context manager support."""
        with ToolGuard() as guard:
            assert guard is not None
            assert guard.client is not None


class TestCheckMethod:
    """Test check() method."""

    def test_check_benign_text(self, mocker):
        """Test checking benign text."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": False,
            "threat_level": "none",
            "final_action": "allow",
            "confidence": 0.0,
            "threats_detected": [],
            "processing_time_ms": 1.2,
        }
        mock_response.raise_for_status = Mock()

        mocker.patch.object(guard.client, "request", return_value=mock_response)

        result = guard.check("Hello world")

        assert isinstance(result, ProtectionResult)
        assert result.is_threat is False
        assert result.threat_level == "none"
        assert result.final_action == "allow"

    def test_check_blocked_threat(self, mocker):
        """Test checking blocked threat."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": True,
            "threat_level": "critical",
            "final_action": "block",
            "confidence": 0.95,
            "threats_detected": [
                {"source": "static", "type": "sql_injection", "confidence": 0.95}
            ],
            "processing_time_ms": 1.5,
        }
        mock_response.raise_for_status = Mock()

        mocker.patch.object(guard.client, "request", return_value=mock_response)

        with pytest.raises(ThreatBlockedError) as exc_info:
            guard.check("DROP TABLE users")

        assert exc_info.value.threat_level == "critical"
        assert len(exc_info.value.threats) > 0

    def test_check_with_context_id(self, mocker):
        """Test checking with context ID."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": False,
            "threat_level": "none",
            "final_action": "allow",
            "confidence": 0.0,
            "threats_detected": [],
        }
        mock_response.raise_for_status = Mock()

        mock_request = mocker.patch.object(guard.client, "request", return_value=mock_response)

        guard.check("Hello", context_id="session-123")

        # Verify context_id was passed
        call_args = mock_request.call_args
        assert call_args[1]["json"]["context_id"] == "session-123"

    def test_check_with_metadata(self, mocker):
        """Test checking with metadata."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": False,
            "threat_level": "none",
            "final_action": "allow",
            "confidence": 0.0,
            "threats_detected": [],
        }
        mock_response.raise_for_status = Mock()

        mock_request = mocker.patch.object(guard.client, "request", return_value=mock_response)

        guard.check("Hello", metadata={"user_id": "123"})

        # Verify metadata was passed
        call_args = mock_request.call_args
        assert call_args[1]["json"]["metadata"]["user_id"] == "123"


class TestProtectDecorator:
    """Test @protect decorator."""

    def test_protect_allows_safe_input(self, mocker):
        """Test decorator allows safe input."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": False,
            "threat_level": "none",
            "final_action": "allow",
            "confidence": 0.0,
            "threats_detected": [],
        }
        mock_response.raise_for_status = Mock()

        mocker.patch.object(guard.client, "request", return_value=mock_response)

        @guard.protect
        def test_func(query: str):
            return f"Executed: {query}"

        result = test_func("SELECT * FROM users")
        assert result == "Executed: SELECT * FROM users"

    def test_protect_blocks_threat(self, mocker):
        """Test decorator blocks threat."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": True,
            "threat_level": "critical",
            "final_action": "block",
            "confidence": 0.95,
            "threats_detected": [{"source": "static", "type": "sql_injection"}],
        }
        mock_response.raise_for_status = Mock()

        mocker.patch.object(guard.client, "request", return_value=mock_response)

        @guard.protect
        def test_func(query: str):
            return f"Executed: {query}"

        with pytest.raises(ThreatBlockedError):
            test_func("DROP TABLE users")

    def test_protect_with_context_id(self, mocker):
        """Test decorator with context ID."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": False,
            "threat_level": "none",
            "final_action": "allow",
            "confidence": 0.0,
            "threats_detected": [],
        }
        mock_response.raise_for_status = Mock()

        mock_request = mocker.patch.object(guard.client, "request", return_value=mock_response)

        @guard.protect(context_id="session-123")
        def test_func(query: str):
            return f"Executed: {query}"

        test_func("SELECT * FROM users")

        # Verify context_id was passed
        call_args = mock_request.call_args
        assert call_args[1]["json"]["context_id"] == "session-123"

    def test_protect_no_text_argument(self, mocker):
        """Test decorator with no text argument."""
        guard = ToolGuard()

        @guard.protect
        def test_func(value: int):
            return value * 2

        with pytest.raises(ValueError, match="No text argument found"):
            test_func(42)


class TestCallToolMethod:
    """Test call_tool() method."""

    def test_call_tool_allows_safe_input(self, mocker):
        """Test call_tool allows safe input."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": False,
            "threat_level": "none",
            "final_action": "allow",
            "confidence": 0.0,
            "threats_detected": [],
        }
        mock_response.raise_for_status = Mock()

        mocker.patch.object(guard.client, "request", return_value=mock_response)

        def test_func(query: str):
            return f"Executed: {query}"

        result = guard.call_tool(test_func, "SELECT * FROM users")
        assert result == "Executed: SELECT * FROM users"

    def test_call_tool_blocks_threat(self, mocker):
        """Test call_tool blocks threat."""
        guard = ToolGuard()

        # Mock HTTP response
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": True,
            "threat_level": "critical",
            "final_action": "block",
            "confidence": 0.95,
            "threats_detected": [{"source": "static", "type": "sql_injection"}],
        }
        mock_response.raise_for_status = Mock()

        mocker.patch.object(guard.client, "request", return_value=mock_response)

        def test_func(query: str):
            return f"Executed: {query}"

        with pytest.raises(ThreatBlockedError):
            guard.call_tool(test_func, "DROP TABLE users")


class TestRetryLogic:
    """Test retry logic."""

    def test_retry_on_timeout(self, mocker):
        """Test retry on timeout."""
        guard = ToolGuard(max_retries=2, retry_backoff=0.1)

        import httpx

        # Mock first two calls to timeout, third succeeds
        mock_response = Mock()
        mock_response.json.return_value = {
            "is_threat": False,
            "threat_level": "none",
            "final_action": "allow",
            "confidence": 0.0,
            "threats_detected": [],
        }
        mock_response.raise_for_status = Mock()

        mock_request = mocker.patch.object(guard.client, "request")
        mock_request.side_effect = [
            httpx.TimeoutException("Timeout"),
            httpx.TimeoutException("Timeout"),
            mock_response,
        ]

        result = guard.check("Hello")
        assert result.is_threat is False
        assert mock_request.call_count == 3

    def test_fail_open_on_error(self, mocker):
        """Test fail-open mode on error."""
        guard = ToolGuard(fail_open=True, max_retries=1)

        import httpx

        mock_request = mocker.patch.object(guard.client, "request")
        mock_request.side_effect = httpx.TimeoutException("Timeout")

        # Should not raise, returns safe default
        result = guard.check("Hello")
        assert result.is_threat is False
        assert result.final_action == "allow"
        assert result.metadata.get("fail_mode") == "open"

    def test_fail_closed_on_error(self, mocker):
        """Test fail-closed mode on error."""
        guard = ToolGuard(fail_open=False, max_retries=1)

        import httpx
        from blindai.exceptions import TimeoutError

        mock_request = mocker.patch.object(guard.client, "request")
        mock_request.side_effect = httpx.TimeoutException("Timeout")

        with pytest.raises(TimeoutError):
            guard.check("Hello")


class TestCleanup:
    """Test resource cleanup."""

    def test_close_method(self):
        """Test close() method."""
        guard = ToolGuard()
        guard.close()
        # Should not raise error

    def test_context_manager_cleanup(self):
        """Test context manager cleanup."""
        with ToolGuard() as guard:
            pass
        # Should close client automatically


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
