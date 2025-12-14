"""Mock guard for testing without making real API calls."""

import inspect
import time
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Callable, Dict, Generator, List, Optional, Type

from ..client import ProgressMetadata
from ..exceptions import ThreatBlockedError
from ..models import ProtectionResult
from .models import MockConfig


# Module-level state for MockBlindAI context manager
_mock_active: bool = False
_mock_config: Optional[MockConfig] = None
_mock_rules: Dict[str, MockConfig] = {}


class MockBlindAI:
    """Context manager for mocking BlindAI SDK in tests.
    
    Provides a clean way to test code that uses the Guard/ToolGuard SDK
    without making real API calls.
    
    Example:
        Basic usage::
        
            from blindai import Guard
            from blindai.testing import MockBlindAI
            
            with MockBlindAI():
                guard = Guard(api_key="test_key")
                result = guard.check("test input")
                assert not result.is_threat  # Default: allow all
        
        Configure to block::
        
            from blindai.testing import MockBlindAI, MockConfig
            
            with MockBlindAI(MockConfig.block(threat_level="high")):
                guard = Guard(api_key="test_key")
                try:
                    guard.check("malicious input")
                except ThreatBlockedError as e:
                    assert e.threat_level == "high"
        
        Add rules for specific patterns::
        
            with MockBlindAI() as mock:
                mock.configure(
                    rules={
                        "DROP TABLE": MockConfig.block(threat_level="critical"),
                        "SELECT": MockConfig.allow(),
                    }
                )
                
                guard = Guard(api_key="test_key")
                result = guard.check("SELECT * FROM users")
                assert result.is_allowed()
    """
    
    def __init__(
        self,
        default_config: Optional[MockConfig] = None,
    ):
        """Initialize MockBlindAI.
        
        Args:
            default_config: Default configuration for all checks.
                If None, defaults to allowing all requests.
        """
        self._default_config = default_config or MockConfig.allow()
        self._rules: Dict[str, MockConfig] = {}
        self._previous_active: bool = False
        self._previous_config: Optional[MockConfig] = None
        self._previous_rules: Dict[str, MockConfig] = {}
    
    def __enter__(self) -> "MockBlindAI":
        """Enter mock context."""
        global _mock_active, _mock_config, _mock_rules
        
        # Save previous state
        self._previous_active = _mock_active
        self._previous_config = _mock_config
        self._previous_rules = _mock_rules.copy()
        
        # Set new state
        _mock_active = True
        _mock_config = self._default_config
        _mock_rules = self._rules.copy()
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit mock context."""
        global _mock_active, _mock_config, _mock_rules
        
        # Restore previous state
        _mock_active = self._previous_active
        _mock_config = self._previous_config
        _mock_rules = self._previous_rules
        
        return False
    
    def configure(
        self,
        default: Optional[MockConfig] = None,
        rules: Optional[Dict[str, MockConfig]] = None,
    ) -> None:
        """Configure mock behavior.
        
        Args:
            default: Default config for unmatched requests
            rules: Dictionary mapping patterns to configs
            
        Example:
            mock.configure(
                default=MockConfig.allow(),
                rules={
                    "DROP": MockConfig.block(),
                    "DELETE": MockConfig.block(),
                }
            )
        """
        global _mock_config, _mock_rules
        
        if default is not None:
            _mock_config = default
        
        if rules is not None:
            _mock_rules.update({k.lower(): v for k, v in rules.items()})
    
    @staticmethod
    def is_active() -> bool:
        """Check if mock mode is active."""
        return _mock_active
    
    @staticmethod
    def get_config(text: str) -> MockConfig:
        """Get mock config for given text.
        
        Args:
            text: Text to match against rules
            
        Returns:
            Matching MockConfig or default config
        """
        if not _mock_active:
            raise RuntimeError("MockBlindAI not active. Use 'with MockBlindAI():' context.")
        
        text_lower = text.lower()
        for pattern, config in _mock_rules.items():
            if pattern in text_lower:
                return config
        
        return _mock_config or MockConfig.allow()


class MockGuard:
    """Mock guard for testing without making real API calls.
    
    Simulates ToolGuard behavior with configurable responses.
    
    Example:
        ```python
        from blindai.testing import MockGuard, MockConfig
        
        # Always allow
        guard = MockGuard()
        result = guard.check("SELECT * FROM users")
        assert not result.is_threat
        
        # Always block
        guard = MockGuard(MockConfig.block())
        try:
            guard.check("DROP TABLE users")
        except ThreatBlockedError:
            print("Blocked as expected!")
        
        # Custom behavior per input
        guard = MockGuard()
        guard.add_rule("DROP", MockConfig.block(threat_level="critical"))
        guard.add_rule("SELECT", MockConfig.allow())
        ```
    """
    
    def __init__(
        self,
        default_config: Optional[MockConfig] = None,
        rules: Optional[Dict[str, MockConfig]] = None,
    ):
        """Initialize mock guard.
        
        Args:
            default_config: Default mock configuration
            rules: Dictionary mapping text patterns to configs
        """
        self.default_config = default_config or MockConfig.allow()
        self.rules: Dict[str, MockConfig] = rules or {}
        self.call_history: List[Dict[str, Any]] = []
    
    def add_rule(self, pattern: str, config: MockConfig) -> None:
        """Add a rule for specific text patterns.
        
        Args:
            pattern: Text pattern to match (case-insensitive substring)
            config: MockConfig to use when pattern matches
        """
        self.rules[pattern.lower()] = config
    
    def clear_rules(self) -> None:
        """Clear all rules."""
        self.rules.clear()
    
    def clear_history(self) -> None:
        """Clear call history."""
        self.call_history.clear()
    
    def _get_config(self, text: str) -> MockConfig:
        """Get config for given text, checking rules first."""
        text_lower = text.lower()
        for pattern, config in self.rules.items():
            if pattern in text_lower:
                return config
        return self.default_config
    
    def check(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[Any] = None,
    ) -> ProtectionResult:
        """Mock check that returns configured result.
        
        Args:
            text: Text to check
            context_id: Optional context ID
            metadata: Optional metadata
            user: Optional user context
            
        Returns:
            Configured ProtectionResult
            
        Raises:
            ThreatBlockedError: If configured to block
            Exception: If raise_error is set in config
        """
        config = self._get_config(text)
        
        # Record the call
        self.call_history.append({
            "text": text,
            "context_id": context_id,
            "metadata": metadata,
            "user_id": user.user_id if user and hasattr(user, 'user_id') else None,
            "config_used": config,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        # Simulate latency
        if config.latency_ms > 0:
            time.sleep(config.latency_ms / 1000)
        
        # Raise error if configured
        if config.raise_error:
            raise config.raise_error
        
        # Build result
        result = ProtectionResult(
            is_threat=config.is_threat,
            threat_level=config.threat_level,
            final_action=config.final_action,
            threats_detected=config.threats_detected,
            confidence=config.confidence,
            processing_time_ms=config.latency_ms,
            metadata={"mock": True},
        )
        
        # Raise if blocking
        if config.final_action == "block":
            raise ThreatBlockedError(
                message=f"Mock blocked: {config.threat_level}",
                threat_level=config.threat_level,
                threats=config.threats_detected,
                response={"mock": True},
            )
        
        return result
    
    def check_batch(
        self,
        items: List[Dict[str, Any]],
        fail_fast: bool = False,
        parallel: bool = True,
        on_progress: Optional[Callable] = None,
    ) -> List[ProtectionResult]:
        """Mock batch check with progress metadata support.
        
        Args:
            items: List of check items
            fail_fast: Stop on first threat
            parallel: Ignored in mock
            on_progress: Optional progress callback. Can be:
                - Simple: func(completed, total)
                - With metadata: func(completed, total, metadata)
            
        Returns:
            List of ProtectionResults
        """
        results = []
        total = len(items)
        threats_detected = 0
        blocked_count = 0
        total_latency_ms = 0.0
        errors_count = 0
        
        # Check if callback accepts metadata
        accepts_metadata = False
        if on_progress:
            try:
                sig = inspect.signature(on_progress)
                accepts_metadata = len(sig.parameters) >= 3
            except (ValueError, TypeError):
                pass
        
        for i, item in enumerate(items):
            item_start = time.time()
            try:
                result = self.check(
                    text=item["text"],
                    context_id=item.get("context_id"),
                    metadata=item.get("metadata"),
                    user=item.get("user"),
                )
                results.append(result)
                
                if result.is_threat:
                    threats_detected += 1
                    
            except ThreatBlockedError as e:
                blocked_count += 1
                threats_detected += 1
                if fail_fast:
                    raise
                # For non-fail-fast, we still need to record it somehow
                results.append(ProtectionResult(
                    is_threat=True,
                    threat_level=e.threat_level,
                    final_action="block",
                    threats_detected=e.threats,
                    confidence=0.95,
                    processing_time_ms=0,
                    metadata={"mock": True, "blocked": True},
                ))
            
            item_latency = (time.time() - item_start) * 1000
            total_latency_ms += item_latency
            completed = i + 1
            
            # Report progress
            if on_progress:
                if accepts_metadata:
                    text = item.get("text", "")
                    preview = text[:50] + "..." if len(text) > 50 else text
                    metadata = ProgressMetadata(
                        threats_detected=threats_detected,
                        blocked_count=blocked_count,
                        avg_latency_ms=total_latency_ms / completed,
                        total_latency_ms=total_latency_ms,
                        current_item_preview=preview,
                        current_index=i,
                        errors_count=errors_count,
                    )
                    on_progress(completed, total, metadata)
                else:
                    on_progress(completed, total)
        
        return results
    
    def assert_called(self, times: Optional[int] = None) -> None:
        """Assert that check was called.
        
        Args:
            times: If provided, assert exact number of calls
        """
        if times is not None:
            assert len(self.call_history) == times, \
                f"Expected {times} calls, got {len(self.call_history)}"
        else:
            assert len(self.call_history) > 0, "Expected at least one call"
    
    def assert_called_with(self, text: str) -> None:
        """Assert that check was called with specific text.
        
        Args:
            text: Text to look for in call history
        """
        texts = [call["text"] for call in self.call_history]
        assert text in texts, f"Expected call with '{text}', got: {texts}"
    
    def assert_not_called(self) -> None:
        """Assert that check was never called."""
        assert len(self.call_history) == 0, \
            f"Expected no calls, got {len(self.call_history)}"
