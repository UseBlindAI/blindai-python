"""Testing utilities for Blind AI SDK.

Provides mock mode, recording mode, and test fixtures for easy testing.

Example:
    Basic mock testing::
    
        from blindai import Guard
        from blindai.testing import MockBlindAI
        
        with MockBlindAI():
            guard = Guard(api_key="test")
            result = guard.check("user input")
            assert result.is_allowed()
    
    Advanced mock with rules::
    
        from blindai.testing import MockBlindAI, MockConfig
        
        with MockBlindAI() as mock:
            mock.configure(rules={
                "DROP TABLE": MockConfig.block(threat_level="critical"),
            })
            # Test your code...
    
    Recording mode for replay testing::
    
        from blindai.testing import RecordingGuard
        
        guard = RecordingGuard(api_key="real_key")
        # Make real calls that get recorded
        guard.save_recordings("tests/fixtures/recordings.json")
"""

from .models import MockConfig, RecordedCheck
from .mock import MockBlindAI, MockGuard
from .recording import RecordingGuard
from .replay import ReplayGuard
from .factory import create_test_guard

__all__ = [
    # Context manager (recommended)
    "MockBlindAI",
    # Models
    "MockConfig",
    "RecordedCheck",
    # Guards
    "MockGuard",
    "RecordingGuard",
    "ReplayGuard",
    # Factory
    "create_test_guard",
]
