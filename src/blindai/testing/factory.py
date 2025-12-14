"""Factory function for creating test guards."""

from typing import Any, Optional, Union

from .models import MockConfig
from .mock import MockGuard
from .recording import RecordingGuard
from .replay import ReplayGuard


def create_test_guard(
    mode: str = "mock",
    mock_config: Optional[MockConfig] = None,
    recordings_file: Optional[str] = None,
    real_guard: Optional[Any] = None,
) -> Union[MockGuard, RecordingGuard, ReplayGuard]:
    """Create a test guard with specified mode.
    
    Args:
        mode: Test mode - "mock", "record", or "replay"
        mock_config: Configuration for mock mode
        recordings_file: File path for replay mode
        real_guard: Real guard for recording mode
        
    Returns:
        Appropriate test guard instance
        
    Example:
        ```python
        from blindai.testing import create_test_guard, MockConfig
        
        # Mock mode
        guard = create_test_guard("mock", mock_config=MockConfig.block())
        
        # Recording mode
        real_guard = ToolGuard(base_url="http://localhost:8000")
        guard = create_test_guard("record", real_guard=real_guard)
        
        # Replay mode
        guard = create_test_guard("replay", recordings_file="tests.json")
        ```
    """
    if mode == "mock":
        return MockGuard(default_config=mock_config)
    elif mode == "record":
        if real_guard is None:
            raise ValueError("real_guard required for record mode")
        return RecordingGuard(real_guard)
    elif mode == "replay":
        if recordings_file is None:
            raise ValueError("recordings_file required for replay mode")
        return ReplayGuard.from_file(recordings_file)
    else:
        raise ValueError(f"Unknown mode: {mode}")
