"""Guard - User-friendly alias for ToolGuard.

This module provides the ``Guard`` class as the primary user-facing API
for BlindAI SDK, with full type hints and IDE autocomplete support.

Example:
    ```python
    from blindai import Guard
    from typing import List, Dict

    guard = Guard(api_key="...")

    @guard.protect(
        policies=["pii", "prompt_injection"],  # ← Autocomplete available
        on_violation="block"  # ← Type hints show valid values
    )
    def chat(messages: List[Dict[str, str]]) -> str:
        '''Your docstring here'''
        return llm.generate(messages)
    ```
"""

from typing import Any, Callable, Dict, List, Optional, Union, overload, TYPE_CHECKING

from .client import ToolGuard
from .circuit_breaker import CircuitBreakerConfig
from .models import ProtectionResult

if TYPE_CHECKING:
    from .types import Policy, ViolationAction, TierMode, ThreatLevel


class Guard(ToolGuard):
    """Security guard for protecting AI/LLM tool calls.
    
    The Guard class provides easy-to-use security protection for any function
    or tool that processes user input. It detects threats like prompt injection,
    PII disclosure, SQL injection, and more.
    
    This is the recommended entry point for using the BlindAI SDK.
    
    Args:
        api_key: Your BlindAI API key. Get one at https://blindai.dev
        base_url: API endpoint URL. Defaults to production.
        timeout: Request timeout in seconds. Default: 10.0
        max_retries: Maximum retry attempts on failure. Default: 3
        retry_backoff: Backoff multiplier between retries. Default: 0.5
        fail_open: If True, allow requests when API is unavailable.
            If False (default), block requests on error.
        verify_ssl: Verify SSL certificates. Default: True
        circuit_breaker: Optional circuit breaker config for resilience.
    
    Example:
        Basic initialization::
        
            from blindai import Guard
            
            guard = Guard(api_key="blind_xxxxx")
        
        With custom settings::
        
            guard = Guard(
                api_key="blind_xxxxx",
                timeout=5.0,
                fail_open=True,  # Allow on API errors
            )
        
        As context manager (recommended)::
        
            with Guard(api_key="blind_xxxxx") as guard:
                result = guard.check("user input")
                # Resources automatically cleaned up
    
    Attributes:
        config: SDK configuration settings
        hooks: Event hooks for custom callbacks
        circuit_breaker: Circuit breaker instance if configured
    
    See Also:
        - :meth:`protect`: Decorator for protecting functions
        - :meth:`check`: Manual threat detection
        - :meth:`check_batch`: Batch threat detection
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://web-production-b14fb.up.railway.app",
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_backoff: float = 0.5,
        fail_open: bool = False,
        verify_ssl: bool = True,
        circuit_breaker: Optional[CircuitBreakerConfig] = None,
        sandbox: bool = False,
    ) -> None:
        """Initialize Guard with API credentials and options.
        
        Args:
            api_key: Your BlindAI API key. If not provided, will check
                BLINDAI_API_KEY environment variable.
            base_url: API endpoint URL.
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts on transient failures.
            retry_backoff: Multiplier for exponential backoff between retries.
            fail_open: Behavior when API unavailable:
                
                - ``False`` (default): Block all requests (secure)
                - ``True``: Allow requests through (available)
                
            verify_ssl: Whether to verify SSL certificates.
            circuit_breaker: Optional :class:`CircuitBreakerConfig` for
                automatic failure handling and recovery.
            sandbox: Enable sandbox mode for testing. Sandbox mode:
            
                - Returns predictable responses for testing
                - Does not count against rate limits  
                - Uses mock threat detection
                - No API key required
            sandbox: Enable sandbox mode for testing. Sandbox mode:
            
                - Returns predictable responses for testing
                - Does not count against rate limits  
                - Uses mock threat detection
                - No API key required
        
        Raises:
            ConfigurationError: If configuration is invalid (e.g., negative timeout).
        
        Example:
            Production setup with circuit breaker::
            
                from blindai import Guard
                from blindai import CircuitBreakerConfig
                
                guard = Guard(
                    api_key="blind_xxxxx",
                    circuit_breaker=CircuitBreakerConfig(
                        failure_threshold=5,
                        timeout=30.0,
                    ),
                )
        """
        # Use sandbox URL if sandbox mode enabled
        effective_url = "https://web-production-b14fb.up.railway.app/sandbox" if sandbox else base_url
        
        super().__init__(
            api_key=api_key or ("sandbox_key" if sandbox else None),
            base_url=effective_url,
            timeout=timeout,
            max_retries=max_retries,
            retry_backoff=retry_backoff,
            fail_open=fail_open,
            verify_ssl=verify_ssl,
            circuit_breaker=circuit_breaker,
        )

    # Override protect with better type hints for the primary use case
    @overload
    def protect(self, func: Callable) -> Callable:
        """Apply protection with defaults: @guard.protect"""
        ...

    @overload
    def protect(
        self,
        func: None = None,
        *,
        policies: Optional[List["Policy"]] = None,
        on_violation: "ViolationAction" = "block",
        context_id: Optional[str] = None,
        param: Optional[str] = None,
        mode: Optional["TierMode"] = None,
        agent_id: Optional[str] = None,
        auto_register: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Callable[[Callable], Callable]:
        """Apply protection with options: @guard.protect(policies=[...])"""
        ...

    def protect(
        self,
        func: Optional[Callable] = None,
        *,
        policies: Optional[List["Policy"]] = None,
        on_violation: "ViolationAction" = "block",
        context_id: Optional[str] = None,
        param: Optional[str] = None,
        mode: Optional["TierMode"] = None,
        agent_id: Optional[str] = None,
        auto_register: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Decorator to protect a function from security threats.
        
        Automatically scans function inputs for threats before execution.
        Supports both ``@guard.protect`` and ``@guard.protect(options)`` syntax.
        
        Args:
            func: Function to protect (when used as @guard.protect without parens).
            policies: Security policies to enforce. IDE autocomplete shows options:
            
                - ``"pii"``: Block personally identifiable information
                - ``"prompt_injection"``: Block prompt injection attempts
                - ``"jailbreak"``: Block jailbreak attempts
                - ``"sql_injection"``: Block SQL injection
                - ``"code_injection"``: Block code injection
                - ``"data_exfiltration"``: Block data extraction attempts
                - ``"all"``: Enable all policies (default)
                
            on_violation: Action when threat detected. Type hints show valid values:
            
                - ``"block"``: Raise ThreatBlockedError (default, recommended)
                - ``"warn"``: Log warning but allow execution
                - ``"log"``: Silently log for monitoring
                - ``"challenge"``: Trigger challenge handler
                - ``"allow"``: Allow despite threat (testing only)
                
            context_id: Session ID for tracking multi-turn conversations.
            param: Specific parameter to check. If None, checks all strings.
            mode: Detection tier mode:
            
                - ``"full"``: All detection tiers (default)
                - ``"fast"``: Skip ML for 10x speed
                
            agent_id: Agent ID for multi-agent orchestration.
            auto_register: Register function as tool in security registry.
            metadata: Additional metadata for audit logging.
        
        Returns:
            Decorated function with security protection.
        
        Raises:
            ThreatBlockedError: If threat detected and on_violation="block".
            ValueError: If no text argument found to protect.
        
        Example:
            Basic protection::
            
                @guard.protect
                def chat(message: str) -> str:
                    return llm.generate(message)
            
            With specific policies (IDE autocomplete works here!)::
            
                @guard.protect(
                    policies=["pii", "prompt_injection"],
                    on_violation="block",
                )
                def process_input(user_text: str) -> str:
                    return sanitize(user_text)
            
            Fast mode for high throughput::
            
                @guard.protect(mode="fast", on_violation="log")
                def batch_process(text: str) -> str:
                    return process(text)
        """
        return super().protect(
            func,
            policies=policies,
            on_violation=on_violation,
            context_id=context_id,
            param=param,
            mode=mode,
            agent_id=agent_id,
            auto_register=auto_register,
            metadata=metadata,
        )
    
    def check(
        self,
        text: str,
        *,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        policies: Optional[List["Policy"]] = None,
        mode: Optional["TierMode"] = None,
    ) -> ProtectionResult:
        """Check text for security threats.
        
        Scans the provided text through BlindAI's multi-tier detection system
        and returns detailed results about any threats found.
        
        Args:
            text: The text to scan for threats.
            context_id: Optional session ID for multi-turn conversation tracking.
                Enables detection of attack chains across multiple messages.
            metadata: Additional metadata to include with the check.
            policies: Specific policies to apply. If None, uses default policies.
                Valid values: ``"pii"``, ``"prompt_injection"``, ``"sql_injection"``, etc.
            mode: Detection tier mode:
            
                - ``"full"``: Run all tiers (Bloom + Aho-Corasick + ML)
                - ``"fast"``: Skip ML model for ~10x speed
        
        Returns:
            :class:`ProtectionResult` with detection details:
            
            - ``is_threat``: Whether any threat was detected
            - ``threat_level``: Severity ("none", "low", "medium", "high", "critical")
            - ``final_action``: Recommended action ("allow", "block", etc.)
            - ``confidence``: Detection confidence (0.0 to 1.0)
            - ``threats_detected``: List of specific threats found
            - ``processing_time_ms``: Detection latency
        
        Raises:
            APIError: If the API request fails.
            TimeoutError: If the request times out.
        
        Example:
            Basic check::
            
                result = guard.check("user input text")
                if result.is_threat:
                    print(f"Threat: {result.threat_level}")
            
            With policies::
            
                result = guard.check(
                    user_input,
                    policies=["pii", "prompt_injection"],
                )
            
            Fast mode for iteration::
            
                result = guard.check(text, mode="fast")
        """
        check_metadata = dict(metadata or {})
        if policies:
            check_metadata["policies"] = policies
        if mode:
            check_metadata["mode"] = mode
            
        return super().check(
            text,
            context_id=context_id,
            metadata=check_metadata if check_metadata else None,
        )


# Convenience alias
ToolGuard = Guard

__all__ = ["Guard", "ToolGuard"]
