"""Type definitions for BlindAI SDK.

This module provides comprehensive type hints for IDE autocomplete support,
runtime validation hints, and clear documentation of all valid values.

Example:
    ```python
    from blindai import Guard
    from blindai.types import Policy, ViolationAction, ThreatLevel

    guard = Guard(api_key="...")

    # IDE autocomplete shows valid policy values
    @guard.protect(
        policies=["pii", "prompt_injection"],  # ← Autocomplete available
        on_violation="block"  # ← Type hints show: block, warn, log, challenge
    )
    def chat(messages: list[dict[str, str]]) -> str:
        ...
    ```
"""

from typing import (
    Any,
    Callable,
    Dict,
    List,
    Literal,
    Optional,
    Protocol,
    TypedDict,
    Union,
    TYPE_CHECKING,
)

# =============================================================================
# Literal Types - Use these for autocomplete on string parameters
# =============================================================================

Policy = Literal[
    "pii",
    "prompt_injection",
    "jailbreak",
    "sql_injection",
    "code_injection",
    "xss",
    "ssrf",
    "data_exfiltration",
    "sensitive_topics",
    "toxicity",
    "bias",
    "hallucination",
    "off_topic",
    "all",
]
"""Valid security policies for protection.

- ``pii``: Detect personally identifiable information (SSN, credit cards, etc.)
- ``prompt_injection``: Detect attempts to override system instructions
- ``jailbreak``: Detect attempts to bypass safety guidelines
- ``sql_injection``: Detect SQL injection attacks
- ``code_injection``: Detect code injection attempts
- ``xss``: Detect cross-site scripting attempts
- ``ssrf``: Detect server-side request forgery
- ``data_exfiltration``: Detect data extraction attempts
- ``sensitive_topics``: Detect discussion of sensitive/restricted topics
- ``toxicity``: Detect toxic or harmful content
- ``bias``: Detect biased or discriminatory content
- ``hallucination``: Detect potential AI hallucinations
- ``off_topic``: Detect off-topic responses
- ``all``: Enable all policies
"""

ViolationAction = Literal["block", "warn", "log", "challenge", "allow"]
"""Actions to take when a security violation is detected.

- ``block``: Reject the request and raise ThreatBlockedError
- ``warn``: Log a warning but allow the request
- ``log``: Silently log for monitoring without interruption
- ``challenge``: Trigger challenge handler for human review
- ``allow``: Allow despite violation (for testing/debugging)
"""

ThreatLevel = Literal["none", "low", "medium", "high", "critical"]
"""Severity level of detected threats.

- ``none``: No threat detected
- ``low``: Minor issue, likely false positive
- ``medium``: Potential threat, warrants investigation
- ``high``: Confirmed threat, should be blocked
- ``critical``: Severe threat, immediate action required
"""

FinalAction = Literal["allow", "log", "warn", "challenge", "block"]
"""Final action determined after policy evaluation.

- ``allow``: Request is safe to proceed
- ``log``: Request allowed but logged for review
- ``warn``: Request allowed with warning emitted
- ``challenge``: Request requires human approval
- ``block``: Request denied
"""

TrustLevel = Literal["HIGH", "MEDIUM", "LOW"]
"""Trust level for registered tools.

- ``HIGH``: Trusted internal tools, minimal validation
- ``MEDIUM``: Semi-trusted tools, standard validation
- ``LOW``: Untrusted/external tools, strict validation
"""

ToolType = Literal[
    "DATABASE",
    "API", 
    "EMAIL",
    "COMMUNICATION",
    "FILE",
    "COMMAND",
    "BROWSER",
    "CODE_EXECUTION",
    "SEARCH",
    "RETRIEVAL",
    "CUSTOM",
]
"""Categories of tools for policy-based access control.

- ``DATABASE``: SQL/NoSQL database operations
- ``API``: External API calls
- ``EMAIL``: Email sending/reading
- ``COMMUNICATION``: Slack, Teams, SMS, etc.
- ``FILE``: File system operations
- ``COMMAND``: Shell/system commands
- ``BROWSER``: Web browser automation
- ``CODE_EXECUTION``: Dynamic code execution
- ``SEARCH``: Search engine queries
- ``RETRIEVAL``: RAG/document retrieval
- ``CUSTOM``: Custom tool types
"""

OutputFormat = Literal["text", "json", "csv", "table"]
"""Output format for CLI and API responses."""

TierMode = Literal["full", "fast", "tier1", "tier2", "tier3"]
"""Detection tier mode.

- ``full``: All tiers (Bloom + Aho-Corasick + ML)
- ``fast``: Tier 1-2 only (skip ML for speed)
- ``tier1``: Bloom filter only
- ``tier2``: Aho-Corasick only  
- ``tier3``: ML model only
"""

CircuitState = Literal["closed", "open", "half_open"]
"""Circuit breaker state for resilience.

- ``closed``: Normal operation, requests flow through
- ``open``: Circuit tripped, requests fail fast
- ``half_open``: Testing if service recovered
"""

LogStatus = Literal["allowed", "blocked", "warned", "error"]
"""Status of a logged request."""


# =============================================================================
# TypedDict Types - For structured dictionaries with autocomplete
# =============================================================================

class ThreatDetail(TypedDict, total=False):
    """Details about a detected threat."""
    
    type: str
    """Threat type (e.g., 'PROMPT_INJECTION', 'PII_SSN')."""
    
    confidence: float
    """Detection confidence from 0.0 to 1.0."""
    
    severity: ThreatLevel
    """Severity level of the threat."""
    
    description: str
    """Human-readable description of the threat."""
    
    matched_text: str
    """The text that triggered the detection."""
    
    position: int
    """Character position where threat was detected."""
    
    tier: int
    """Detection tier that caught this (1, 2, or 3)."""


class ProtectionResultDict(TypedDict, total=False):
    """Dictionary representation of protection check result."""
    
    is_threat: bool
    """Whether any threat was detected."""
    
    threat_level: ThreatLevel
    """Highest severity level among detected threats."""
    
    final_action: FinalAction
    """Recommended action based on policies."""
    
    confidence: float
    """Overall detection confidence from 0.0 to 1.0."""
    
    threats_detected: List[ThreatDetail]
    """List of specific threats found."""
    
    processing_time_ms: float
    """Time taken to process in milliseconds."""
    
    trace_id: str
    """Unique trace ID for this request."""
    
    metadata: Dict[str, Any]
    """Additional metadata from processing."""


class ToolMetadata(TypedDict, total=False):
    """Metadata for a registered tool."""
    
    name: str
    """Unique tool identifier."""
    
    trust_level: TrustLevel
    """Tool trust level for access control."""
    
    tool_type: ToolType
    """Category of the tool."""
    
    description: str
    """Human-readable description."""
    
    allowed_domains: List[str]
    """Domains this tool can access."""
    
    allowed_roles: List[str]
    """Roles permitted to use this tool."""
    
    rate_limit_per_minute: Optional[int]
    """Maximum calls per minute."""
    
    require_approval: bool
    """Whether calls need human approval."""


class CheckOptions(TypedDict, total=False):
    """Options for check() method."""
    
    context_id: str
    """Session/context ID for multi-turn tracking."""
    
    metadata: Dict[str, Any]
    """Additional metadata to include."""
    
    policies: List[Policy]
    """Specific policies to apply."""
    
    mode: TierMode
    """Detection tier mode."""
    
    timeout: float
    """Request timeout in seconds."""


class ProtectOptions(TypedDict, total=False):
    """Options for @protect decorator."""
    
    policies: List[Policy]
    """Security policies to apply (e.g., ['pii', 'prompt_injection'])."""
    
    on_violation: ViolationAction
    """Action to take when violation detected."""
    
    param: str
    """Specific parameter name to check."""
    
    context_id: str
    """Session/context ID for tracking."""
    
    mode: TierMode
    """Detection tier mode."""
    
    agent_id: str
    """Agent ID for multi-agent setups."""
    
    auto_register: bool
    """Whether to auto-register the tool."""
    
    metadata: Dict[str, Any]
    """Additional metadata for logging."""


class BatchResult(TypedDict):
    """Result from batch checking multiple texts."""
    
    total: int
    """Total number of texts checked."""
    
    safe: int
    """Number of safe texts."""
    
    blocked: int
    """Number of blocked texts."""
    
    warned: int
    """Number of warned texts."""
    
    results: List[ProtectionResultDict]
    """Individual results for each text."""
    
    processing_time_ms: float
    """Total processing time."""


class SDKConfigDict(TypedDict, total=False):
    """Configuration dictionary for SDK initialization."""
    
    api_key: str
    """API key for authentication."""
    
    base_url: str
    """Base URL for API endpoint."""
    
    timeout: float
    """Request timeout in seconds."""
    
    max_retries: int
    """Maximum retry attempts."""
    
    retry_backoff: float
    """Backoff multiplier for retries."""
    
    fail_open: bool
    """Allow on error (True) or block on error (False)."""
    
    verify_ssl: bool
    """Whether to verify SSL certificates."""


class CircuitBreakerConfigDict(TypedDict, total=False):
    """Circuit breaker configuration."""
    
    failure_threshold: int
    """Failures before opening circuit."""
    
    success_threshold: int
    """Successes to close half-open circuit."""
    
    timeout: float
    """Seconds before trying half-open."""
    
    excluded_exceptions: List[type]
    """Exceptions that don't count as failures."""


# =============================================================================
# Protocol Types - For duck typing / structural subtyping
# =============================================================================

class GuardProtocol(Protocol):
    """Protocol defining the Guard interface for type checking.
    
    Use this when you want to accept any Guard-like object.
    """
    
    def check(
        self,
        text: str,
        context_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ProtectionResultDict": ...
    
    def protect(
        self,
        func: Optional[Callable] = None,
        *,
        policies: Optional[List[Policy]] = None,
        on_violation: ViolationAction = "block",
        **kwargs: Any,
    ) -> Callable: ...


class EventHandler(Protocol):
    """Protocol for event handler callbacks."""
    
    def __call__(self, event: "SecurityEventDict") -> Optional[bool]: ...


class SecurityEventDict(TypedDict, total=False):
    """Security event for hooks/callbacks."""
    
    event_type: str
    """Type of event (block, allow, challenge, error)."""
    
    text: str
    """Text that was checked."""
    
    threat_level: ThreatLevel
    """Detected threat level."""
    
    threats_detected: List[ThreatDetail]
    """List of threats found."""
    
    latency_ms: float
    """Processing latency."""
    
    context_id: str
    """Session context ID."""
    
    user_id: str
    """User who made the request."""
    
    tool_name: str
    """Tool being protected."""
    
    error: str
    """Error message if event_type is 'error'."""


# =============================================================================
# Callback Type Aliases
# =============================================================================

ProgressCallback = Union[
    Callable[[int, int], None],  # (completed, total)
    Callable[[int, int, Optional["ProgressMetadataDict"]], None],  # With metadata
]
"""Callback for batch processing progress updates.

Simple form: ``(completed: int, total: int) -> None``
Extended form: ``(completed: int, total: int, metadata: ProgressMetadataDict) -> None``
"""


class ProgressMetadataDict(TypedDict, total=False):
    """Metadata provided with progress callbacks."""
    
    threats_detected: int
    """Number of threats detected so far."""
    
    blocked_count: int
    """Number of items blocked so far."""
    
    avg_latency_ms: float
    """Average processing time per item."""
    
    total_latency_ms: float
    """Total processing time so far."""
    
    current_item_preview: str
    """Preview of current item text (truncated)."""
    
    current_index: int
    """Index of current item being processed."""
    
    errors_count: int
    """Number of errors encountered."""


# =============================================================================
# Callback Types - For custom handlers
# =============================================================================

ChallengeHandler = Callable[[Any], bool]
"""Callback for challenge decisions.

Called when ``on_violation="challenge"`` is set and a potential threat
is detected. Return True to allow the request, False to block.

Example:
    def review_handler(event) -> bool:
        '''Prompt user for approval.'''
        print(f"Threat detected: {event}")
        response = input("Allow? (y/n): ")
        return response.lower() == 'y'
    
    @guard.protect(
        on_violation="challenge",
        challenge_action=review_handler,
    )
    def sensitive_function(data: str): ...
"""

BlockHandler = Callable[[Any], None]
"""Callback when a request is blocked.

Called after blocking a request. Use for custom alerting, logging,
or cleanup operations.

Example:
    def on_blocked(event) -> None:
        '''Send alert when attack detected.'''
        alert_security_team(
            threat=event.threat_level,
            details=event.threats_detected,
        )
    
    @guard.protect(
        on_violation="block",
        block_action=on_blocked,
    )
    def critical_function(data: str): ...
"""


# =============================================================================
# Re-exports for convenience
# =============================================================================

__all__ = [
    # Literal types
    "Policy",
    "ViolationAction", 
    "ThreatLevel",
    "FinalAction",
    "TrustLevel",
    "ToolType",
    "OutputFormat",
    "TierMode",
    "CircuitState",
    "LogStatus",
    # TypedDict types
    "ThreatDetail",
    "ProtectionResultDict",
    "ToolMetadata",
    "CheckOptions",
    "ProtectOptions",
    "BatchResult",
    "SDKConfigDict",
    "CircuitBreakerConfigDict",
    "SecurityEventDict",
    "ProgressMetadataDict",
    # Protocol types
    "GuardProtocol",
    "EventHandler",
    # Callback types
    "ProgressCallback",
    "ChallengeHandler",
    "BlockHandler",
]
