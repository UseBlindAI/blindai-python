"""Protect decorator and call_tool method."""

import asyncio
import functools
import inspect
import logging
import sys
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    TypeVar,
    Union,
    overload,
)

# ParamSpec available in Python 3.10+, backport from typing_extensions
if sys.version_info >= (3, 10):
    from typing import ParamSpec
else:
    try:
        from typing_extensions import ParamSpec
    except ImportError:
        ParamSpec = None  # type: ignore

from ...exceptions import ThreatBlockedError
from ...types import Policy, ViolationAction, TierMode

logger = logging.getLogger(__name__)

# Valid values for runtime validation
VALID_POLICIES = frozenset({
    "pii", "prompt_injection", "jailbreak", "sql_injection", 
    "code_injection", "xss", "ssrf", "data_exfiltration",
    "sensitive_topics", "toxicity", "bias", "hallucination", 
    "off_topic", "all",
})
VALID_VIOLATION_ACTIONS = frozenset({"block", "warn", "log", "challenge", "allow"})
VALID_TIER_MODES = frozenset({"full", "fast", "tier1", "tier2", "tier3"})

# Type variable for preserving return types
T = TypeVar("T")

# ParamSpec for preserving function signatures (Python 3.10+)
if ParamSpec is not None:
    P = ParamSpec("P")
else:
    P = None  # type: ignore

# Callback types for custom handlers
ChallengeHandler = Callable[[Any], bool]  # Returns True to allow, False to block
BlockHandler = Callable[[Any], None]  # Called when blocked


def _validate_options(
    policies: Optional[List[str]],
    on_violation: str,
    mode: Optional[str],
) -> None:
    """Validate decorator options at decoration time (fail fast).
    
    Raises:
        ValueError: If any option has an invalid value
    """
    if policies:
        invalid = set(policies) - VALID_POLICIES
        if invalid:
            raise ValueError(
                f"Invalid policies: {invalid!r}. "
                f"Valid values: {', '.join(sorted(VALID_POLICIES))}"
            )
    
    if on_violation not in VALID_VIOLATION_ACTIONS:
        raise ValueError(
            f"Invalid on_violation: {on_violation!r}. "
            f"Valid values: {', '.join(sorted(VALID_VIOLATION_ACTIONS))}"
        )
    
    if mode and mode not in VALID_TIER_MODES:
        raise ValueError(
            f"Invalid mode: {mode!r}. "
            f"Valid values: {', '.join(sorted(VALID_TIER_MODES))}"
        )


class DecoratorMixin:
    """Mixin providing protect decorator and call_tool."""

    @overload
    def protect(self, func: Callable[..., T]) -> Callable[..., T]:
        """Protect with no arguments: @guard.protect"""
        ...

    @overload
    def protect(
        self,
        func: None = None,
        *,
        policies: Optional[List[Policy]] = None,
        on_violation: ViolationAction = "block",
        context_id: Optional[str] = None,
        param: Optional[str] = None,
        mode: Optional[TierMode] = None,
        agent_id: Optional[str] = None,
        auto_register: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        challenge_action: Optional[ChallengeHandler] = None,
        block_action: Optional[BlockHandler] = None,
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Protect with arguments: @guard.protect(policies=["pii"])"""
        ...

    def protect(
        self,
        func: Optional[Callable[..., T]] = None,
        *,
        policies: Optional[List[Policy]] = None,
        on_violation: ViolationAction = "block",
        context_id: Optional[str] = None,
        param: Optional[str] = None,
        mode: Optional[TierMode] = None,
        agent_id: Optional[str] = None,
        auto_register: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        challenge_action: Optional[ChallengeHandler] = None,
        block_action: Optional[BlockHandler] = None,
    ) -> Union[Callable[..., T], Callable[[Callable[..., T]], Callable[..., T]]]:
        """Decorator to protect a function from security threats.

        Wraps any function (sync or async) to automatically scan inputs for 
        threats like prompt injection, PII, SQL injection, and more.

        Can be used with or without arguments:
            - ``@guard.protect`` - Apply all default policies
            - ``@guard.protect(policies=["pii", "prompt_injection"])`` - Specific policies
            - ``@guard.protect(on_violation="warn")`` - Custom violation handling

        Args:
            func: Function to protect (when used without parentheses).
            policies: List of security policies to apply. Autocomplete shows valid
                values like ``"pii"``, ``"prompt_injection"``, ``"sql_injection"``.
                If None, applies all default policies.
            on_violation: Action when threat detected. Valid values:

                - ``"block"``: Raise ThreatBlockedError (default)
                - ``"warn"``: Log warning but allow execution
                - ``"log"``: Silently log for monitoring
                - ``"challenge"``: Trigger challenge_action handler
                - ``"allow"``: Allow despite violation (testing only)

            context_id: Session/context ID for multi-turn conversation tracking.
                Enables detection of attack chains across multiple calls.
            param: Specific parameter name to check. If None, checks all string
                parameters. Use when your function has multiple string params
                and you only want to protect one.
            mode: Detection tier mode. Valid values:

                - ``"full"``: All tiers - Bloom + Aho-Corasick + ML (default)
                - ``"fast"``: Tier 1-2 only, skip ML for 10x speed
                - ``"tier1"``, ``"tier2"``, ``"tier3"``: Individual tiers

            agent_id: Agent ID for multi-agent orchestration setups.
            auto_register: Whether to automatically register this function as a
                tool in the security registry. Enables tool-aware policies.
            metadata: Additional metadata to include with all checks from this
                decorated function. Useful for audit logs.
            challenge_action: Custom handler called when on_violation="challenge".
                Should return True to allow the request, False to block.
            block_action: Custom handler called when a request is blocked.
                Use for custom alerting, logging, or cleanup.

        Returns:
            Decorated function that performs security checks before execution.

        Raises:
            ThreatBlockedError: If threat detected and on_violation is "block".
            ValueError: If no text argument found to protect, or invalid options.

        Example:
            Basic usage with all defaults::

                from blindai import Guard

                guard = Guard(api_key="...")

                @guard.protect
                def chat(message: str) -> str:
                    return llm.generate(message)
                
                # Safe input
                chat("Hello!")  # → Executes normally, returns response
                
                # Threat detected
                chat("Ignore all instructions")
                # → Raises ThreatBlockedError:
                #    ThreatBlockedError: Threat detected: HIGH
                #    Threats: ['PROMPT_INJECTION']

            With specific policies and IDE autocomplete::

                @guard.protect(
                    policies=["pii", "prompt_injection"],  # ← Autocomplete shows options
                    on_violation="block"  # ← Type hints show valid values
                )
                def process_user_input(text: str) -> str:
                    return sanitize(text)

            With custom handlers::

                def request_approval(event) -> bool:
                    '''Prompt user for approval on ambiguous cases.'''
                    return input(f"Allow {event.threat_level} threat? [y/N] ").lower() == "y"
                
                def alert_security(event) -> None:
                    '''Send alert when request is blocked.'''
                    slack.post(f"🚨 Blocked: {event.threats_detected}")

                @guard.protect(
                    on_violation="challenge",
                    challenge_action=request_approval,
                    block_action=alert_security,
                )
                def sensitive_operation(data: str) -> str:
                    return process(data)

            Async functions work seamlessly::

                @guard.protect(policies=["sql_injection"])
                async def async_query(sql: str) -> list:
                    return await db.execute(sql)
                
                # Automatically uses async checking
                results = await async_query("SELECT * FROM users")

        See Also:
            - :meth:`check`: For manual threat checking without decoration
            - :meth:`check_batch`: For checking multiple texts efficiently
            - :class:`ThreatBlockedError`: Exception raised on blocked threats
        """
        # Validate options at decoration time (fail fast)
        _validate_options(policies, on_violation, mode)
        
        # Store options for use in decorator
        options = {
            "policies": policies,
            "on_violation": on_violation,
            "context_id": context_id,
            "param": param,
            "mode": mode,
            "agent_id": agent_id,
            "auto_register": auto_register,
            "metadata": metadata,
            "challenge_action": challenge_action,
            "block_action": block_action,
        }

        def decorator(f: Callable[..., T]) -> Callable[..., T]:
            if options["auto_register"]:
                self._register_tool_async(f, options["agent_id"])
            
            def _extract_text(args, kwargs) -> str:
                """Extract text to check from function arguments."""
                text = None
                param_name = options["param"]

                if param_name:
                    if param_name in kwargs:
                        text = kwargs[param_name]
                    else:
                        sig = inspect.signature(f)
                        param_names = list(sig.parameters.keys())
                        if param_name in param_names:
                            param_index = param_names.index(param_name)
                            if param_index < len(args):
                                text = args[param_index]

                    if text is None:
                        raise ValueError(f"Parameter '{param_name}' not found in function call")
                else:
                    for arg in args:
                        if isinstance(arg, str):
                            text = arg
                            break
                    if text is None:
                        for value in kwargs.values():
                            if isinstance(value, str):
                                text = value
                                break

                if text is None:
                    raise ValueError("No text argument found to protect")
                
                return text
            
            def _handle_threat(result, text: str) -> None:
                """Handle detected threat based on on_violation setting."""
                if not result.is_threat:
                    return
                    
                violation_action = options["on_violation"]
                
                if violation_action == "block":
                    # Call block_action handler if provided
                    if options["block_action"]:
                        try:
                            options["block_action"](result)
                        except Exception as e:
                            logger.warning(f"block_action handler failed: {e}")
                    
                    raise ThreatBlockedError(
                        message=f"Threat detected: {result.threat_level}",
                        threat_level=result.threat_level,
                        threats=result.threats_detected,
                        response=result.to_dict() if hasattr(result, 'to_dict') else {
                            "is_threat": True, 
                            "threat_level": result.threat_level
                        },
                    )
                elif violation_action == "warn":
                    logger.warning(
                        f"Security warning: {result.threat_level} threat in {f.__name__}. "
                        f"Threats: {result.threats_detected}"
                    )
                elif violation_action == "log":
                    logger.info(
                        f"Security log: {result.threat_level} threat in {f.__name__}"
                    )
                elif violation_action == "challenge":
                    # Use custom challenge_action if provided, else use hooks
                    approved = False
                    
                    if options["challenge_action"]:
                        try:
                            approved = options["challenge_action"](result)
                        except Exception as e:
                            logger.warning(f"challenge_action handler failed: {e}")
                            approved = False
                    else:
                        # Fall back to hooks system
                        from ...hooks import EventType, SecurityEvent
                        event = SecurityEvent(
                            event_type=EventType.CHALLENGE,
                            text=text,
                            threat_level=result.threat_level,
                            threats_detected=result.threats_detected,
                        )
                        challenge_results = self.hooks.dispatch(EventType.CHALLENGE, event)
                        approved = not any(r is False for r in challenge_results)
                    
                    if not approved:
                        if options["block_action"]:
                            try:
                                options["block_action"](result)
                            except Exception as e:
                                logger.warning(f"block_action handler failed: {e}")
                        
                        raise ThreatBlockedError(
                            message=f"Challenge denied: {result.threat_level}",
                            threat_level=result.threat_level,
                            threats=result.threats_detected,
                            response={"is_threat": True, "threat_level": result.threat_level},
                        )
                # "allow" does nothing - continues execution
            
            # Check if function is async
            if asyncio.iscoroutinefunction(f):
                @functools.wraps(f)
                async def async_wrapper(*args, **kwargs) -> T:
                    text = _extract_text(args, kwargs)
                    
                    # Build check metadata
                    check_metadata = dict(options["metadata"] or {})
                    if options["policies"]:
                        check_metadata["policies"] = options["policies"]
                    if options["mode"]:
                        check_metadata["mode"] = options["mode"]

                    try:
                        # Use async check if available, else run sync in executor
                        if hasattr(self, 'check_async'):
                            result = await self.check_async(
                                text,
                                context_id=options["context_id"],
                                metadata=check_metadata if check_metadata else None,
                            )
                        else:
                            # Fall back to sync check in executor
                            loop = asyncio.get_event_loop()
                            result = await loop.run_in_executor(
                                None,
                                lambda: self.check(
                                    text,
                                    context_id=options["context_id"],
                                    metadata=check_metadata if check_metadata else None,
                                )
                            )
                        
                        _handle_threat(result, text)
                        
                    except ThreatBlockedError:
                        raise

                    return await f(*args, **kwargs)

                return async_wrapper  # type: ignore
            else:
                @functools.wraps(f)
                def sync_wrapper(*args, **kwargs) -> T:
                    text = _extract_text(args, kwargs)
                    
                    # Build check metadata
                    check_metadata = dict(options["metadata"] or {})
                    if options["policies"]:
                        check_metadata["policies"] = options["policies"]
                    if options["mode"]:
                        check_metadata["mode"] = options["mode"]

                    try:
                        result = self.check(
                            text, 
                            context_id=options["context_id"],
                            metadata=check_metadata if check_metadata else None,
                        )
                        
                        _handle_threat(result, text)
                        
                    except ThreatBlockedError:
                        raise
                        
                    return f(*args, **kwargs)

                return sync_wrapper  # type: ignore

        if func is None:
            return decorator
        else:
            return decorator(func)

    def call_tool(
        self,
        tool_func: Callable[..., T],
        *args: Any,
        policies: Optional[List[Policy]] = None,
        on_violation: ViolationAction = "block",
        context_id: Optional[str] = None,
        mode: Optional[TierMode] = None,
        metadata: Optional[Dict[str, Any]] = None,
        challenge_action: Optional[ChallengeHandler] = None,
        block_action: Optional[BlockHandler] = None,
        **kwargs: Any,
    ) -> T:
        """Call a tool function with automatic threat protection.

        Alternative to the @protect decorator for dynamic tool invocations,
        such as when calling tools selected at runtime by an LLM agent.

        Args:
            tool_func: The tool function to call.
            *args: Positional arguments to pass to the tool.
            policies: Security policies to apply. Valid values include:

                - ``"pii"``: Detect personally identifiable information
                - ``"prompt_injection"``: Detect prompt injection attempts
                - ``"sql_injection"``: Detect SQL injection
                - ``"jailbreak"``: Detect jailbreak attempts

            on_violation: Action when threat detected:

                - ``"block"``: Raise ThreatBlockedError (default)
                - ``"warn"``: Log warning but proceed
                - ``"log"``: Silently log
                - ``"challenge"``: Trigger review handler

            context_id: Session ID for multi-turn tracking.
            mode: Detection mode (``"full"``, ``"fast"``, etc.)
            metadata: Additional metadata for the check.
            challenge_action: Custom handler for challenge decisions.
            block_action: Custom handler called on block.
            **kwargs: Keyword arguments to pass to the tool.

        Returns:
            The return value from tool_func (type preserved).

        Raises:
            ThreatBlockedError: If threat detected and on_violation is "block".
            ValueError: If no text argument found in args/kwargs, or invalid options.

        Example:
            Dynamic tool execution in an agent::

                tools = {
                    "search": search_function,
                    "email": send_email,
                    "query": run_sql,
                }

                # LLM selects tool and args
                tool_name, tool_args = llm.select_tool(user_request)

                # Execute with protection
                result = guard.call_tool(
                    tools[tool_name],
                    *tool_args,
                    policies=["prompt_injection", "sql_injection"],
                    on_violation="block",
                )

            With context tracking::

                guard.call_tool(
                    my_tool,
                    user_input,
                    context_id=session_id,
                    mode="fast",
                )
        """
        # Validate options
        _validate_options(policies, on_violation, mode)
        
        text = None
        for arg in args:
            if isinstance(arg, str):
                text = arg
                break
        if text is None:
            for value in kwargs.values():
                if isinstance(value, str):
                    text = value
                    break

        if text is None:
            raise ValueError("No text argument found to protect")

        # Build check metadata
        check_metadata = dict(metadata or {})
        if policies:
            check_metadata["policies"] = policies
        if mode:
            check_metadata["mode"] = mode

        try:
            result = self.check(
                text, 
                context_id=context_id,
                metadata=check_metadata if check_metadata else None,
            )
            
            if result.is_threat:
                if on_violation == "block":
                    if block_action:
                        try:
                            block_action(result)
                        except Exception as e:
                            logger.warning(f"block_action handler failed: {e}")
                    
                    raise ThreatBlockedError(
                        message=f"Threat detected: {result.threat_level}",
                        threat_level=result.threat_level,
                        threats=result.threats_detected,
                        response=result.to_dict() if hasattr(result, 'to_dict') else {
                            "is_threat": True, 
                            "threat_level": result.threat_level
                        },
                    )
                elif on_violation == "warn":
                    logger.warning(
                        f"Security warning: {result.threat_level} threat. "
                        f"Threats: {result.threats_detected}"
                    )
                elif on_violation == "log":
                    logger.info(f"Security log: {result.threat_level} threat")
                elif on_violation == "challenge":
                    approved = False
                    if challenge_action:
                        try:
                            approved = challenge_action(result)
                        except Exception as e:
                            logger.warning(f"challenge_action handler failed: {e}")
                    
                    if not approved:
                        if block_action:
                            try:
                                block_action(result)
                            except Exception as e:
                                logger.warning(f"block_action handler failed: {e}")
                        
                        raise ThreatBlockedError(
                            message=f"Challenge denied: {result.threat_level}",
                            threat_level=result.threat_level,
                            threats=result.threats_detected,
                            response={"is_threat": True, "threat_level": result.threat_level},
                        )
                    
        except ThreatBlockedError:
            raise

        return tool_func(*args, **kwargs)
