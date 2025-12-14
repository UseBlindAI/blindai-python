"""Multi-Agent SDK Integration.

Provides Python SDK for multi-agent security:
- Agent decorators
- Context management
- Trust evaluation
- Secure communication

Example:
    ```python
    from blindai import MultiAgentGuard
    
    guard = MultiAgentGuard(api_key="...")
    
    # Register an agent
    @guard.agent(
        agent_id="data-analyst",
        capabilities=["read_data", "analyze"],
        trust_level="trusted",
    )
    async def analyze_data(data):
        # Protected agent logic
        return process(data)
    
    # Or use context manager
    async with guard.agent_context("processor") as ctx:
        # Evaluate trust before action
        if ctx.can_communicate("external-api"):
            result = await fetch_data()
    ```
"""

import asyncio
import functools
import logging
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Optional, Any, Callable, TypeVar, List, Dict
from enum import Enum

logger = logging.getLogger(__name__)

# Type variables for decorators
F = TypeVar("F", bound=Callable[..., Any])

# Current agent context
_current_agent: ContextVar[Optional["AgentContext"]] = ContextVar("current_agent", default=None)


class AgentTrustLevel(str, Enum):
    """Agent trust levels."""
    UNTRUSTED = "untrusted"
    RESTRICTED = "restricted"
    STANDARD = "standard"
    TRUSTED = "trusted"
    PRIVILEGED = "privileged"


@dataclass
class AgentContext:
    """Context for an active agent.
    
    Attributes:
        agent_id: Agent identifier
        name: Agent name
        trust_level: Current trust level
        capabilities: Agent capabilities
        parent_id: Parent agent ID
        guard: MultiAgentGuard instance
        start_time: Context start time
        metadata: Additional context data
    """
    agent_id: str
    name: str
    trust_level: AgentTrustLevel
    capabilities: List[str]
    parent_id: Optional[str]
    guard: "MultiAgentGuard"
    start_time: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def can_communicate(self, target_agent: str) -> bool:
        """Check if this agent can communicate with target.
        
        Args:
            target_agent: Target agent ID
            
        Returns:
            True if communication allowed
        """
        return self.guard.can_communicate(self.agent_id, target_agent)
    
    def can_use_capability(self, capability: str) -> bool:
        """Check if agent has a capability.
        
        Args:
            capability: Capability to check
            
        Returns:
            True if agent has capability
        """
        return capability in self.capabilities
    
    async def send_message(
        self,
        target_agent: str,
        payload: Any,
        **kwargs,
    ) -> Optional[str]:
        """Send a message to another agent.
        
        Args:
            target_agent: Recipient agent ID
            payload: Message payload
            **kwargs: Additional send options
            
        Returns:
            Message ID if sent
        """
        return await self.guard.send_message(
            source_agent=self.agent_id,
            target_agent=target_agent,
            payload=payload,
            **kwargs,
        )
    
    async def receive_messages(self, limit: int = 10) -> List[dict]:
        """Receive pending messages.
        
        Args:
            limit: Maximum messages to receive
            
        Returns:
            List of message dictionaries
        """
        return await self.guard.receive_messages(self.agent_id, limit=limit)
    
    def spawn_child(
        self,
        agent_id: str,
        name: str,
        capabilities: Optional[List[str]] = None,
        **kwargs,
    ) -> "AgentContext":
        """Spawn a child agent.
        
        Args:
            agent_id: Child agent ID
            name: Child agent name
            capabilities: Child capabilities (subset of parent)
            **kwargs: Additional agent options
            
        Returns:
            Child agent context
        """
        # Child trust level can't exceed parent
        child_capabilities = capabilities or []
        allowed_caps = [c for c in child_capabilities if c in self.capabilities]
        
        return self.guard.register_agent(
            agent_id=agent_id,
            name=name,
            trust_level=self.trust_level,
            capabilities=allowed_caps,
            parent_agent=self.agent_id,
            **kwargs,
        )


@dataclass
class MultiAgentConfig:
    """Configuration for MultiAgentGuard.
    
    Attributes:
        base_url: API base URL
        timeout: Request timeout in seconds
        auto_register: Auto-register agents on first use
        default_trust_level: Default trust for new agents
        enable_attack_detection: Enable background attack detection
        detection_interval: Attack detection interval
    """
    base_url: str = "http://localhost:8000"
    timeout: int = 30
    auto_register: bool = True
    default_trust_level: AgentTrustLevel = AgentTrustLevel.STANDARD
    enable_attack_detection: bool = True
    detection_interval: int = 60


class MultiAgentGuard:
    """Multi-agent security guard.
    
    Provides security controls for multi-agent systems including:
    - Agent registration and lifecycle
    - Trust evaluation
    - Secure communication
    - Attack detection
    
    Example:
        ```python
        guard = MultiAgentGuard(api_key="your-key")
        
        # Register agents
        agent = guard.register_agent(
            agent_id="coordinator",
            name="Task Coordinator",
            trust_level="trusted",
            capabilities=["read_data", "spawn_agent"],
        )
        
        # Use decorator for agent functions
        @guard.agent("worker", capabilities=["read_data"])
        async def worker_task(data):
            ctx = get_current_agent()
            if ctx.can_communicate("database"):
                return await fetch_data()
        
        # Run attack detection
        attacks = await guard.detect_attacks()
        ```
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        config: Optional[MultiAgentConfig] = None,
    ):
        """Initialize guard.
        
        Args:
            api_key: API key for authentication
            config: Guard configuration
        """
        self.api_key = api_key
        self.config = config or MultiAgentConfig()
        
        # Local state
        self._agents: Dict[str, AgentContext] = {}
        self._http_client = None
        
        # For local mode (no API)
        self._local_registry = None
        self._local_trust = None
        self._local_policy = None
        self._local_communicator = None
    
    def _get_local_components(self):
        """Initialize local components for non-API mode."""
        if self._local_registry is None:
            from blindai.core.multi_agent import (
                AgentRegistry,
                TrustManager,
                CrossAgentPolicy,
                SecureCommunicator,
            )
            
            self._local_registry = AgentRegistry()
            self._local_trust = TrustManager(self._local_registry)
            self._local_policy = CrossAgentPolicy(self._local_registry)
            self._local_communicator = SecureCommunicator(
                self._local_registry,
                self._local_policy,
            )
        
        return (
            self._local_registry,
            self._local_trust,
            self._local_policy,
            self._local_communicator,
        )
    
    def register_agent(
        self,
        agent_id: str,
        name: str,
        trust_level: str | AgentTrustLevel = AgentTrustLevel.STANDARD,
        capabilities: Optional[List[str]] = None,
        parent_agent: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[dict] = None,
    ) -> AgentContext:
        """Register a new agent.
        
        Args:
            agent_id: Unique agent identifier
            name: Human-readable name
            trust_level: Agent trust level
            capabilities: List of capabilities
            parent_agent: Parent agent ID
            tags: Agent tags
            metadata: Additional metadata
            
        Returns:
            Agent context
        """
        if isinstance(trust_level, str):
            trust_level = AgentTrustLevel(trust_level.lower())
        
        capabilities = capabilities or []
        
        # Register with local registry
        registry, _, _, _ = self._get_local_components()
        
        from blindai.core.multi_agent import (
            AgentIdentity,
            AgentTrustLevel as CoreTrustLevel,
            AgentCapability,
        )
        
        # Map trust level
        trust_map = {
            AgentTrustLevel.UNTRUSTED: CoreTrustLevel.UNTRUSTED,
            AgentTrustLevel.RESTRICTED: CoreTrustLevel.RESTRICTED,
            AgentTrustLevel.STANDARD: CoreTrustLevel.STANDARD,
            AgentTrustLevel.TRUSTED: CoreTrustLevel.TRUSTED,
            AgentTrustLevel.PRIVILEGED: CoreTrustLevel.PRIVILEGED,
        }
        
        # Map capabilities
        cap_set = set()
        for cap in capabilities:
            try:
                cap_set.add(AgentCapability(cap))
            except ValueError:
                logger.warning(f"Unknown capability: {cap}")
        
        identity = AgentIdentity(
            agent_id=agent_id,
            name=name,
            trust_level=trust_map.get(trust_level, CoreTrustLevel.STANDARD),
            capabilities=cap_set,
            parent_agent=parent_agent,
            tags=set(tags or []),
            metadata=metadata or {},
        )
        
        registry.register(identity)
        
        # Create context
        ctx = AgentContext(
            agent_id=agent_id,
            name=name,
            trust_level=trust_level,
            capabilities=capabilities,
            parent_id=parent_agent,
            guard=self,
            metadata=metadata or {},
        )
        
        self._agents[agent_id] = ctx
        logger.info(f"Registered agent: {agent_id} ({trust_level.value})")
        
        return ctx
    
    def get_agent(self, agent_id: str) -> Optional[AgentContext]:
        """Get an agent context.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Agent context or None
        """
        return self._agents.get(agent_id)
    
    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            True if unregistered
        """
        if agent_id in self._agents:
            del self._agents[agent_id]
            
            registry, _, _, _ = self._get_local_components()
            registry.delete(agent_id)
            
            logger.info(f"Unregistered agent: {agent_id}")
            return True
        return False
    
    def can_communicate(
        self,
        source_agent: str,
        target_agent: str,
        capability: Optional[str] = None,
    ) -> bool:
        """Check if communication is allowed.
        
        Args:
            source_agent: Source agent ID
            target_agent: Target agent ID
            capability: Optional capability being used
            
        Returns:
            True if allowed
        """
        registry, trust, policy, _ = self._get_local_components()
        
        source = registry.get(source_agent)
        target = registry.get(target_agent)
        
        if not source or not target:
            return False
        
        # Parse capability
        cap = None
        if capability:
            from blindai.core.multi_agent import AgentCapability
            try:
                cap = AgentCapability(capability)
            except ValueError:
                pass
        
        # Evaluate policy
        result = policy.evaluate(source, target, cap)
        return result.allowed
    
    def evaluate_trust(
        self,
        source_agent: str,
        target_agent: str,
        capability: Optional[str] = None,
    ) -> dict:
        """Evaluate trust between agents.
        
        Args:
            source_agent: Source agent ID
            target_agent: Target agent ID
            capability: Optional capability
            
        Returns:
            Trust decision dictionary
        """
        registry, trust, _, _ = self._get_local_components()
        
        source = registry.get(source_agent)
        target = registry.get(target_agent)
        
        if not source or not target:
            return {"allowed": False, "reason": "Agent not found"}
        
        # Parse capability
        cap = None
        if capability:
            from blindai.core.multi_agent import AgentCapability
            try:
                cap = AgentCapability(capability)
            except ValueError:
                pass
        
        decision = trust.evaluate(source, target, cap)
        
        return {
            "allowed": decision.allowed,
            "trust_score": decision.trust_score,
            "reason": decision.reason,
            "conditions": decision.conditions,
        }
    
    async def send_message(
        self,
        source_agent: str,
        target_agent: str,
        payload: Any,
        **kwargs,
    ) -> Optional[str]:
        """Send a secure message.
        
        Args:
            source_agent: Sender ID
            target_agent: Recipient ID
            payload: Message payload
            **kwargs: Additional options
            
        Returns:
            Message ID if sent
        """
        _, _, _, communicator = self._get_local_components()
        
        result = communicator.send(
            source_agent=source_agent,
            target_agent=target_agent,
            payload=payload,
            **kwargs,
        )
        
        if result.success:
            return result.message_id
        
        logger.warning(f"Message send failed: {result.error}")
        return None
    
    async def receive_messages(
        self,
        agent_id: str,
        limit: int = 10,
    ) -> List[dict]:
        """Receive pending messages.
        
        Args:
            agent_id: Agent ID
            limit: Maximum messages
            
        Returns:
            List of messages
        """
        _, _, _, communicator = self._get_local_components()
        
        messages = communicator.receive(agent_id, limit=limit)
        
        result = []
        for msg in messages:
            try:
                payload = communicator.decrypt_payload(msg, agent_id)
                result.append({
                    "message_id": msg.message_id,
                    "source_agent": msg.source_agent,
                    "payload": payload,
                    "priority": msg.priority.value,
                    "created_at": msg.created_at,
                })
            except Exception as e:
                logger.error(f"Failed to decrypt message: {e}")
        
        return result
    
    async def detect_attacks(
        self,
        time_window: int = 300,
    ) -> List[dict]:
        """Run attack detection.
        
        Args:
            time_window: Analysis window in seconds
            
        Returns:
            List of detected attacks
        """
        registry, _, _, _ = self._get_local_components()
        
        from blindai.core.multi_agent import CoordinatedAttackDetector
        detector = CoordinatedAttackDetector(registry)
        
        results = detector.analyze_all(time_window=time_window)
        
        return [
            {
                "attack_pattern": r.attack_pattern.value if r.attack_pattern else None,
                "confidence": r.confidence,
                "involved_agents": r.involved_agents,
                "risk_score": r.risk_score,
                "recommendation": r.recommendation,
            }
            for r in results
        ]
    
    def agent(
        self,
        agent_id: str,
        name: Optional[str] = None,
        trust_level: str | AgentTrustLevel = AgentTrustLevel.STANDARD,
        capabilities: Optional[List[str]] = None,
        **kwargs,
    ) -> Callable[[F], F]:
        """Decorator to mark a function as an agent.
        
        Args:
            agent_id: Agent identifier
            name: Agent name (defaults to function name)
            trust_level: Trust level
            capabilities: Agent capabilities
            **kwargs: Additional agent options
            
        Returns:
            Decorated function
        """
        def decorator(func: F) -> F:
            agent_name = name or func.__name__
            
            # Register agent on first call
            registered = False
            
            @functools.wraps(func)
            async def async_wrapper(*args, **kw):
                nonlocal registered
                
                if not registered:
                    self.register_agent(
                        agent_id=agent_id,
                        name=agent_name,
                        trust_level=trust_level,
                        capabilities=capabilities,
                        **kwargs,
                    )
                    registered = True
                
                ctx = self._agents.get(agent_id)
                token = _current_agent.set(ctx)
                
                try:
                    return await func(*args, **kw)
                finally:
                    _current_agent.reset(token)
            
            @functools.wraps(func)
            def sync_wrapper(*args, **kw):
                nonlocal registered
                
                if not registered:
                    self.register_agent(
                        agent_id=agent_id,
                        name=agent_name,
                        trust_level=trust_level,
                        capabilities=capabilities,
                        **kwargs,
                    )
                    registered = True
                
                ctx = self._agents.get(agent_id)
                token = _current_agent.set(ctx)
                
                try:
                    return func(*args, **kw)
                finally:
                    _current_agent.reset(token)
            
            if asyncio.iscoroutinefunction(func):
                return async_wrapper  # type: ignore
            return sync_wrapper  # type: ignore
        
        return decorator
    
    def agent_context(self, agent_id: str) -> "AgentContextManager":
        """Context manager for agent scope.
        
        Args:
            agent_id: Agent ID
            
        Returns:
            Context manager
            
        Example:
            ```python
            async with guard.agent_context("worker") as ctx:
                if ctx.can_communicate("database"):
                    await ctx.send_message("database", {"query": "..."})
            ```
        """
        return AgentContextManager(self, agent_id)
    
    def add_policy_rule(
        self,
        rule_id: str,
        name: str,
        action: str,
        source_filter: Optional[dict] = None,
        target_filter: Optional[dict] = None,
        capability_filter: Optional[List[str]] = None,
        priority: int = 50,
    ) -> None:
        """Add a policy rule.
        
        Args:
            rule_id: Rule identifier
            name: Rule name
            action: Action (allow, deny, audit, etc.)
            source_filter: Source agent filter
            target_filter: Target agent filter
            capability_filter: Capability filter
            priority: Rule priority
        """
        _, _, policy, _ = self._get_local_components()
        
        from blindai.core.multi_agent.policy import (
            PolicyRule,
            PolicyPriority,
            PolicyAction,
        )
        from blindai.core.multi_agent import AgentCapability
        
        action_map = {
            "allow": PolicyAction.ALLOW,
            "deny": PolicyAction.DENY,
            "audit": PolicyAction.AUDIT,
            "quarantine": PolicyAction.QUARANTINE,
        }
        
        cap_filter = None
        if capability_filter:
            cap_filter = set()
            for cap in capability_filter:
                try:
                    cap_filter.add(AgentCapability(cap))
                except ValueError:
                    pass
        
        rule = PolicyRule(
            rule_id=rule_id,
            name=name,
            description=name,
            priority=PolicyPriority(priority),
            action=action_map.get(action, PolicyAction.ALLOW),
            source_filter=source_filter,
            target_filter=target_filter,
            capability_filter=cap_filter,
        )
        
        policy.add_rule(rule)
    
    def quarantine_agent(self, agent_id: str, reason: str = "Security incident") -> None:
        """Quarantine an agent.
        
        Args:
            agent_id: Agent to quarantine
            reason: Quarantine reason
        """
        _, _, policy, _ = self._get_local_components()
        policy.quarantine_agent(agent_id, reason)
        logger.warning(f"Agent quarantined: {agent_id} - {reason}")


class AgentContextManager:
    """Context manager for agent scope."""
    
    def __init__(self, guard: MultiAgentGuard, agent_id: str):
        self.guard = guard
        self.agent_id = agent_id
        self._token = None
        self._ctx = None
    
    async def __aenter__(self) -> AgentContext:
        self._ctx = self.guard.get_agent(self.agent_id)
        if self._ctx is None:
            raise ValueError(f"Agent not found: {self.agent_id}")
        
        self._token = _current_agent.set(self._ctx)
        return self._ctx
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._token:
            _current_agent.reset(self._token)
    
    def __enter__(self) -> AgentContext:
        self._ctx = self.guard.get_agent(self.agent_id)
        if self._ctx is None:
            raise ValueError(f"Agent not found: {self.agent_id}")
        
        self._token = _current_agent.set(self._ctx)
        return self._ctx
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._token:
            _current_agent.reset(self._token)


def get_current_agent() -> Optional[AgentContext]:
    """Get the current agent context.
    
    Returns:
        Current agent context or None
    """
    return _current_agent.get()
