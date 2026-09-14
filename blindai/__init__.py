"""Fail-closed Python client for the BlindAI authorization API.

**The one rule: errors throw. No error path in this client produces an allow.**

    from blindai import BlindAIClient

    client = BlindAIClient(api_key=os.environ["BLINDAI_API_KEY"],
                           base_url=os.environ["BLINDAI_BASE_URL"])
    decision = client.authorize("look up invoice 4471", tool="crm_lookup", preset="strict")
    if decision.blocked:
        raise RuntimeError(decision.reason or "blocked by policy")
"""
from .client import BlindAIClient
from .errors import (
                     ApiError,
                     AuthError,
                     BlindAIError,
                     ContractError,
                     PresetUnavailableError,
                     TimeoutError,
                     TransportError,
                     ValidationError,
)
from .parse import parse_decision
from .rate_limit import RateLimiter, RateLimitExceeded
from .session import Session
from .types import PRESETS, ROLES, Decision, ThreatDetail

__version__ = "0.1.0"

__all__ = [
                     "PRESETS",
                     "ROLES",
                     "ApiError",
                     "AuthError",
                     "BlindAIClient",
                     "BlindAIError",
                     "ContractError",
                     "Decision",
                     "PresetUnavailableError",
                     "RateLimitExceeded",
                     "RateLimiter",
                     "Session",
                     "ThreatDetail",
                     "TimeoutError",
                     "TransportError",
                     "ValidationError",
                     "parse_decision",
]
