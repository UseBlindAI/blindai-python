"""The wire types, as the server actually defines them.

Authoritative source: `AuthorizeRequest`, `ThreatDetail`, `AuthorizeResponse`, `RAGScanRequest` and
`RAGScanResponse` in the API's `routes/guardian.py`. Every field and default here was read off the
running server and verified against it, not inferred from an older client.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Roles the server's RBAC gate knows, lowercase. Anything else is treated as `guest` -- no
#: permissions, fail-closed. This client passes roles through unchanged and maps nothing: an SDK
#: that quietly promoted an unrecognised role would grant more access than the caller asked for.
ROLES = ("admin", "user", "viewer", "guest", "foreign")

#: Detection presets. Which of these is actually running depends on deployment configuration --
#: presets that use the intent classifier refuse to start without an API key rather than silently
#: dropping a detection layer, so naming one that is not up returns 503, not a quiet downgrade.
PRESETS = ("strict", "balanced", "permissive")


@dataclass(frozen=True)
class ThreatDetail:
    type: str
    confidence: float = 0.9
    severity: str | None = None

    @classmethod
    def from_wire(cls, raw: dict[str, Any]) -> ThreatDetail:
        return cls(
            type=str(raw.get("type", "unknown")),
            confidence=float(raw.get("confidence", 0.9)),
            severity=raw.get("severity"),
        )


@dataclass(frozen=True)
class Decision:
    """The answer to one authorization request.

    `blocked` is the enforcement signal. `is_threat` is for reporting: a request can carry detected
    threats and still be allowed, so gating on `is_threat` refuses work the policy permitted.
    """

    blocked: bool
    action: str                      # "allow" | "block"
    is_threat: bool                  # blocked or any threats present
    confidence: float                # max across threats, 0.0 when there are none
    threats: list[ThreatDetail]
    threat_level: str                # never None: "none", the server's value, or "medium"
    reason: str | None
    latency_ms: float
    preset: str | None
    raw: dict[str, Any] = field(repr=False)

    @property
    def allowed(self) -> bool:
        return not self.blocked


@dataclass(frozen=True)
class TokenGrant:
    """Identity tokens for a runtime's agents, as `/v1/cp/tokens` granted them."""

    tokens: dict[str, str]
    expires_in: int

    @classmethod
    def from_wire(cls, body: Any) -> TokenGrant:
        from .errors import ContractError
        if not isinstance(body, dict) or not isinstance(body.get("tokens"), dict):
            raise ContractError("not a token grant: missing 'tokens'")
        tokens = body["tokens"]
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in tokens.items()):
            raise ContractError("not a token grant: 'tokens' must map agent ids to strings")
        expires_in = body.get("expires_in")
        if not isinstance(expires_in, int) or isinstance(expires_in, bool):
            raise ContractError("not a token grant: 'expires_in' is not an integer")
        return cls(tokens=dict(tokens), expires_in=expires_in)
