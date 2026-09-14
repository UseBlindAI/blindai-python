"""Turning a response body into a decision, and refusing to guess.

These rules are the client's contract with the server. Port the rules, not just the field names.
"""
from __future__ import annotations

from typing import Any

from .errors import ContractError
from .types import Decision, ThreatDetail


def parse_decision(body: Any) -> Decision:
    """Build a `Decision`, or raise `ContractError`.

    Rule 1: never guess a verdict. A body with neither `blocked` nor `allowed` is not an
    AuthorizeResponse, and defaulting it to "allow" is what turns contract drift into a silent
    bypass instead of a loud failure.

    Rule 2: never coerce one. A `blocked` that is the string "false" is precisely the shape
    mismatch this check exists to catch, so a truthy or falsy non-bool raises rather than being
    read for its truthiness.
    """
    if not isinstance(body, dict):
        raise ContractError(f"not an AuthorizeResponse: body is {type(body).__name__}, not an object")

    if "blocked" not in body and "allowed" not in body:
        raise ContractError("not an AuthorizeResponse: missing 'blocked'")

    for key in ("blocked", "allowed"):
        if key in body and not isinstance(body[key], bool):
            raise ContractError(
                f"not an AuthorizeResponse: '{key}' is {type(body[key]).__name__}, not bool")

    # `blocked` wins when present; otherwise derive it.
    blocked = body["blocked"] if "blocked" in body else not body["allowed"]

    raw_threats = body.get("threats") or []
    threats = [ThreatDetail.from_wire(t) for t in raw_threats if isinstance(t, dict)]

    # A request can carry detected threats and still be allowed.
    is_threat = blocked or bool(threats)
    threat_level = body.get("threat_level") or ("medium" if is_threat else "none")
    confidence = max((t.confidence for t in threats), default=0.0)

    return Decision(
        blocked=blocked,
        action="block" if blocked else "allow",
        is_threat=is_threat,
        confidence=confidence,
        threats=threats,
        threat_level=threat_level,
        reason=body.get("reason"),
        latency_ms=float(body.get("latency_ms", 0.0)),
        preset=body.get("preset"),
        raw=body,
    )
