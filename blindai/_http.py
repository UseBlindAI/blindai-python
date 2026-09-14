"""Shared rules for what is worth retrying and what an error should say.

The sync and async clients make the same two decisions, so they are made here once rather than
written twice and left to drift -- which is how the previous client ended up retrying a mistyped
API key four times in one place and not the other.
"""
from __future__ import annotations

from typing import Any

from .errors import ApiError, AuthError, PresetUnavailableError, ValidationError

#: The only 4xx worth repeating. 429 is the server asking us back; 408 is a timeout it chose to
#: report rather than hold. Every other 4xx describes the request itself -- a bad key, a malformed
#: body, a missing permission -- and will fail identically on every attempt, so retrying it only
#: delays the answer and makes a typo look like a network problem.
RETRYABLE_CLIENT_ERRORS = frozenset({408, 429})


def is_retryable(status_code: int) -> bool:
    return status_code >= 500 or status_code in RETRYABLE_CLIENT_ERRORS


def safe_json(response: Any) -> dict[str, Any] | None:
    """The parsed body, or None when it is not JSON.

    An error path is where a proxy is most likely to return HTML, and a parse failure while
    handling a failure must not replace the failure being handled.
    """
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 - the breadth IS the contract here
        # Deliberately total. This runs while handling a failure, and any narrower clause would let
        # a parse error replace the error being reported -- a proxy returning HTML on a 502 must
        # still surface as a 502, not as a JSON decode error.
        return None
    return body if isinstance(body, dict) else None


def server_message(body: dict[str, Any] | None, fallback_text: str = "") -> str | None:
    """The server's own explanation.

    FastAPI reports errors as `{"detail": ...}` -- a string for a raised error, a list of per-field
    objects for a 422. Both are worth surfacing: for a 422 the field name is the entire useful
    content of the message.

    The `input` key inside a validation entry is deliberately never read. It echoes the submitted
    body, which on a real call contains the caller's `input_text`.
    """
    if not isinstance(body, dict):
        text = (fallback_text or "").strip()
        return text[:200] or None

    detail = body.get("detail")
    if isinstance(detail, str):
        return detail.strip() or None
    if isinstance(detail, list):
        parts = []
        for item in detail:
            if not isinstance(item, dict):
                continue
            loc = ".".join(str(p) for p in item.get("loc", []) if p not in ("body", "query"))
            msg = item.get("msg")
            if loc and msg:
                parts.append(f"{loc}: {msg}")
            elif msg:
                parts.append(str(msg))
        return "; ".join(parts) or None
    return None


def error_for(status_code: int, body: dict[str, Any] | None, text: str = "") -> ApiError:
    """The exception a non-2xx deserves, with the server's sentence kept."""
    detail = server_message(body, text)
    message = f"HTTP {status_code}" + (f" - {detail}" if detail else "")
    retryable = is_retryable(status_code)

    if status_code in (401, 403):
        return AuthError(message, status_code, body, retryable)
    if status_code == 422:
        return ValidationError(message, status_code, body, retryable)
    if status_code == 503:
        return PresetUnavailableError(message, status_code, body, retryable)
    return ApiError(message, status_code, body, retryable)
