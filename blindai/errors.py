"""The exception taxonomy.

Every failure in this client raises. **No error path produces an allow.** If your application needs
a fallback when authorization is unavailable, catch the error and make that decision in your own
code, where a reviewer can see it and where it is your name on the commit.

That is not fastidiousness. A client that decides on its own is a second enforcement engine, and a
second enforcement engine has to be kept correct forever -- which is how the previous client came to
turn every error into an allow by default.
"""
from __future__ import annotations

from typing import Any


class BlindAIError(Exception):
    """Base for everything this client raises."""


class TransportError(BlindAIError):
    """The request never completed: connection refused, DNS failure, TLS problem."""


class TimeoutError(TransportError):
    """The request did not complete within the configured timeout."""


class ApiError(BlindAIError):
    """A non-2xx response that is not one of the more specific cases below."""

    def __init__(self, message: str, status_code: int, body: dict[str, Any] | None = None,
                 retryable: bool = False) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        #: Whether this status was one the client would retry. Useful when deciding what to do in
        #: a caller-side fallback: a 429 says come back, a 403 says never.
        self.retryable = retryable


class AuthError(ApiError):
    """401 or 403. The server's own `detail` string is included, because it is the useful half --
    "Invalid or expired API key" tells you more than the status code does."""


class ValidationError(ApiError):
    """422. Built from `loc` and `msg` only.

    FastAPI's validation entries also carry an `input` field echoing the body you submitted, which
    on a real call contains the caller's `input_text`. This client never reads it, so it cannot end
    up in a log or an error surfaced to an end user.
    """


class PresetUnavailableError(ApiError):
    """503, when a preset is not running on this deployment.

    Not retried: it is a configuration answer, not a transient one. The server's detail names the
    preset, lists what is running, and says which variable to set.
    """


class ContractError(BlindAIError):
    """The response carried no usable decision.

    Raised when a body has neither `blocked` nor `allowed`, or has one that is not a bool. This is
    the single most important error in the client: defaulting to "allow" here is exactly the defect
    that made the previous version report every block as an allow.
    """
