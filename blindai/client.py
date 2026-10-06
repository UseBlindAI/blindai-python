"""The wire client.

Every public method either makes exactly one request or raises. Nothing here caches a verdict,
samples traffic, or produces a decision of its own -- the three shapes that let a previous client
answer without asking.
"""
from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

import httpx
from typing_extensions import Self

from ._http import error_for, is_retryable, safe_json
from .errors import TimeoutError as BlindAITimeoutError
from .errors import TransportError
from .parse import parse_decision
from .rate_limit import RateLimiter
from .types import Decision, TokenGrant
from .wire import IDENTITY_HEADER, TOKENS_PATH

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BASE = 0.2


class BlindAIClient:
    """A synchronous client for the BlindAI authorization API.

    Args:
        api_key: must start with `ba_`.
        base_url: required. There is no production default: a client that guesses where to send
            authorization requests is a client that can be pointed somewhere else.
        timeout: seconds per request.
        max_retries: retries for 5xx, 408 and 429 only.
        auth_style: "bearer" or "x-api-key"; the server accepts both.
        rate_limiter: optional local limiter. It raises when the bucket is empty and never
            returns a verdict.
        transport: an httpx transport, for tests.
    """

    def __init__(self, api_key: str, base_url: str, *, timeout: float = DEFAULT_TIMEOUT,
                 max_retries: int = DEFAULT_MAX_RETRIES, retry_base: float = DEFAULT_RETRY_BASE,
                 auth_style: str = "bearer", rate_limiter: RateLimiter | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        if not api_key.startswith("ba_"):
            raise ValueError("api_key must start with 'ba_'; a Clerk JWT is rejected on these routes")
        if not base_url:
            raise ValueError(
                "base_url is required and has no default: state the deployment explicitly")
        if auth_style not in ("bearer", "x-api-key"):
            raise ValueError("auth_style must be 'bearer' or 'x-api-key'")

        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self.retry_base = retry_base
        self.rate_limiter = rate_limiter
        headers = ({"Authorization": f"Bearer {api_key}"} if auth_style == "bearer"
                   else {"X-API-Key": api_key})
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout,
                                    headers={**headers, "Content-Type": "application/json"},
                                    transport=transport)

    # -- public surface -------------------------------------------------------------------

    def authorize(self, input_text: str, *, identity_token: str | None = None,
                  **fields: Any) -> Decision:
        """POST /v1/authorize. Exactly one request, or an exception.

        `identity_token`: the agent's token from `exchange_tokens`. A tool call needs one while the
        deployment's control plane is on; it is refused `identity_token_required` without.
        """
        return parse_decision(self._post("/v1/authorize", _body(input_text, fields),
                                         headers=_identity(identity_token)))

    def scan(self, input_text: str, *, identity_token: str | None = None,
             **fields: Any) -> Decision:
        """POST /v1/scan -- identical models to authorize; the non-enforcing sibling."""
        return parse_decision(self._post("/v1/scan", _body(input_text, fields),
                                         headers=_identity(identity_token)))

    def exchange_tokens(self, runtime_secret: str, agent_ids: Sequence[str]) -> TokenGrant:
        """POST /v1/cp/tokens: a runtime's secret for its agents' identity tokens.

        Exactly one request, or an exception. An agent id the runtime does not own, or one that is
        not active, is absent from the grant rather than an error -- the server's own rule, so a
        caller cannot probe which agents exist. Tokens are short-lived (`expires_in` seconds).
        """
        if not runtime_secret:
            raise ValueError("runtime_secret is required")
        body = self._post(TOKENS_PATH, {"runtime_secret": runtime_secret,
                                        "agent_ids": list(agent_ids)})
        return TokenGrant.from_wire(body)

    def rag_scan(self, documents: Sequence[dict[str, Any]],
                 threshold: float | None = None) -> dict[str, Any]:
        """POST /v1/rag/scan."""
        if not documents:
            raise ValueError("documents must not be empty")
        payload: dict[str, Any] = {"documents": list(documents)}
        if threshold is not None:
            payload["threshold"] = threshold
        body = self._post("/v1/rag/scan", payload)
        if not isinstance(body, dict) or "threats_found" not in body:
            from .errors import ContractError
            raise ContractError(
                "not a RAGScanResponse: missing 'threats_found'; refusing to infer a result")
        return body

    def authorize_batch(self, requests: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
        """One request per item. A failed item carries its error and NO decision.

        There is deliberately no `continue_on_error` and no collapsed verdict: an item that failed
        must not be mistakable for one that was allowed.
        """
        results: list[dict[str, Any]] = []
        for index, request in enumerate(requests):
            text = request.get("input_text")
            if not isinstance(text, str):
                results.append({"ok": False, "index": index,
                                "error": ValueError("input_text is required")})
                continue
            fields = {k: v for k, v in request.items() if k != "input_text"}
            try:
                results.append({"ok": True, "index": index,
                                "decision": self.authorize(text, **fields)})
            except Exception as exc:  # noqa: BLE001 - carried, never converted to a verdict
                results.append({"ok": False, "index": index, "error": exc})
        return results

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals ------------------------------------------------------------------------

    def _post(self, path: str, payload: dict[str, Any],
              headers: dict[str, str] | None = None) -> Any:
        if self.rate_limiter is not None:
            self.rate_limiter.acquire()   # raises; never returns a verdict

        last: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.post(path, json=payload, headers=headers)
            except httpx.TimeoutException:
                last = BlindAITimeoutError(f"request to {path} timed out")
            except httpx.RequestError as exc:
                last = TransportError(f"request to {path} failed: {exc}")
            else:
                if response.status_code < 300:
                    body = safe_json(response)
                    if body is None:
                        from .errors import ContractError
                        raise ContractError(
                            f"{path} returned {response.status_code} with a non-JSON body")
                    return body
                error = error_for(response.status_code, safe_json(response), response.text)
                # A 4xx that cannot succeed is not retried: every attempt produces the identical
                # failure, and waiting to report a typo makes it look like a network problem.
                if not is_retryable(response.status_code) or attempt == self.max_retries:
                    raise error
                last = error

            if attempt < self.max_retries:
                time.sleep(self.retry_base * (2 ** attempt))

        assert last is not None
        raise last


def _identity(token: str | None) -> dict[str, str] | None:
    """The identity header, only when a token is held -- never sent empty (wire-constants.json)."""
    if token is None:
        return None
    if not isinstance(token, str) or not token.strip():
        raise ValueError("identity_token must be a non-empty string, or omitted")
    return {IDENTITY_HEADER: token}


def _body(input_text: str, fields: dict[str, Any]) -> dict[str, Any]:
    """The request body. Only `input_text` is required; the server defaults the rest.

    There is no free-form `metadata` field on AuthorizeRequest, so anything not recognised here
    would be dropped by the server. Passing it on silently would be worse than refusing it.
    """
    allowed = {"user_id", "action", "agent_id", "role", "tool", "preset", "session_id",
               "parameters", "target_space_id"}
    unknown = set(fields) - allowed
    if unknown:
        raise ValueError(
            f"unknown field(s) {sorted(unknown)}; AuthorizeRequest accepts {sorted(allowed)} "
            "and has no free-form metadata field")
    return {"input_text": input_text, **{k: v for k, v in fields.items() if v is not None}}
