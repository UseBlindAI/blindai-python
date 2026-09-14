"""Test helpers: a scripted transport that fails an unscripted call.

The rule this follows is the client's own: never invent a response. If a test makes a call the
script did not anticipate, that is a bug in the test, and answering it with a fabricated allow
would hide exactly the kind of mistake the client is built to make loud.

    from blindai.testing import decision, stub_transport

    client = BlindAIClient("ba_live_t", "http://test",
                           transport=stub_transport([decision.block("prompt injection")]))
"""
from __future__ import annotations

import json
from typing import Any

import httpx


class _Decision:
    """Bodies a scripted response can carry. Each names the case it builds, so a fabricated allow
    only ever comes from an author asking for one."""

    @staticmethod
    def allow(**overrides: Any) -> dict[str, Any]:
        return {"allowed": True, "blocked": False, "threats": [], "threat_level": "none",
                "latency_ms": 1.0, **overrides}

    @staticmethod
    def block(reason: str = "blocked by policy", threats: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return {"allowed": False, "blocked": True, "reason": reason,
                "threats": threats or [{"type": "policy", "confidence": 0.95}],
                "threat_level": "high", "latency_ms": 1.0}

    @staticmethod
    def flagged(threats: list[dict[str, Any]]) -> dict[str, Any]:
        """Allowed, but carrying detected threats -- the case that catches code gating on
        `is_threat` when it should gate on `blocked`."""
        return {"allowed": True, "blocked": False, "threats": threats,
                "threat_level": "medium", "latency_ms": 1.0}

    @staticmethod
    def malformed() -> dict[str, Any]:
        """A body that is not an AuthorizeResponse. The client must raise, never allow."""
        return {"is_threat": False, "final_action": "allow"}

    @staticmethod
    def status(code: int, detail: Any = None) -> dict[str, Any]:
        return {"__status__": code, "detail": detail if detail is not None else "error"}

    @staticmethod
    def down(message: str = "Connection refused") -> dict[str, Any]:
        return {"__raise__": message}


decision = _Decision()


def stub_transport(script: list[dict[str, Any]]) -> httpx.MockTransport:
    """A transport that plays `script` in order and fails anything beyond it."""
    queue = list(script)
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if not queue:
            raise AssertionError(
                f"unscripted call to {request.url.path}; the stub refuses to invent a response "
                f"({len(calls)} call(s) made, {len(script)} scripted)")
        item = queue.pop(0)
        if "__raise__" in item:
            raise httpx.ConnectError(item["__raise__"], request=request)
        status = item.pop("__status__", 200) if "__status__" in item else 200
        return httpx.Response(status, content=json.dumps(item).encode(),
                              headers={"content-type": "application/json"})

    transport = httpx.MockTransport(handler)
    transport.calls = calls  # type: ignore[attr-defined]
    return transport
