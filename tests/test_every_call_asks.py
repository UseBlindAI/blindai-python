"""Every public call either makes exactly one request, or raises.

The companion to the static no-local-verdicts check, covering what that one structurally cannot.
A fabricated allow is a literal a parser can find. These two are not:

  - Not asking. A rollout that samples traffic returns without a request for most calls. No
    permissive literal appears anywhere in it; it simply skips the question.
  - Reusing an answer. A verdict cache does make requests, just not for this call. The verdict it
    returns was real once, for different input, under a policy version that may since have changed.

Both produce a log that is not merely thin but false: it asserts that nothing else happened.

The invariant, stated so a client-side rate limiter still passes -- it raises before the transport,
which is correct, and "must reach the transport" would wrongly fail it:

    On return:  exactly one request was made for this call.
    On raise:   zero or one request was made.
    Always:     the Decision was built from the body served for THIS request.

The last line is what catches a cache: each response carries a unique nonce, and a returned
decision must carry that same nonce back in `raw`.
"""
from __future__ import annotations

import itertools
import json

import httpx
import pytest

from blindai import AuthError, BlindAIClient, RateLimiter, RateLimitExceeded, TransportError

_nonce = itertools.count()


def counting_transport(body_for=None, status=200):
    """A transport that counts calls and stamps each response with a nonce unique to it."""
    state = {"requests": 0, "nonces": []}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"] += 1
        nonce = f"n-{next(_nonce)}"
        state["nonces"].append(nonce)
        body = dict(body_for(request) if body_for else
                    {"allowed": True, "blocked": False, "threats": [], "latency_ms": 1.0})
        body["request_id"] = nonce
        return httpx.Response(status, content=json.dumps(body).encode(),
                              headers={"content-type": "application/json"})

    return state, httpx.MockTransport(handler)


def client(transport, **kw):
    return BlindAIClient("ba_live_test", "http://test", max_retries=0, transport=transport, **kw)


RAG_BODY = {"threats_found": False, "total_documents": 1, "safe_count": 1,
            "unsafe_count": 0, "flagged_indices": []}


@pytest.mark.parametrize("name,call,body_for", [
    ("authorize", lambda c: c.authorize("hello"), None),
    ("scan", lambda c: c.scan("hello"), None),
    ("rag_scan", lambda c: c.rag_scan([{"content": "hello"}]), lambda r: RAG_BODY),
    ("authorize with an identity token",
     lambda c: c.authorize("pay", tool="pay", identity_token="tok"), None),
    ("exchange_tokens", lambda c: c.exchange_tokens("rs_secret", ["a-1"]),
     lambda r: {"tokens": {"a-1": "tok"}, "expires_in": 60}),
])
def test_a_returning_call_made_exactly_one_request(name, call, body_for):
    state, transport = counting_transport(body_for)
    call(client(transport))
    assert state["requests"] == 1, (
        f"{name} returned after {state['requests']} requests; a value without a question is a log "
        "entry asserting something that never happened")


def test_batch_makes_one_request_per_item_and_answers_none_without_one():
    state, transport = counting_transport()
    items = client(transport).authorize_batch(
        [{"input_text": "a"}, {"input_text": "b"}, {"input_text": "c"}])
    assert state["requests"] == 3
    assert [i["ok"] for i in items] == [True, True, True]
    assert all("decision" in i for i in items)


def test_a_failed_batch_item_carries_no_decision():
    """The shape that matters: a failure must not be mistakable for an allow."""
    def handler(request):
        return httpx.Response(401, content=b'{"detail":"Invalid or expired API key"}',
                              headers={"content-type": "application/json"})
    items = client(httpx.MockTransport(handler)).authorize_batch([{"input_text": "a"}])
    assert items[0]["ok"] is False
    assert "decision" not in items[0], "a failed item must carry no decision at all"


def test_a_raising_call_made_at_most_one_request():
    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        return httpx.Response(401, content=b'{"detail":"Invalid or expired API key"}',
                              headers={"content-type": "application/json"})

    with pytest.raises(AuthError):
        client(httpx.MockTransport(handler)).authorize("hello")
    assert state["n"] <= 1, f"a 401 must not be retried; made {state['n']} requests"


def test_an_unreachable_transport_raises_rather_than_returning():
    """The rollout shape: anything that short-circuits before the transport must raise."""
    def handler(request):
        raise httpx.ConnectError("unreachable", request=request)
    with pytest.raises(TransportError):
        client(httpx.MockTransport(handler)).authorize("hello")


def test_the_rate_limiter_raises_and_never_returns_a_verdict():
    """The one piece of local logic allowed, and the reason it is allowed."""
    state, transport = counting_transport()
    c = client(transport, rate_limiter=RateLimiter(rate_per_second=1, burst=1))
    c.authorize("first")                       # consumes the only token
    with pytest.raises(RateLimitExceeded):
        c.authorize("second")
    assert state["requests"] == 1, "the refused call must not have reached the server either"


def test_the_decision_came_from_this_requests_response_not_an_earlier_one():
    state, transport = counting_transport()
    c = client(transport)

    first = c.authorize("same text every time")
    second = c.authorize("same text every time")

    assert state["requests"] == 2, (
        "identical input must still be asked about; a cached verdict outlives the policy that made it")
    assert state["nonces"][0] != state["nonces"][1]
    assert first.raw["request_id"] == state["nonces"][0]
    assert second.raw["request_id"] == state["nonces"][1], (
        "the second decision carried the first response back: an answer was reused")


def test_a_second_exchange_asks_again():
    """A token cache is a cache of an identity decision: a revoked agent would keep its token until
    the cache said otherwise. Each exchange is its own request."""
    state, transport = counting_transport(lambda r: {"tokens": {"a-1": "tok"}, "expires_in": 60})
    c = client(transport)
    c.exchange_tokens("rs_secret", ["a-1"])
    c.exchange_tokens("rs_secret", ["a-1"])
    assert state["requests"] == 2
