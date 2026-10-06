"""Identity tokens: exchanged once per call, sent only when held, never sent empty."""
from __future__ import annotations

import json

import httpx
import pytest

from blindai import IDENTITY_HEADER, BlindAIClient, ContractError


def recording(body):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=json.dumps(body).encode(),
                              headers={"content-type": "application/json"})

    return seen, httpx.MockTransport(handler)


ALLOW = {"allowed": True, "blocked": False, "threats": []}


def client(transport):
    return BlindAIClient("ba_live_test", "http://test", max_retries=0, transport=transport)


def test_a_call_with_a_token_carries_it_and_one_without_carries_no_header():
    seen, transport = recording(ALLOW)
    c = client(transport)
    c.authorize("pay", tool="pay", identity_token="tok-1")
    c.authorize("hello")
    assert seen[0].headers[IDENTITY_HEADER] == "tok-1"
    assert IDENTITY_HEADER not in seen[1].headers


@pytest.mark.parametrize("bad", ["", "   "])
def test_an_empty_token_is_refused_before_any_request(bad):
    seen, transport = recording(ALLOW)
    with pytest.raises(ValueError):
        client(transport).authorize("pay", identity_token=bad)
    assert seen == []


def test_the_exchange_posts_the_runtime_secret_and_returns_the_grant():
    seen, transport = recording({"tokens": {"a-1": "tok-1"}, "expires_in": 14400})
    grant = client(transport).exchange_tokens("rs_secret", ["a-1"])
    assert seen[0].url.path == "/v1/cp/tokens"
    assert json.loads(seen[0].content) == {"runtime_secret": "rs_secret", "agent_ids": ["a-1"]}
    assert grant.tokens == {"a-1": "tok-1"} and grant.expires_in == 14400


@pytest.mark.parametrize("body", [{}, {"tokens": []}, {"tokens": {"a": 1}, "expires_in": 1},
                                  {"tokens": {}, "expires_in": "soon"}])
def test_a_body_that_is_not_a_grant_is_a_contract_error(body):
    _seen, transport = recording(body)
    with pytest.raises(ContractError):
        client(transport).exchange_tokens("rs_secret", ["a-1"])
