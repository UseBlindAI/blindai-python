"""The P1 journey's calls, through this client, against a real control plane (pilot S).

Run against a deployment seeded by BlindAI's `scripts/pilot_stack.py`: one organisation, a runtime
declaring `purchase.order`, an agent, and a binding refusing orders over 1000. It prints the four
variables below. Skipped when BLINDAI_RUNTIME_SECRET is unset: these need a control plane, which
the basic contract tests above do not.
"""
from __future__ import annotations

import os

import pytest

from blindai import BlindAIClient

BASE = os.getenv("BLINDAI_BASE_URL")
KEY = os.getenv("BLINDAI_API_KEY")
SECRET = os.getenv("BLINDAI_RUNTIME_SECRET")
AGENT = os.getenv("BLINDAI_AGENT_ID")

pytestmark = pytest.mark.skipif(not (BASE and KEY and SECRET and AGENT),
                                reason="needs a seeded control plane (BLINDAI_RUNTIME_SECRET)")


@pytest.fixture(scope="module")
def agent():
    with BlindAIClient(KEY, BASE) as c:
        grant = c.exchange_tokens(SECRET, [AGENT])
        assert AGENT in grant.tokens, "the runtime's own active agent was not granted a token"
        yield c, grant.tokens[AGENT]


def order(c, token, amount):
    return c.authorize("place the order", tool="purchase.order", action="run",
                       parameters={"amount": amount, "supplier": "Acier SA"},
                       identity_token=token)


def test_an_order_under_the_threshold_is_allowed(agent):
    c, token = agent
    assert order(c, token, 250).allowed


def test_an_order_over_the_threshold_is_refused_by_the_rule(agent):
    c, token = agent
    d = order(c, token, 5000)
    assert d.blocked and d.reason == "Orders over 1000 need a human.", d.raw


def test_a_tool_call_without_the_token_is_refused(agent):
    c, _token = agent
    d = c.authorize("place the order", tool="purchase.order",
                    parameters={"amount": 250, "supplier": "Acier SA"})
    assert d.blocked and d.reason == "identity_token_required", d.raw
