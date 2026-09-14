"""Contract tests against a real server.

These are the tests that would have caught the original defect: the client posted to a route that
had never existed, and nothing noticed because every test used a stub.

CI must set BLINDAI_BASE_URL and BLINDAI_API_KEY. If they are missing the suite FAILS rather than
skipping, so a green build can never mean "we never checked". For local runs without a server, set
BLINDAI_CONTRACT_OPTIONAL=1.
"""
from __future__ import annotations

import os

import httpx
import pytest

from blindai import AuthError, BlindAIClient

BASE = os.getenv("BLINDAI_BASE_URL")
KEY = os.getenv("BLINDAI_API_KEY")
OPTIONAL = os.getenv("BLINDAI_CONTRACT_OPTIONAL") == "1"

pytestmark = pytest.mark.skipif(OPTIONAL and not (BASE and KEY),
                                reason="BLINDAI_CONTRACT_OPTIONAL=1 and no server configured")


@pytest.fixture(scope="module")
def live():
    assert BASE and KEY, (
        "BLINDAI_BASE_URL and BLINDAI_API_KEY are required for contract tests. "
        "Set BLINDAI_CONTRACT_OPTIONAL=1 to skip them locally; CI must not.")
    with BlindAIClient(KEY, BASE) as c:
        yield c


def test_authorize_exists_and_answers(live):
    d = live.authorize("hello", preset="permissive")
    assert d.action in ("allow", "block")


def test_scan_exists_and_answers(live):
    assert live.scan("hello", preset="permissive").action in ("allow", "block")


def test_the_route_the_old_client_used_is_gone():
    """`/v1/protect` never existed on this API. If it ever starts answering, something is serving
    a shape this client does not understand and the contract has drifted."""
    r = httpx.post(f"{BASE.rstrip('/')}/v1/protect", json={"text": "x"},
                   headers={"Authorization": f"Bearer {KEY}"}, timeout=10)
    assert r.status_code == 404, f"expected 404 from /v1/protect, got {r.status_code}"


def test_both_auth_styles_are_accepted():
    for style in ("bearer", "x-api-key"):
        with BlindAIClient(KEY, BASE, auth_style=style) as c:
            assert c.authorize("hello", preset="permissive").action in ("allow", "block")


def test_a_bad_key_raises_rather_than_returning_a_decision():
    with BlindAIClient("ba_live_not_a_real_key", BASE) as c, pytest.raises(AuthError):
        c.authorize("hello", preset="permissive")
