"""The client's contract: what it sends, what it accepts, and what it refuses to guess."""
from __future__ import annotations

import json

import httpx
import pytest

from blindai import (
    ApiError,
    AuthError,
    BlindAIClient,
    ContractError,
    PresetUnavailableError,
    ValidationError,
    parse_decision,
)
from blindai.testing import decision, stub_transport

OK = {"allowed": True, "blocked": False, "threats": [], "latency_ms": 2.0}


def client(transport, **kw):
    return BlindAIClient("ba_live_test", "http://test", max_retries=0, transport=transport, **kw)


class TestTheParseContract:
    def test_a_block_is_a_block(self):
        d = parse_decision({"allowed": False, "blocked": True, "reason": "injection",
                            "latency_ms": 3.0})
        assert d.blocked is True and d.action == "block" and d.is_threat is True

    def test_a_body_with_no_verdict_raises_rather_than_allowing(self):
        """The single most important line in the client. The previous version defaulted here."""
        with pytest.raises(ContractError, match="missing 'blocked'"):
            parse_decision({"is_threat": False, "final_action": "allow"})

    @pytest.mark.parametrize("bad", ["false", 0, 1, None, [], {}])
    def test_a_verdict_that_is_not_a_bool_is_not_coerced(self, bad):
        with pytest.raises(ContractError, match="not bool"):
            parse_decision({"blocked": bad})

    def test_blocked_wins_over_allowed_when_both_are_present(self):
        assert parse_decision({"blocked": True, "allowed": True, "latency_ms": 0}).blocked is True

    def test_allowed_is_used_when_blocked_is_absent(self):
        assert parse_decision({"allowed": False, "latency_ms": 0}).blocked is True

    def test_threats_can_be_present_on_an_allowed_request(self):
        d = parse_decision({"allowed": True, "blocked": False, "latency_ms": 0,
                            "threats": [{"type": "pii", "confidence": 0.4}]})
        assert d.blocked is False and d.is_threat is True, (
            "code gating on is_threat would refuse work the policy permitted")
        assert d.threat_level == "medium"

    def test_confidence_is_the_maximum_across_threats(self):
        d = parse_decision({"blocked": True, "latency_ms": 0, "threats": [
            {"type": "a", "confidence": 0.3}, {"type": "b", "confidence": 0.91}]})
        assert d.confidence == 0.91

    def test_threat_level_is_never_none(self):
        assert parse_decision({"allowed": True, "blocked": False, "latency_ms": 0}).threat_level == "none"


class TestWhatGoesOnTheWire:
    def test_only_input_text_is_required(self):
        transport = stub_transport([decision.allow()])
        client(transport).authorize("hello")
        body = json.loads(transport.calls[0].content)
        assert body == {"input_text": "hello"}

    def test_known_fields_are_sent_through(self):
        transport = stub_transport([decision.allow()])
        client(transport).authorize("hello", tool="crm", role="user", preset="strict")
        body = json.loads(transport.calls[0].content)
        assert body["tool"] == "crm" and body["role"] == "user" and body["preset"] == "strict"

    def test_an_unknown_field_is_refused_rather_than_silently_dropped(self):
        """AuthorizeRequest has no free-form metadata field; sending one would be discarded by the
        server, and a client that lets you believe otherwise is worse than one that refuses."""
        with pytest.raises(ValueError, match="metadata"):
            client(stub_transport([decision.allow()])).authorize("hello", metadata={"a": 1})

    def test_the_api_key_must_look_like_an_api_key(self):
        with pytest.raises(ValueError, match="ba_"):
            BlindAIClient("eyJhbGciOi", "http://test")

    def test_base_url_has_no_default(self):
        with pytest.raises(ValueError, match="base_url"):
            BlindAIClient("ba_live_x", "")


class TestErrors:
    def test_a_bad_key_raises_with_the_servers_own_sentence(self):
        with pytest.raises(AuthError) as caught:
            client(stub_transport([decision.status(401, "Invalid or expired API key")])).authorize("x")
        assert "Invalid or expired API key" in str(caught.value)
        assert caught.value.status_code == 401

    def test_a_validation_error_names_the_field(self):
        detail = [{"type": "missing", "loc": ["body", "input_text"], "msg": "Field required",
                   "input": {"secret": "the caller's own text"}}]
        with pytest.raises(ValidationError) as caught:
            client(stub_transport([decision.status(422, detail)])).authorize("x")
        assert "input_text" in str(caught.value) and "Field required" in str(caught.value)
        assert "body" not in str(caught.value)
        assert "the caller's own text" not in str(caught.value), (
            "the 422 `input` echo must never reach a message; it contains the caller's input_text")

    def test_an_unavailable_preset_is_its_own_error_and_is_not_retried(self):
        with pytest.raises(PresetUnavailableError) as caught:
            client(stub_transport([decision.status(503, "preset 'balanced' is not running")])).authorize("x")
        assert caught.value.retryable is True  # 5xx generally is
        assert "balanced" in str(caught.value)

    def test_a_malformed_body_raises_rather_than_allowing(self):
        with pytest.raises(ContractError):
            client(stub_transport([decision.malformed()])).authorize("x")

    def test_a_non_json_body_does_not_replace_the_error(self):
        def handler(request):
            return httpx.Response(502, content=b"<html>502 Bad Gateway</html>")
        with pytest.raises(ApiError) as caught:
            client(httpx.MockTransport(handler)).authorize("x")
        assert caught.value.status_code == 502

    def test_a_transport_failure_raises(self):
        from blindai import TransportError
        with pytest.raises(TransportError):
            client(stub_transport([decision.down()])).authorize("x")


class TestTheStubRefusesToInvent:
    def test_an_unscripted_call_fails_the_test_rather_than_returning_an_allow(self):
        c = client(stub_transport([decision.allow()]))
        c.authorize("first")
        with pytest.raises(AssertionError, match="unscripted"):
            c.authorize("second")
