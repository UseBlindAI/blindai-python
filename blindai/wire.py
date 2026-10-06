"""The wire constants this client shares with the control plane.

The source of truth is `specs/wire-constants.json` in the BlindAI repository (Apache-2.0); a copy
lives at `tests/fixtures/wire-constants.json` and `tests/test_wire.py` holds this module to it, so
the header name cannot drift from the server's without a test going red.
"""
from __future__ import annotations

#: The header carrying an agent's identity token. Sent only when a token is held: absent is a valid
#: state, and an empty header reaches the server as something different from a missing one.
IDENTITY_HEADER = "X-BlindAI-Identity"

#: The control plane's token exchange: a runtime's secret for its agents' identity tokens.
TOKENS_PATH = "/v1/cp/tokens"
