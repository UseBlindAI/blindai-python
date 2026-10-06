"""The client's wire constants match the spec's (specs/wire-constants.json in the BlindAI repo).

The fixture is a verbatim copy. When the spec changes, copy it again: this test then says which
constant the client has to follow.
"""
from __future__ import annotations

import json
from pathlib import Path

from blindai import IDENTITY_HEADER

SPEC = json.loads((Path(__file__).parent / "fixtures" / "wire-constants.json").read_text())


def test_the_identity_header_is_the_specs():
    assert IDENTITY_HEADER == SPEC["identity"]["header"]


def test_the_spec_copy_is_the_version_this_client_was_written_against():
    assert SPEC["version"] == "1.0.0"
