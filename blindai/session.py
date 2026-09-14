"""Session context: a correlation id and nothing else.

Carries `session_id` onto requests so multi-turn conversations can be analysed server-side. It
reads verdicts and never produces one -- there is deliberately no logic here that could change
what a decision says, because the moment context could alter a verdict it would be deciding.
"""
from __future__ import annotations

import uuid


class Session:
    """A conversation's correlation id, and a count of what passed through it."""

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id or f"sess_{uuid.uuid4().hex[:16]}"
        self.checked = 0
        self.blocked = 0

    def record(self, blocked: bool) -> None:
        """Note a decision that has already been made. Counting only."""
        self.checked += 1
        if blocked:
            self.blocked += 1

    def __repr__(self) -> str:
        return f"Session({self.session_id!r}, checked={self.checked}, blocked={self.blocked})"
