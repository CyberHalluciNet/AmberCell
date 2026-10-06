"""Evidence record identifiers."""

from __future__ import annotations

import secrets


def new_session_id(prefix: str = "fp") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def new_event_id(prefix: str = "evt") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"
