"""Authority levels: the bank's delegated-authority matrix, applied to agents.

A new cashier does not get the same cash limit as a branch manager. Likewise an
unproven agent should start on a short leash and earn more room.
"""
from __future__ import annotations

from .teller import Limits

LEVELS: dict[str, dict] = {
    "trainee": {
        "label": "Trainee",
        "blurb": "New or untrusted agent. Tiny budget, a few writes, a handful of commands.",
        "limits": Limits(risk_budget=30, max_writes=3, max_commands=5, max_bytes_written=20_000),
    },
    "standard": {
        "label": "Standard",
        "blurb": "Default cashier limits. Enough for a normal bug-fix session.",
        "limits": Limits(),
    },
    "senior": {
        "label": "Senior",
        "blurb": "Proven agent on a larger task. Wider budget, still never past hard blocks.",
        "limits": Limits(risk_budget=200, max_writes=30, max_commands=40, max_bytes_written=1_000_000),
    },
}


def limits_for(level: str) -> Limits:
    """A fresh Limits object for the level (never shared between sessions)."""
    if level not in LEVELS:
        raise ValueError(f"unknown authority level '{level}', choose from {', '.join(LEVELS)}")
    return Limits(**vars(LEVELS[level]["limits"]))
