"""Teller limits: a per-session risk budget, like a cashier's cash limit.

Every attempted action costs points by risk tier, *including blocked attempts*:
an agent that keeps trying forbidden things burns its own budget and gets
frozen until a human tops the limit up.
"""
from __future__ import annotations

from dataclasses import dataclass

from .risk import HIGH, LOW, MEDIUM

POINTS = {LOW: 1, MEDIUM: 5, HIGH: 20}


@dataclass
class Limits:
    risk_budget: int = 80
    max_writes: int = 10
    max_commands: int = 15
    max_bytes_written: int = 200_000


class Teller:
    def __init__(self, limits: Limits | None = None):
        self.limits = limits or Limits()
        self.used = 0
        self.writes = 0
        self.commands = 0
        self.network = 0
        self.bytes_written = 0
        self.frozen = False
        self.freeze_reason = ""

    def precheck(self, tool: str, tier: str, size: int = 0) -> tuple[bool, str]:
        if self.frozen:
            return False, self.freeze_reason
        if self.used + POINTS[tier] > self.limits.risk_budget:
            self.frozen = True
            self.freeze_reason = (
                f"risk budget exhausted ({self.used}/{self.limits.risk_budget} points used). "
                "Session frozen until a human raises the limit."
            )
            return False, self.freeze_reason
        if tool == "write_file":
            if self.writes + 1 > self.limits.max_writes:
                return False, f"write limit reached ({self.limits.max_writes} files per session)"
            if self.bytes_written + size > self.limits.max_bytes_written:
                return False, f"byte limit reached ({self.limits.max_bytes_written} bytes written per session)"
        if tool == "run_command" and self.commands + 1 > self.limits.max_commands:
            return False, f"command limit reached ({self.limits.max_commands} per session)"
        return True, ""

    def charge(self, tier: str) -> None:
        self.used += POINTS[tier]

    def record_exec(self, tool: str, size: int = 0) -> None:
        if tool == "write_file":
            self.writes += 1
            self.bytes_written += size
        elif tool == "run_command":
            self.commands += 1
        elif tool == "http_post":
            self.network += 1

    def top_up(self, points: int) -> None:
        self.limits.risk_budget += points
        if self.used < self.limits.risk_budget:
            self.frozen = False
            self.freeze_reason = ""

    def snapshot(self) -> dict:
        return {
            "used": self.used, "budget": self.limits.risk_budget, "writes": self.writes,
            "max_writes": self.limits.max_writes, "commands": self.commands,
            "max_commands": self.limits.max_commands, "bytes": self.bytes_written,
            "max_bytes": self.limits.max_bytes_written, "network": self.network, "frozen": self.frozen,
        }
