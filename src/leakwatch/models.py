"""Core data types shared across the scanner."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """How bad a leaked value is. Ordered so they can be compared with < and >."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            allowed = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{value}' (expected one of: {allowed})") from exc

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """A single suspected secret found in a file (or in a commit)."""

    rule_id: str
    description: str
    severity: Severity
    file: str
    line: int
    column: int
    secret: str
    commit: str | None = None

    @property
    def redacted(self) -> str:
        """The secret with everything but the first few characters hidden."""
        return redact(self.secret)

    @property
    def fingerprint(self) -> str:
        """Stable id used by baselines.

        The line number is left out on purpose, so a known finding stays
        accepted when code above it moves.
        """
        raw = f"{self.rule_id}:{self.file}:{self.secret}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def location(self) -> str:
        if self.line <= 0:
            return self.file
        return f"{self.file}:{self.line}:{self.column}"


def redact(value: str, visible: int = 4) -> str:
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * min(len(value) - visible, 12)
