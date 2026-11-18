"""Baselines: accept findings you already know about, fail only on new ones.

Useful when adding leakwatch to an existing project. You record today's
findings once, rotate those secrets, and from then on the scan only fails
when something new shows up.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from .models import Finding

DEFAULT_BASELINE = ".leakwatch-baseline.json"


def write_baseline(findings: Iterable[Finding], path: Path) -> int:
    entries = sorted(
        {
            f.fingerprint: {"fingerprint": f.fingerprint, "rule": f.rule_id, "file": f.file} for f in findings
        }.values(),
        key=lambda e: (e["file"], e["rule"]),
    )
    path.write_text(json.dumps({"version": 1, "accepted": entries}, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load_baseline(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise ValueError(f"could not read baseline {path}: {exc}") from exc
    return {entry["fingerprint"] for entry in data.get("accepted", [])}


def filter_known(findings: Iterable[Finding], known: set[str]) -> list[Finding]:
    return [f for f in findings if f.fingerprint not in known]
