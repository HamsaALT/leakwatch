"""Output formats: human-readable text, JSON and SARIF (for GitHub code scanning)."""

from __future__ import annotations

import json
import os
import sys
from collections import Counter
from collections.abc import Sequence
from typing import TextIO

from . import __version__
from .models import Finding, Severity
from .rules import CONTENT_RULES, PATH_RULES

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


def use_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _shown(finding: Finding, redact: bool) -> str:
    return finding.redacted if redact else finding.secret


def render_text(findings: Sequence[Finding], redact: bool = True, color: bool = False) -> str:
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    if not findings:
        return paint("\033[32m", "No secrets found.") + "\n"

    lines: list[str] = []
    ordered = sorted(findings, key=lambda f: (-f.severity, f.file, f.line))
    for f in ordered:
        label = paint(_COLORS[f.severity], f"[{f.severity.name}]".ljust(10))
        lines.append(f"{label} {paint(_BOLD, f.description)}  {paint(_DIM, f.rule_id)}")
        lines.append(f"           {f.location()}")
        if f.commit:
            lines.append(f"           commit {f.commit[:12]}")
        lines.append(f"           value: {_shown(f, redact)}")
        lines.append("")

    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[s]} {s.name.lower()}" for s in sorted(counts, reverse=True))
    noun = "secret" if len(findings) == 1 else "secrets"
    lines.append(paint(_BOLD, f"Found {len(findings)} possible {noun} ({summary})."))
    if any(f.commit for f in findings):
        lines.append(
            "Secrets in the git history stay readable after you delete them. Revoke and rotate each one."
        )
    else:
        lines.append(
            "Remove each secret from the code, move it to an environment variable, "
            "and rotate it if it was ever pushed."
        )
    return "\n".join(lines) + "\n"


def render_json(findings: Sequence[Finding], redact: bool = True) -> str:
    payload = {
        "tool": "leakwatch",
        "version": __version__,
        "count": len(findings),
        "findings": [
            {
                "rule": f.rule_id,
                "description": f.description,
                "severity": str(f.severity),
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "commit": f.commit,
                "secret": _shown(f, redact),
                "fingerprint": f.fingerprint,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def render_sarif(findings: Sequence[Finding]) -> str:
    """SARIF 2.1.0, the format GitHub code scanning reads.

    Secrets are always redacted here, because SARIF reports are uploaded
    and shown in the GitHub UI.
    """
    all_rules = [(r.id, r.description, r.severity) for r in (*CONTENT_RULES, *PATH_RULES)]
    rule_index = {rule_id: i for i, (rule_id, _, _) in enumerate(all_rules)}

    results = []
    for f in findings:
        region = {"startLine": max(f.line, 1)}
        if f.column > 0:
            region["startColumn"] = f.column
        message = f"{f.description}: {f.redacted}"
        if f.commit:
            message += f" (introduced in commit {f.commit[:12]})"
        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": region,
                        }
                    }
                ],
                "partialFingerprints": {"leakwatch/v1": f.fingerprint},
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leakwatch",
                        "version": __version__,
                        "informationUri": "https://github.com/HamsaALT/leakwatch",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": description},
                                "defaultConfiguration": {"level": _SARIF_LEVEL[severity]},
                                "properties": {"severity": str(severity)},
                            }
                            for rule_id, description, severity in all_rules
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def render(findings: Sequence[Finding], fmt: str, redact: bool = True, stream: TextIO = sys.stdout) -> str:
    if fmt == "json":
        return render_json(findings, redact)
    if fmt == "sarif":
        return render_sarif(findings)
    return render_text(findings, redact, color=use_color(stream))
