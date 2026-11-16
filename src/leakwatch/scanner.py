"""Turns files and text into findings."""

from __future__ import annotations

import os
from bisect import bisect_right
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .ignore import DEFAULT_MAX_FILE_SIZE, INLINE_IGNORE_MARKER, IgnoreRules, is_binary
from .models import Finding
from .rules import CONTENT_RULES, PATH_RULES, PathRule, Rule


@dataclass(frozen=True)
class ScanOptions:
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    content_rules: tuple[Rule, ...] = CONTENT_RULES
    path_rules: tuple[PathRule, ...] = PATH_RULES


def scan_text(
    text: str,
    path: str,
    options: ScanOptions | None = None,
    commit: str | None = None,
    line_numbers: list[int] | None = None,
) -> list[Finding]:
    """Scan ``text`` as if it were the contents of ``path``.

    ``line_numbers`` lets the git history scanner pass in the real line
    numbers of the lines it extracted from a diff.
    """
    options = options or ScanOptions()
    lowered = text.lower()
    rules = [r for r in options.content_rules if r.applies_to(path) and r.might_match(lowered)]
    if not rules:
        return []

    # Offsets where each line starts, so a match position can be turned into
    # a line and column with a binary search. Only "\n" counts as a line break
    # (str.splitlines() would also break on rare characters like \x1c).
    line_starts: list[int] = []
    ignored_lines: set[int] = set()

    def line_index(position: int) -> int:
        if not line_starts:  # built on the first match only, most files have none
            line_starts.append(0)
            newline = text.find("\n")
            while newline != -1:
                line_starts.append(newline + 1)
                newline = text.find("\n", newline + 1)
            if INLINE_IGNORE_MARKER in text:
                ignored_lines.update(
                    i for i, line in enumerate(text.split("\n")) if INLINE_IGNORE_MARKER in line
                )
        return bisect_right(line_starts, position) - 1

    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []  # character spans already claimed by a rule

    for rule in rules:
        for match in rule.pattern.finditer(text):
            start, end = match.span(rule.secret_group)
            if start < 0:
                continue
            index = line_index(start)
            if index in ignored_lines:
                continue
            if any(start < t_end and t_start < end for t_start, t_end in taken):
                continue
            if not rule.accepts(match):
                continue
            taken.append((start, end))
            findings.append(
                Finding(
                    rule_id=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    file=path,
                    line=line_numbers[index] if line_numbers else index + 1,
                    column=start - line_starts[index] + 1,
                    secret=match.group(rule.secret_group),
                    commit=commit,
                )
            )
    findings.sort(key=lambda f: (f.line, f.column))
    return findings


def scan_path_name(path: str, options: ScanOptions | None = None, commit: str | None = None) -> list[Finding]:
    """Flag files that should not be committed at all, based on their name."""
    options = options or ScanOptions()
    return [
        Finding(
            rule_id=rule.id,
            description=rule.description,
            severity=rule.severity,
            file=path,
            line=0,
            column=0,
            secret=PurePosixPath(path).name,
            commit=commit,
        )
        for rule in options.path_rules
        if rule.matches(path)
    ]


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def scan_bytes(
    data: bytes, path: str, options: ScanOptions | None = None, commit: str | None = None
) -> list[Finding]:
    options = options or ScanOptions()
    findings = scan_path_name(path, options, commit)
    if len(data) > options.max_file_size or is_binary(data):
        return findings
    return findings + scan_text(decode(data), path, options, commit)


def iter_files(root: Path, ignore: IgnoreRules) -> Iterator[tuple[Path, PurePosixPath]]:
    """Walk ``root`` and yield (absolute path, path relative to root)."""
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        rel_dir = PurePosixPath(current.relative_to(root).as_posix())
        dirnames[:] = sorted(
            d for d in dirnames if not ignore.is_ignored_dir(rel_dir / d) and not (current / d).is_symlink()
        )
        for name in sorted(filenames):
            full = current / name
            rel = rel_dir / name if rel_dir.as_posix() != "." else PurePosixPath(name)
            if full.is_symlink() or ignore.is_ignored_file(rel):
                continue
            yield full, rel


def scan_directory(root: Path, options: ScanOptions | None = None) -> list[Finding]:
    options = options or ScanOptions()
    root = root.resolve()
    if root.is_file():
        return scan_bytes(root.read_bytes(), root.name, options)
    ignore = IgnoreRules.load(root)
    findings: list[Finding] = []
    for full, rel in iter_files(root, ignore):
        try:
            data = full.read_bytes()
        except OSError:
            continue
        findings.extend(scan_bytes(data, rel.as_posix(), options))
    return findings


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Keep one finding per (rule, file, secret).

    The git history scanner sees the same secret in every commit that
    touches the line; only the first sighting is useful.
    """
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return unique
