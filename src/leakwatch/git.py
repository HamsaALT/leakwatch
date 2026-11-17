"""Git integration: scan staged changes and the full commit history."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .ignore import IgnoreRules
from .models import Finding
from .scanner import ScanOptions, deduplicate, scan_bytes, scan_path_name, scan_text

_COMMIT_MARKER = "\x1ecommit:"
_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class GitError(RuntimeError):
    pass


def run_git(args: list[str], cwd: Path) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotepath=false", *args],
            cwd=cwd,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    if result.returncode != 0:
        message = result.stderr.decode(errors="replace").strip()
        raise GitError(message or f"git {' '.join(args)} failed")
    return result.stdout


def repo_root(path: Path) -> Path:
    out = run_git(["rev-parse", "--show-toplevel"], path)
    return Path(out.decode().strip())


def scan_staged(path: Path, options: ScanOptions | None = None) -> list[Finding]:
    """Scan the staged version of every added, copied, modified or renamed file.

    This is what the pre-commit hook runs, so a secret is caught before it
    ever becomes part of a commit.
    """
    options = options or ScanOptions()
    root = repo_root(path)
    ignore = IgnoreRules.load(root)
    names = run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], root)
    findings: list[Finding] = []
    for raw_name in filter(None, names.split(b"\x00")):
        name = raw_name.decode("utf-8", errors="replace")
        if ignore.is_ignored_file(PurePosixPath(name)):
            continue
        data = run_git(["show", f":{name}"], root)
        findings.extend(scan_bytes(data, name, options))
    return findings


@dataclass
class _Chunk:
    commit: str
    path: str
    lines: list[str] = field(default_factory=list)
    numbers: list[int] = field(default_factory=list)


def _parse_log(log: str) -> Iterator[_Chunk]:
    """Split ``git log -p`` output into the lines each commit added per file."""
    commit = ""
    chunk: _Chunk | None = None
    next_line = 0

    for line in log.split("\n"):
        if line.startswith(_COMMIT_MARKER):
            if chunk:
                yield chunk
            chunk = None
            commit = line[len(_COMMIT_MARKER) :].strip()
        elif line.startswith("diff --git "):
            if chunk:
                yield chunk
            chunk = None
        elif line.startswith("+++ "):
            target = line[4:]
            if target == "/dev/null":
                chunk = None  # file was deleted, nothing was added
            else:
                chunk = _Chunk(commit=commit, path=target[2:] if target.startswith("b/") else target)
        elif chunk is not None and (match := _HUNK_HEADER.match(line)):
            next_line = int(match.group(1))
        elif chunk is not None and line.startswith("+"):
            chunk.lines.append(line[1:])
            chunk.numbers.append(next_line)
            next_line += 1
    if chunk:
        yield chunk


def scan_history(path: Path, options: ScanOptions | None = None) -> list[Finding]:
    """Scan every line ever added in any commit on any branch.

    A secret that was committed and later deleted is still in the history
    and still readable by anyone who can clone the repository.
    """
    options = options or ScanOptions()
    root = repo_root(path)
    ignore = IgnoreRules.load(root)
    log = run_git(
        [
            "log",
            "-p",
            "--all",
            "--reverse",
            "--no-color",
            "--no-ext-diff",
            "--unified=0",
            f"--format={_COMMIT_MARKER}%H",
        ],
        root,
    ).decode("utf-8", errors="replace")

    findings: list[Finding] = []
    for chunk in _parse_log(log):
        if ignore.is_ignored_file(PurePosixPath(chunk.path)):
            continue
        findings.extend(scan_path_name(chunk.path, options, chunk.commit))
        if chunk.lines:
            findings.extend(
                scan_text("\n".join(chunk.lines), chunk.path, options, chunk.commit, chunk.numbers)
            )
    # Oldest commits come first, so deduplicating keeps the commit that
    # introduced each secret.
    return deduplicate(findings)
