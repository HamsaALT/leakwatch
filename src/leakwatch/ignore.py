"""Decides which files are skipped during a scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

IGNORE_FILE_NAME = ".leakwatchignore"
INLINE_IGNORE_MARKER = "leakwatch:ignore"

DEFAULT_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        "target",
        ".gradle",
        ".idea",
        ".next",
        "coverage",
        "vendor",
    }
)

DEFAULT_MAX_FILE_SIZE = 1_000_000  # 1 MB


@dataclass
class IgnoreRules:
    """Glob patterns from ``.leakwatchignore`` plus the built-in defaults.

    Patterns work like a simplified ``.gitignore``:
    ``*.min.js`` matches the file name anywhere, ``docs/*.md`` matches the
    path relative to the scan root, and a trailing ``/`` matches a folder.
    """

    patterns: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, root: Path) -> IgnoreRules:
        ignore_file = root / IGNORE_FILE_NAME
        if not ignore_file.is_file():
            return cls()
        patterns = []
        for raw in ignore_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
        return cls(patterns)

    def is_ignored_dir(self, relative: PurePosixPath) -> bool:
        if relative.name in DEFAULT_IGNORED_DIRS:
            return True
        rel = relative.as_posix()
        for pattern in self.patterns:
            if pattern.endswith("/"):
                folder = pattern.rstrip("/")
                if fnmatch(rel, folder) or fnmatch(relative.name, folder):
                    return True
        return False

    def is_ignored_file(self, relative: PurePosixPath) -> bool:
        rel = relative.as_posix()
        for pattern in self.patterns:
            if pattern.endswith("/"):
                if any(fnmatch(part, pattern.rstrip("/")) for part in relative.parts[:-1]):
                    return True
                continue
            target = rel if "/" in pattern else relative.name
            if fnmatch(target, pattern.lstrip("/")):
                return True
        return False


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]
