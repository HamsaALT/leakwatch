"""Installs leakwatch as a git pre-commit hook."""

from __future__ import annotations

import stat
import sys
from pathlib import Path

from .git import repo_root, run_git

HOOK_MARKER = "# installed by leakwatch"


def hook_script(python: str) -> str:
    return (
        "#!/bin/sh\n"
        f"{HOOK_MARKER}\n"
        "# Blocks the commit if a secret is found in the staged files.\n"
        "# Bypass once with: git commit --no-verify (only if you are sure).\n"
        f'"{python}" -m leakwatch scan --staged\n'
    )


def install_hook(path: Path, force: bool = False) -> Path:
    root = repo_root(path)
    hooks_dir = Path(run_git(["rev-parse", "--git-path", "hooks"], root).decode().strip())
    if not hooks_dir.is_absolute():
        hooks_dir = root / hooks_dir
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-commit"

    if hook.exists() and HOOK_MARKER not in hook.read_text(errors="replace") and not force:
        raise FileExistsError(
            f"{hook} already exists and was not created by leakwatch. Use --force to replace it."
        )
    hook.write_text(hook_script(sys.executable), encoding="utf-8")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return hook
