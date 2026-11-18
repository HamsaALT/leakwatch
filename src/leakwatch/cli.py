"""Command line interface.

Exit codes:
    0  no findings at or above --fail-on
    1  findings at or above --fail-on
    2  usage or runtime error
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .baseline import DEFAULT_BASELINE, filter_known, load_baseline, write_baseline
from .git import GitError, scan_history, scan_staged
from .hook import install_hook
from .ignore import DEFAULT_MAX_FILE_SIZE
from .models import Finding, Severity
from .report import render
from .rules import CONTENT_RULES, PATH_RULES
from .scanner import ScanOptions, deduplicate, scan_directory

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakwatch",
        description="Find API keys, passwords and other secrets in code and git history.",
    )
    parser.add_argument("--version", action="version", version=f"leakwatch {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a folder, the staged files or the git history")
    scan.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: .)")
    mode = scan.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan only files staged for commit")
    mode.add_argument("--history", action="store_true", help="scan every commit on every branch")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--output", "-o", type=Path, help="write the report to a file")
    scan.add_argument(
        "--fail-on",
        default="low",
        metavar="SEVERITY",
        help="lowest severity that makes the scan fail: low, medium, high, critical (default: low)",
    )
    scan.add_argument("--baseline", type=Path, help="ignore findings recorded in this baseline file")
    scan.add_argument("--no-redact", action="store_true", help="show full secret values (careful)")
    scan.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        metavar="BYTES",
        help=f"skip files larger than this (default: {DEFAULT_MAX_FILE_SIZE})",
    )

    base = sub.add_parser("baseline", help="record current findings so future scans only fail on new ones")
    base.add_argument("path", nargs="?", default=".")
    base.add_argument("--history", action="store_true", help="include findings from the git history")
    base.add_argument("--output", "-o", type=Path, default=None, help=f"default: <path>/{DEFAULT_BASELINE}")

    hook = sub.add_parser("install-hook", help="block commits that contain secrets")
    hook.add_argument("path", nargs="?", default=".")
    hook.add_argument("--force", action="store_true", help="replace an existing pre-commit hook")

    sub.add_parser("rules", help="list all detection rules")
    return parser


def _collect(path: Path, staged: bool, history: bool, options: ScanOptions) -> list[Finding]:
    if staged:
        return scan_staged(path, options)
    if history:
        return scan_history(path, options)
    return deduplicate(scan_directory(path, options))


def _cmd_scan(args: argparse.Namespace) -> int:
    fail_on = Severity.parse(args.fail_on)
    path = Path(args.path)
    if not path.exists():
        raise ValueError(f"path does not exist: {path}")

    options = ScanOptions(max_file_size=args.max_file_size)
    findings = _collect(path, args.staged, args.history, options)
    if args.baseline:
        findings = filter_known(findings, load_baseline(args.baseline))

    stream = sys.stdout
    report = render(findings, args.format, redact=not args.no_redact, stream=stream)
    if args.output:
        args.output.write_text(report, encoding="utf-8")
        if args.format != "text":
            print(f"Wrote {len(findings)} finding(s) to {args.output}")
    else:
        stream.write(report)

    failing = [f for f in findings if f.severity >= fail_on]
    if failing and args.staged:
        print(
            "\nCommit blocked by leakwatch. Remove the secrets above, or run "
            "'git commit --no-verify' if they are false positives.",
            file=sys.stderr,
        )
    return EXIT_FINDINGS if failing else EXIT_OK


def _cmd_baseline(args: argparse.Namespace) -> int:
    path = Path(args.path)
    findings = _collect(path, staged=False, history=args.history, options=ScanOptions())
    target = args.output or (path if path.is_dir() else path.parent) / DEFAULT_BASELINE
    count = write_baseline(findings, target)
    print(f"Recorded {count} finding(s) in {target}")
    return EXIT_OK


def _cmd_install_hook(args: argparse.Namespace) -> int:
    hook = install_hook(Path(args.path), force=args.force)
    print(f"Installed pre-commit hook at {hook}")
    return EXIT_OK


def _cmd_rules() -> int:
    rows = [(r.id, str(r.severity), r.description) for r in CONTENT_RULES]
    rows += [(r.id, str(r.severity), r.description) for r in PATH_RULES]
    width = max(len(r[0]) for r in rows)
    for rule_id, severity, description in rows:
        print(f"{rule_id.ljust(width)}  {severity.ljust(8)}  {description}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "baseline":
            return _cmd_baseline(args)
        if args.command == "install-hook":
            return _cmd_install_hook(args)
        return _cmd_rules()
    except (GitError, ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        print(f"leakwatch: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
