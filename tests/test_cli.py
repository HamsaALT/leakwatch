import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from leakwatch.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main

from . import fakes


@pytest.fixture
def project(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(f'TOKEN = "{fakes.github_token()}"\n')
    (tmp_path / "util.py").write_text(f'password = "{fakes.strong_password()}"\n')
    return tmp_path


def test_scan_returns_findings_exit_code(project: Path, capsys) -> None:
    assert main(["scan", str(project)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "GitHub personal access or app token" in out
    assert "Found 2 possible secrets" in out


def test_secret_is_redacted_by_default(project: Path, capsys) -> None:
    main(["scan", str(project)])
    out = capsys.readouterr().out
    assert fakes.github_token() not in out
    assert fakes.github_token()[:4] + "****" in out


def test_no_redact_shows_full_value(project: Path, capsys) -> None:
    main(["scan", str(project), "--no-redact"])
    assert fakes.github_token() in capsys.readouterr().out


def test_clean_folder_exits_zero(tmp_path: Path, capsys) -> None:
    (tmp_path / "ok.py").write_text("print('hi')\n")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    assert "No secrets found." in capsys.readouterr().out


def test_fail_on_threshold(project: Path) -> None:
    # The token is CRITICAL and the password MEDIUM.
    assert main(["scan", str(project), "--fail-on", "critical"]) == EXIT_FINDINGS
    (project / "app.py").unlink()
    assert main(["scan", str(project), "--fail-on", "high"]) == EXIT_OK
    assert main(["scan", str(project), "--fail-on", "medium"]) == EXIT_FINDINGS


def test_invalid_severity_is_an_error(project: Path, capsys) -> None:
    assert main(["scan", str(project), "--fail-on", "extreme"]) == EXIT_ERROR
    assert "unknown severity" in capsys.readouterr().err


def test_missing_path_is_an_error(tmp_path: Path) -> None:
    assert main(["scan", str(tmp_path / "nope")]) == EXIT_ERROR


def test_json_output(project: Path, capsys) -> None:
    main(["scan", str(project), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["count"] == 2
    assert {f["rule"] for f in data["findings"]} == {"github-token", "generic-secret-assignment"}
    assert all("****" in f["secret"] for f in data["findings"])


def test_sarif_output_to_file(project: Path, tmp_path: Path) -> None:
    report = tmp_path / "out" / "results.sarif"
    report.parent.mkdir()
    main(["scan", str(project), "--format", "sarif", "--output", str(report)])
    sarif = json.loads(report.read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "leakwatch"
    assert len(run["results"]) == 2
    assert fakes.github_token() not in report.read_text()
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    for result in run["results"]:
        assert rule_ids[result["ruleIndex"]] == result["ruleId"]


def test_baseline_accepts_known_findings(project: Path, capsys) -> None:
    assert main(["baseline", str(project)]) == EXIT_OK
    baseline = project / ".leakwatch-baseline.json"
    assert baseline.exists()
    assert main(["scan", str(project), "--baseline", str(baseline)]) == EXIT_OK

    (project / "new.py").write_text(f'KEY = "{fakes.stripe_key()}"\n')
    capsys.readouterr()
    assert main(["scan", str(project), "--baseline", str(baseline)]) == EXIT_FINDINGS
    assert "Stripe" in capsys.readouterr().out


def test_rules_command_lists_rules(capsys) -> None:
    assert main(["rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "github-token" in out and "env-file" in out


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_installed_hook_blocks_commit_with_secret(tmp_path: Path) -> None:
    def git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, text=True)

    git("init", "-q")
    git("config", "user.email", "dev@example.com")
    git("config", "user.name", "Dev")
    assert main(["install-hook", str(tmp_path)]) == EXIT_OK

    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    (tmp_path / "leak.py").write_text(f'K = "{fakes.github_token()}"\n')
    git("add", "leak.py")
    blocked = subprocess.run(
        ["git", "commit", "-m", "leak"], cwd=tmp_path, capture_output=True, text=True, env=env
    )
    assert blocked.returncode != 0
    assert "Commit blocked by leakwatch" in blocked.stderr

    (tmp_path / "leak.py").write_text("K = os.environ['K']\n")
    git("add", "leak.py")
    ok = subprocess.run(
        ["git", "commit", "-m", "clean"], cwd=tmp_path, capture_output=True, text=True, env=env
    )
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_install_hook_refuses_to_overwrite_foreign_hook(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho custom\n")
    assert main(["install-hook", str(tmp_path)]) == EXIT_ERROR
    assert main(["install-hook", str(tmp_path), "--force"]) == EXIT_OK
    assert "leakwatch" in hook.read_text()
