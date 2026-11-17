import shutil
import subprocess
from pathlib import Path

import pytest

from leakwatch.git import GitError, scan_history, scan_staged

from . import fakes

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True)
    return result.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.email", "dev@example.com")
    git(tmp_path, "config", "user.name", "Dev")
    git(tmp_path, "config", "commit.gpgsign", "false")
    return tmp_path


def commit(repo: Path, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD")


def test_deleted_secret_is_still_found_in_history(repo: Path) -> None:
    (repo / "db.js").write_text("const host = 'localhost';\n")
    commit(repo, "initial")
    (repo / "db.js").write_text(
        f"const host = 'localhost';\nconst config = {{ password: '{fakes.strong_password()}' }};\n"
    )
    leaked = commit(repo, "add railway password to db.js")
    (repo / "db.js").write_text("const host = 'localhost';\nconst pw = process.env.DB_PASSWORD;\n")
    commit(repo, "move password to env")

    findings = scan_history(repo)

    assert len(findings) == 1
    assert findings[0].commit == leaked
    assert (findings[0].file, findings[0].line) == ("db.js", 2)


def test_history_reports_the_commit_that_introduced_the_secret(repo: Path) -> None:
    (repo / "a.py").write_text(f"T = '{fakes.github_token()}'\n")
    first = commit(repo, "one")
    (repo / "a.py").write_text(f"# comment\nT = '{fakes.github_token()}'\n")
    commit(repo, "two")
    [finding] = scan_history(repo)
    assert finding.commit == first


def test_history_flags_env_file_that_was_later_removed(repo: Path) -> None:
    (repo / ".env").write_text(f"API_TOKEN={fakes.strong_password()}\n")
    commit(repo, "oops")
    (repo / ".env").unlink()
    commit(repo, "remove env")
    assert {f.rule_id for f in scan_history(repo)} == {"env-file", "env-secret-assignment"}


def test_history_checks_other_branches(repo: Path) -> None:
    (repo / "README.md").write_text("hello\n")
    commit(repo, "init")
    git(repo, "checkout", "-q", "-b", "feature")
    (repo / "k.txt").write_text(fakes.stripe_key() + "\n")
    commit(repo, "feature work")
    git(repo, "checkout", "-q", "main")
    assert [f.rule_id for f in scan_history(repo)] == ["stripe-secret-key"]


def test_staged_scan_only_sees_staged_files(repo: Path) -> None:
    (repo / "README.md").write_text("hello\n")
    commit(repo, "init")
    (repo / "staged.py").write_text(f"K = '{fakes.github_token()}'\n")
    (repo / "unstaged.py").write_text(f"K = '{fakes.stripe_key()}'\n")
    git(repo, "add", "staged.py")
    assert [(f.rule_id, f.file) for f in scan_staged(repo)] == [("github-token", "staged.py")]


def test_staged_scan_uses_staged_content_not_working_copy(repo: Path) -> None:
    (repo / "a.py").write_text(f"K = '{fakes.github_token()}'\n")
    git(repo, "add", "a.py")
    (repo / "a.py").write_text("K = os.environ['K']\n")  # fixed on disk, but not staged
    assert len(scan_staged(repo)) == 1


def test_not_a_repository_raises(tmp_path: Path) -> None:
    with pytest.raises(GitError):
        scan_history(tmp_path)
