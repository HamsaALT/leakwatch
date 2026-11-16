from pathlib import Path

from leakwatch.scanner import ScanOptions, deduplicate, scan_directory

from . import fakes


def write(root: Path, relative: str, content: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def found(root: Path, **options) -> set[tuple[str, str]]:
    return {(f.rule_id, f.file) for f in scan_directory(root, ScanOptions(**options))}


def test_clean_project_has_no_findings(tmp_path: Path) -> None:
    write(tmp_path, "src/app.py", "import os\nKEY = os.environ['API_KEY']\n")
    write(tmp_path, ".env.example", "API_KEY=your_api_key_here\n")
    assert found(tmp_path) == set()


def test_secret_in_nested_file_is_found_with_relative_path(tmp_path: Path) -> None:
    write(tmp_path, "backend/config/db.js", f'const key = "{fakes.supabase_service_key()}";\n')
    assert found(tmp_path) == {("supabase-service-role-key", "backend/config/db.js")}


def test_env_file_is_flagged_by_name_and_content(tmp_path: Path) -> None:
    write(tmp_path, ".env", f"DB_PASSWORD={fakes.strong_password()}\nPORT=3000\n")
    assert found(tmp_path) == {("env-file", ".env"), ("env-secret-assignment", ".env")}


def test_private_key_file_is_flagged(tmp_path: Path) -> None:
    write(tmp_path, "keys/id_rsa", fakes.private_key_block() + "\n")
    assert found(tmp_path) == {("private-key-file", "keys/id_rsa"), ("private-key", "keys/id_rsa")}


def test_public_certificate_bundle_is_not_flagged(tmp_path: Path) -> None:
    cert = "-----BEGIN CERTIFICATE-----\n" + fakes.rand(64) + "\n-----END CERTIFICATE-----\n"
    write(tmp_path, "certs/cacert.pem", cert)
    assert found(tmp_path) == set()


def test_default_ignored_folders_are_skipped(tmp_path: Path) -> None:
    write(tmp_path, "node_modules/lib/index.js", f'k = "{fakes.github_token()}"\n')
    write(tmp_path, ".git/config", f'k = "{fakes.github_token()}"\n')
    assert found(tmp_path) == set()


def test_leakwatchignore_patterns(tmp_path: Path) -> None:
    token = f'token = "{fakes.github_token()}"\n'
    write(tmp_path, ".leakwatchignore", "# test data\nfixtures/\n*.snap\ndocs/old.md\n")
    write(tmp_path, "fixtures/a.txt", token)
    write(tmp_path, "ui/__snapshots__/view.snap", token)
    write(tmp_path, "docs/old.md", token)
    write(tmp_path, "docs/new.md", token)
    assert found(tmp_path) == {("github-token", "docs/new.md")}


def test_binary_and_large_files_are_skipped(tmp_path: Path) -> None:
    write(tmp_path, "image.png", b"\x89PNG\x00\x00" + fakes.github_token().encode())
    write(tmp_path, "big.log", "x" * 200 + fakes.github_token())
    assert found(tmp_path, max_file_size=100) == set()


def test_scanning_a_single_file(tmp_path: Path) -> None:
    target = write(tmp_path, "settings.py", f'SECRET_KEY = "{fakes.strong_password()}"\n')
    findings = scan_directory(target)
    assert [(f.rule_id, f.file) for f in findings] == [("generic-secret-assignment", "settings.py")]


def test_windows_line_endings(tmp_path: Path) -> None:
    write(tmp_path, "a.txt", f"line one\r\ntoken={fakes.github_token()}\r\n")
    [finding] = scan_directory(tmp_path)
    assert finding.line == 2


def test_non_utf8_file_is_still_scanned(tmp_path: Path) -> None:
    write(tmp_path, "legacy.txt", b"caf\xe9 " + fakes.github_token().encode())
    assert found(tmp_path) == {("github-token", "legacy.txt")}


def test_deduplicate_keeps_first(tmp_path: Path) -> None:
    write(tmp_path, "a.py", f'k = "{fakes.github_token()}"\nk2 = "{fakes.github_token()}"\n')
    findings = scan_directory(tmp_path)
    assert len(findings) == 2
    unique = deduplicate(findings)
    assert len(unique) == 1 and unique[0].line == 1
