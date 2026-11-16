import pytest

from leakwatch.entropy import shannon_entropy
from leakwatch.rules import all_rule_ids, looks_like_placeholder
from leakwatch.scanner import scan_text

from . import fakes


def rule_ids(text: str, path: str = "app.py") -> list[str]:
    return [f.rule_id for f in scan_text(text, path)]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (f'AWS_ACCESS_KEY_ID = "{fakes.aws_key_id()}"', "aws-access-key-id"),
        (f'aws_secret_access_key = "{fakes.aws_secret()}"', "aws-secret-access-key"),
        (f"token = {fakes.github_token()}", "github-token"),
        (f"token: {fakes.github_fine_grained()}", "github-fine-grained-token"),
        (f"GITLAB={fakes.gitlab_token()}", "gitlab-token"),
        (f'client = Anthropic(api_key="{fakes.anthropic_key()}")', "anthropic-api-key"),
        (f'openai.api_key = "{fakes.openai_key()}"', "openai-api-key"),
        (f'stripe.api_key = "{fakes.stripe_key()}"', "stripe-secret-key"),
        (f"SLACK={fakes.slack_token()}", "slack-token"),
        (f'url = "{fakes.slack_webhook()}"', "slack-webhook"),
        (f'const key = "{fakes.google_key()}";', "google-api-key"),
        (f'"private_key": "{fakes.private_key_header()}\\n{fakes.rand(40)}"', "private-key"),
        (
            f'const supabase = createClient(url, "{fakes.supabase_service_key()}")',
            "supabase-service-role-key",
        ),
        (f"Authorization: Bearer {fakes.supabase_anon_key()}", "jwt"),
        (
            f'DATABASE_URL = "postgresql://admin:{fakes.strong_password()}@db.example.com:5432/app"',
            "database-url-password",
        ),
        (f'db_password = "{fakes.strong_password()}"', "generic-secret-assignment"),
    ],
)
def test_rule_detects_secret(line: str, expected: str) -> None:
    assert rule_ids(line) == [expected]


@pytest.mark.parametrize(
    "line",
    [
        'password = "changeme123"',
        'password = "your_password_here"',
        'api_key = "<YOUR_API_KEY>"',
        'secret = "${SECRET_FROM_ENV}"',
        'password = "aaaaaaaaaaaa"',
        'password = os.environ["DB_PASSWORD"]',
        'DATABASE_URL = "postgres://user:password@localhost/db"',
        "AKIA is the prefix of AWS key IDs",
        'title = "eyJhbGciOi is how JWTs start"',
        'def get_password(): return input("Password: ")',
        "postgresql://postgres:postgres@db.internal:5432/app",
        "redis://app:s3cr3tValue99@localhost:6379",
        'AttributeOID.CHALLENGE_PASSWORD: "challengePassword",',
        'client_secret="my-client-secret"',
        "'password_file': 'passwordFile',",
        f'SK_START = b"{fakes.private_key_header()}"',
    ],
)
def test_harmless_lines_are_not_flagged(line: str) -> None:
    assert rule_ids(line) == []


def test_supabase_service_key_beats_generic_jwt() -> None:
    line = f'SUPABASE_KEY = "{fakes.supabase_service_key()}"'
    findings = scan_text(line, "config.js")
    assert [f.rule_id for f in findings] == ["supabase-service-role-key"]
    assert findings[0].severity.name == "CRITICAL"


def test_env_assignment_only_runs_on_env_files() -> None:
    line = f"DB_PASSWORD={fakes.strong_password()}"
    assert rule_ids(line, ".env") == ["env-secret-assignment"]
    assert rule_ids(line, "notes.txt") == []


def test_inline_ignore_marker_skips_line() -> None:
    line = f'token = "{fakes.github_token()}"  # leakwatch:ignore'
    assert rule_ids(line) == []


def test_private_key_block_spanning_lines() -> None:
    text = "KEY = (\n" + fakes.private_key_block() + "\n)\n"
    findings = scan_text(text, "k.py")
    assert [(f.rule_id, f.line) for f in findings] == [("private-key", 2)]


def test_two_secrets_on_one_line_are_both_found() -> None:
    line = f"{fakes.github_token()} {fakes.stripe_key()}"
    assert sorted(rule_ids(line)) == ["github-token", "stripe-secret-key"]


def test_line_and_column_are_reported() -> None:
    text = "first line\n" + f"    key = {fakes.github_token()}\n"
    finding = scan_text(text, "x.py")[0]
    assert (finding.line, finding.column) == (2, 11)


def test_rule_ids_are_unique() -> None:
    ids = all_rule_ids()
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    ("value", "expected"),
    [("changeme", True), ("<token>", True), ("xxxxxxxx", True), (fakes.strong_password(), False)],
)
def test_placeholder_detection(value: str, expected: bool) -> None:
    assert looks_like_placeholder(value) is expected


def test_entropy_separates_words_from_keys() -> None:
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("password") < 3
    assert shannon_entropy(fakes.aws_secret()) > 4
