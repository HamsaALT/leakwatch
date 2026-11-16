"""Detection rules.

Each content rule is a regular expression plus a few optional checks that cut
down on false positives (minimum entropy, placeholder filtering, custom
validators). Path rules flag files that should never be committed at all,
such as ``.env`` files and private key files.

Rules are checked in the order they are listed. When two rules match the same
characters, the first one wins, so the specific rules come before the generic
ones.

Patterns use ``[ \\t]`` instead of ``\\s`` wherever a match must stay on one
line, because the scanner runs each pattern over the whole file at once.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import PurePath

from .entropy import shannon_entropy
from .models import Severity

# Substrings that show up in example values, docs and templates.
_PLACEHOLDER_HINTS = (
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "your",
    "xxxx",
    "dummy",
    "sample",
    "redacted",
    "<",
    ">",
    "${",
    "{{",
    "%s",
    "****",
    "todo",
    "fake",
    "insert",
    "replace",
    "secret_here",
    "password_here",
)

# Whole values that are only ever used as stand-ins.
_DUMMY_VALUES = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "pass",
        "admin",
        "root",
        "test",
        "user",
        "username",
        "token",
        "apikey",
        "api_key",
        "default",
        "letmein",
        "none",
        "null",
    }
)

# A value that itself mentions one of these is almost always a name, a label
# or a reference (e.g. "passwordFile", "my-client-secret"), not a secret.
_KEYWORDS_IN_VALUE = ("password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "api-key")

_IDENTIFIER = re.compile(r"^(?:[a-z]+(?:[A-Z][a-z]+)+|[a-z]+(?:[_.-][a-z]+)+|[A-Z]+(?:_[A-Z]+)+)$")

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "::1")


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if lowered in _DUMMY_VALUES:
        return True
    if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
        return True
    # "aaaaaaaa", "12121212" and similar
    return len(set(lowered)) <= 2


def looks_like_identifier(value: str) -> bool:
    """True for camelCase, snake_case, kebab-case and CONSTANT_CASE names."""
    lowered = value.lower()
    if any(keyword in lowered for keyword in _KEYWORDS_IN_VALUE):
        return True
    return bool(_IDENTIFIER.match(value))


def _b64url_json(segment: str) -> dict | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(padded))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _jwt_parts(token: str) -> tuple[dict, dict] | None:
    pieces = token.split(".")
    if len(pieces) != 3:
        return None
    header, payload = _b64url_json(pieces[0]), _b64url_json(pieces[1])
    if header is None or payload is None or "alg" not in header:
        return None
    return header, payload


def is_supabase_service_key(token: str) -> bool:
    parts = _jwt_parts(token)
    return parts is not None and parts[1].get("role") == "service_role"


def is_generic_jwt(token: str) -> bool:
    parts = _jwt_parts(token)
    return parts is not None and parts[1].get("role") != "service_role"


def is_remote_db_url(match: re.Match[str]) -> bool:
    """Skip local development URLs and ones where the password equals the user."""
    user, password, host = match.group("user"), match.group("password"), match.group("host")
    if password == user:
        return False
    return not host.lower().startswith(_LOCAL_HOSTS)


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    severity: Severity
    pattern: re.Pattern[str]
    # Cheap substring check (case-insensitive) done before running the regex.
    keywords: tuple[str, ...] = ()
    secret_group: int | str = 0
    min_entropy: float | None = None
    filter_placeholders: bool = False
    filter_identifiers: bool = False
    validator: Callable[[str], bool] | None = None
    match_filter: Callable[[re.Match[str]], bool] | None = None
    # Only run this rule on files whose name matches one of these globs.
    file_globs: tuple[str, ...] = ()

    def applies_to(self, path: str) -> bool:
        if not self.file_globs:
            return True
        name = PurePath(path).name
        return any(fnmatch(name, glob) for glob in self.file_globs)

    def might_match(self, lowered_text: str) -> bool:
        return not self.keywords or any(k in lowered_text for k in self.keywords)

    def accepts(self, match: re.Match[str]) -> bool:
        secret = match.group(self.secret_group)
        if self.min_entropy is not None and shannon_entropy(secret) < self.min_entropy:
            return False
        if self.filter_placeholders and looks_like_placeholder(secret):
            return False
        if self.filter_identifiers and looks_like_identifier(secret):
            return False
        if self.validator is not None and not self.validator(secret):
            return False
        return self.match_filter is None or self.match_filter(match)


@dataclass(frozen=True)
class PathRule:
    id: str
    description: str
    severity: Severity
    include: tuple[str, ...]
    exclude: tuple[str, ...] = ()

    def matches(self, path: str) -> bool:
        name = PurePath(path).name
        if any(fnmatch(name, glob) for glob in self.exclude):
            return False
        return any(fnmatch(name, glob) for glob in self.include)


ENV_FILE_GLOBS = (".env", ".env.*", "*.env")

_JWT = r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"

CONTENT_RULES: tuple[Rule, ...] = (
    Rule(
        id="private-key",
        description="Private key",
        severity=Severity.CRITICAL,
        # The header must be followed by key material, either on the next line
        # or after an escaped "\n" (as in JSON service account files).
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            r"(?:[ \t]*\r?\n|\\n)[ \t]*[A-Za-z0-9+/=]{20,}"
        ),
        keywords=("private key",),
    ),
    Rule(
        id="aws-access-key-id",
        description="AWS access key ID",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        keywords=("akia", "asia"),
        secret_group=1,
        filter_placeholders=True,
    ),
    Rule(
        id="aws-secret-access-key",
        description="AWS secret access key",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?i)aws.{0,20}?(?:secret|private).{0,20}?[\"'=: \t]+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"
        ),
        keywords=("aws",),
        secret_group=1,
        min_entropy=4.0,
    ),
    Rule(
        id="github-token",
        description="GitHub personal access or app token",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b"),
        keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
        secret_group=1,
    ),
    Rule(
        id="github-fine-grained-token",
        description="GitHub fine-grained personal access token",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        keywords=("github_pat_",),
        secret_group=1,
    ),
    Rule(
        id="gitlab-token",
        description="GitLab personal access token",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
        keywords=("glpat-",),
        secret_group=1,
    ),
    Rule(
        id="anthropic-api-key",
        description="Anthropic API key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})"),
        keywords=("sk-ant-",),
        secret_group=1,
    ),
    Rule(
        id="openai-api-key",
        description="OpenAI API key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,})"),
        keywords=("sk-",),
        secret_group=1,
        min_entropy=3.5,
    ),
    Rule(
        id="stripe-secret-key",
        description="Stripe live secret key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b"),
        keywords=("_live_",),
        secret_group=1,
    ),
    Rule(
        id="slack-token",
        description="Slack token",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
        keywords=("xox",),
        secret_group=1,
    ),
    Rule(
        id="slack-webhook",
        description="Slack incoming webhook URL",
        severity=Severity.HIGH,
        pattern=re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})"),
        keywords=("hooks.slack.com",),
        secret_group=1,
    ),
    Rule(
        id="google-api-key",
        description="Google API key",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"),
        keywords=("aiza",),
        secret_group=1,
    ),
    Rule(
        id="supabase-service-role-key",
        description="Supabase service_role key (full database access)",
        severity=Severity.CRITICAL,
        pattern=re.compile(_JWT),
        keywords=("eyj",),
        secret_group=1,
        validator=is_supabase_service_key,
    ),
    Rule(
        id="jwt",
        description="JSON Web Token",
        severity=Severity.MEDIUM,
        pattern=re.compile(_JWT),
        keywords=("eyj",),
        secret_group=1,
        validator=is_generic_jwt,
    ),
    Rule(
        id="database-url-password",
        description="Password inside a database connection URL",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|mssql)"
            r"://(?P<user>[^\s:/@'\"]+):(?P<password>[^\s@'\"]+)@(?P<host>[^\s'\"/:]+)"
        ),
        keywords=("://",),
        secret_group="password",
        filter_placeholders=True,
        match_filter=is_remote_db_url,
    ),
    Rule(
        id="env-secret-assignment",
        description="Secret value in an environment file",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]*"
            r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|SERVICE_KEY)"
            r"[A-Za-z0-9_]*[ \t]*=[ \t]*[\"']?([^\"'\s#]{6,})",
            re.IGNORECASE | re.MULTILINE,
        ),
        secret_group=1,
        filter_placeholders=True,
        file_globs=ENV_FILE_GLOBS,
    ),
    Rule(
        id="generic-secret-assignment",
        description="Hard-coded password or secret",
        severity=Severity.MEDIUM,
        pattern=re.compile(
            r"(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
            r"[\w.-]*[\"']?[ \t]*(?::=|=>|[:=])[ \t]*[\"']([^\"'\s]{8,})[\"']"
        ),
        keywords=("pass", "pwd", "secret", "key", "token"),
        secret_group=1,
        min_entropy=3.0,
        filter_placeholders=True,
        filter_identifiers=True,
    ),
)

PATH_RULES: tuple[PathRule, ...] = (
    PathRule(
        id="env-file",
        description="Environment file committed to the repository",
        severity=Severity.HIGH,
        include=ENV_FILE_GLOBS,
        exclude=(".env.example", ".env.sample", ".env.template", ".env.dist", "*.example.env"),
    ),
    PathRule(
        id="private-key-file",
        description="Private key or keystore file",
        severity=Severity.HIGH,
        # *.pem is left out on purpose: most .pem files are public certificates.
        # Private keys inside them are caught by the "private-key" content rule.
        include=("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "*.p12", "*.pfx", "*.key", "*.jks"),
    ),
)


def all_rule_ids() -> list[str]:
    return [r.id for r in CONTENT_RULES] + [r.id for r in PATH_RULES]
