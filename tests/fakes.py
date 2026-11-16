"""Fake secrets for the tests.

They are generated at runtime instead of written out in full, so that the
test files themselves never contain anything that looks like a real key.
Otherwise GitHub push protection (and leakwatch itself) would flag them.
"""

from __future__ import annotations

import base64
import json
import random
import string

ALNUM = string.ascii_letters + string.digits


def rand(length: int, alphabet: str = ALNUM, seed: int = 1) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


def join(*parts: str) -> str:
    return "".join(parts)


def aws_key_id() -> str:
    return join("AK", "IA", rand(16, string.ascii_uppercase + string.digits, seed=2))


def aws_secret() -> str:
    return rand(40, ALNUM + "/+", seed=3)


def github_token() -> str:
    return join("gh", "p_", rand(36, seed=4))


def github_fine_grained() -> str:
    return join("github", "_pat_", rand(82, ALNUM + "_", seed=5))


def gitlab_token() -> str:
    return join("gl", "pat-", rand(20, seed=6))


def anthropic_key() -> str:
    return join("sk-", "ant-", "api03-", rand(40, ALNUM + "-_", seed=7))


def openai_key() -> str:
    return join("sk-", "proj-", rand(48, seed=8))


def stripe_key() -> str:
    return join("sk", "_live_", rand(24, seed=9))


def slack_token() -> str:
    return join("xo", "xb-", rand(12, string.digits, seed=10), "-", rand(24, seed=11))


def slack_webhook() -> str:
    return join(
        "https://hooks.",
        "slack.com/services/",
        "T",
        rand(8, string.ascii_uppercase + string.digits, seed=12),
        "/B",
        rand(8, string.ascii_uppercase + string.digits, seed=13),
        "/",
        rand(24, seed=14),
    )


def google_key() -> str:
    return join("AI", "za", rand(35, ALNUM + "-_", seed=15))


def private_key_header() -> str:
    return join("-----BEGIN ", "RSA PRIVATE", " KEY-----")


def private_key_block() -> str:
    body = rand(64, ALNUM + "+/", seed=18)
    footer = join("-----END ", "RSA PRIVATE", " KEY-----")
    return f"{private_key_header()}\n{body}\n{footer}"


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def jwt(payload: dict) -> str:
    return ".".join([_b64({"alg": "HS256", "typ": "JWT"}), _b64(payload), rand(43, ALNUM + "-_", seed=16)])


def supabase_service_key() -> str:
    return jwt({"iss": "supabase", "ref": "abcdefgh", "role": "service_role"})


def supabase_anon_key() -> str:
    return jwt({"iss": "supabase", "ref": "abcdefgh", "role": "anon"})


def strong_password() -> str:
    return rand(16, ALNUM + "!#%&", seed=17)
