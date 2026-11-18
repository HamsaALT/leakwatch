"""Create a small git repository with realistic leaks, for demos and screenshots.

    python examples/create_demo_repo.py
    leakwatch scan demo-repo
    leakwatch scan demo-repo --history

The story: a student group builds a club website. Over a few commits they
paste a Supabase service key into the frontend, commit their .env file and
hard-code a database password, then "fix" it by deleting the line. The
current files look clean, but the history does not.

The secrets are generated at runtime so this script never contains one.
"""

from __future__ import annotations

import base64
import json
import random
import shutil
import string
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "demo-repo"
RNG = random.Random(42)


def rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def service_key() -> str:
    header = b64({"alg": "HS256", "typ": "JWT"})
    payload = b64({"iss": "supabase", "ref": rand(20).lower(), "role": "service" + "_role"})
    return f"{header}.{payload}.{rand(43, string.ascii_letters + string.digits + '-_')}"


def git(*args: str) -> None:
    subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True)


def commit(message: str) -> None:
    git("add", "-A")
    git("commit", "-q", "-m", message)


def write(relative: str, content: str) -> None:
    path = ROOT / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    ROOT.mkdir()
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Demo Student")
    git("config", "user.email", "student@example.com")
    git("config", "commit.gpgsign", "false")

    write("README.md", "# Club website\n")
    write("public/app.js", "console.log('hello');\n")
    commit("Initial commit")

    write(
        "public/supabase.js",
        "import { createClient } from '@supabase/supabase-js'\n"
        f"export const supabase = createClient('https://{rand(20).lower()}.supabase.co',\n"
        f"  '{service_key()}')\n",
    )
    commit("Connect frontend to database")

    write(".env", f"PORT=3000\nSUPABASE_SERVICE_KEY={service_key()}\nSESSION_SECRET={rand(32)}\n")
    commit("Add env config")

    db_password = rand(14, string.ascii_letters + string.digits + "!#%")
    write(
        "backend/db.js",
        "module.exports = {\n"
        "  host: 'containers-us-west-1.railway.app',\n"
        f"  password: '{db_password}',\n"
        "}\n",
    )
    commit("add railway password to db.js")

    write(
        "backend/db.js",
        "module.exports = {\n  host: process.env.DB_HOST,\n  password: process.env.DB_PASSWORD,\n}\n",
    )
    (ROOT / ".env").unlink()
    write(".gitignore", ".env\nnode_modules/\n")
    commit("Move secrets to environment variables")

    print(f"Demo repository created at {ROOT}")
    print("Try:\n  leakwatch scan demo-repo\n  leakwatch scan demo-repo --history")
    return 0


if __name__ == "__main__":
    sys.exit(main())
