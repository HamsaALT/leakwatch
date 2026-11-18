# leakwatch

[![CI](https://github.com/HamsaALT/leakwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/HamsaALT/leakwatch/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%E2%80%933.13-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

**Find API keys, passwords and other secrets in your code and your git history, before someone else does.**

leakwatch is a command line tool, a git pre-commit hook and a GitHub Action. It has no dependencies outside the Python standard library.

## Why I built this

During a semester project at university, I noticed that our public repository contained a database service key in a committed `.env` file, and that one commit was literally called *"add password to db.js"*. The password had been removed in a later commit, so the code looked fine. But git keeps everything: anyone who clones the repository can still read it.

That is a common mistake in student and hobby projects, and the usual advice ("just don't commit secrets") does not help once it has already happened. I wanted a tool that:

1. **stops the commit** before a secret is ever saved (pre-commit hook),
2. **checks the whole history**, not just the current files, and
3. **runs in CI** so nothing slips through on a pull request.

## What it looks like

```text
$ leakwatch scan --history

[CRITICAL] Supabase service_role key (full database access)  supabase-service-role-key
           .env:2:22
           commit da143f2aa672
           value: eyJh************

[HIGH]     Environment file committed to the repository  env-file
           .env
           commit da143f2aa672

[MEDIUM]   Hard-coded password or secret  generic-secret-assignment
           backend/db.js:3:14
           commit 08ccdc816c28
           value: kk!i**********

Found 5 possible secrets (2 critical, 2 high, 1 medium).
Secrets in the git history stay readable after you delete them. Revoke and rotate each one.
```

Values are redacted by default, so the report itself is safe to share. Try it yourself with the demo repository:

```bash
python examples/create_demo_repo.py
leakwatch scan demo-repo            # current files: 1 finding
leakwatch scan demo-repo --history  # full history: 5 findings
```

## Install

```bash
pip install git+https://github.com/HamsaALT/leakwatch
```

Requires Python 3.10 or newer, and git for the `--staged` and `--history` modes.

## Usage

```bash
leakwatch scan                      # scan the current folder
leakwatch scan path/to/project      # scan another folder or a single file
leakwatch scan --history            # scan every commit on every branch
leakwatch scan --staged             # scan only what is staged for commit
leakwatch scan --fail-on high       # only fail on high and critical findings
leakwatch scan --format json        # machine-readable output
leakwatch scan --format sarif -o results.sarif   # for GitHub code scanning
leakwatch rules                     # list all detection rules
```

| Exit code | Meaning |
| --- | --- |
| `0` | No findings at or above `--fail-on` |
| `1` | Secrets found |
| `2` | Error (bad arguments, not a git repository, ...) |

### Block commits that contain secrets

```bash
leakwatch install-hook
```

From then on, `git commit` runs `leakwatch scan --staged` first. It scans the *staged* version of each file, so a secret you have fixed on disk but not re-staged is still caught.

### GitHub Action

```yaml
# .github/workflows/secrets.yml
name: Secret scan
on: [push, pull_request]

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed for the SARIF upload
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0       # needed for history: true
      - uses: HamsaALT/leakwatch@v1
        with:
          history: "true"
          fail-on: high
          sarif-file: leakwatch.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: leakwatch.sarif
```

With the SARIF upload, findings show up under the repository's **Security → Code scanning** tab.

### Adopting it in an existing project

If a project already has findings you have dealt with (for example, keys you have rotated), record them in a baseline so the scan only fails on new ones:

```bash
leakwatch baseline --history
leakwatch scan --history --baseline .leakwatch-baseline.json
```

The baseline stores only a hash of each finding, never the secret itself.

### Ignoring things

- **One line:** add `leakwatch:ignore` in a comment on that line.
- **Files and folders:** list glob patterns in a `.leakwatchignore` file in the scan root:
  ```gitignore
  # test fixtures with fake keys
  tests/fixtures/
  *.snap
  docs/old-setup.md
  ```
- `node_modules`, `.git`, `.venv`, `build`, `dist` and similar folders are skipped automatically, as are binary files and files over 1 MB (`--max-file-size`).

## What it detects

| Rule | Severity | Example of what it catches |
| --- | --- | --- |
| `private-key` | critical | `-----BEGIN RSA PRIVATE KEY-----` followed by key data |
| `aws-secret-access-key` | critical | 40-character AWS secret next to an `aws_secret` name |
| `github-token`, `github-fine-grained-token` | critical | `ghp_...`, `github_pat_...` |
| `gitlab-token` | critical | `glpat-...` |
| `anthropic-api-key`, `openai-api-key` | critical | `sk-ant-...`, `sk-proj-...` |
| `stripe-secret-key` | critical | `sk_live_...` |
| `supabase-service-role-key` | critical | JWT whose payload has `"role": "service_role"` |
| `aws-access-key-id` | high | `AKIA...` |
| `slack-token`, `slack-webhook` | high | `xoxb-...`, `hooks.slack.com/services/...` |
| `google-api-key` | high | `AIza...` |
| `database-url-password` | high | `postgresql://user:password@host/db` |
| `env-secret-assignment` | high | `DB_PASSWORD=...` inside a `.env` file |
| `env-file` | high | A committed `.env` file (`.env.example` is allowed) |
| `private-key-file` | high | `id_rsa`, `*.p12`, `*.pfx`, `*.key`, `*.jks` |
| `jwt` | medium | Any other JSON Web Token |
| `generic-secret-assignment` | medium | `password = "..."`, `apiKey: "..."` |

## How it keeps false positives down

A secret scanner that cries wolf gets switched off, so most of the work went into *not* flagging things:

- **Entropy check.** Random keys have high [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) (around 4+ bits per character); words like `password123` do not.
- **Placeholder filter.** Values such as `changeme`, `<YOUR_API_KEY>`, `${SECRET}`, `xxxx` and `your_password_here` are skipped.
- **Identifier filter.** `"passwordFile"` or `"my-client-secret"` are names, not secrets.
- **Validation, not just pattern matching.** A string that looks like a JWT is decoded first. That is also how leakwatch tells a harmless Supabase `anon` key (medium) apart from a `service_role` key that bypasses all database security (critical).
- **Context.** `postgres://postgres:postgres@localhost` is a local dev setup, not a leak.
- **Specific rules win.** If a GitHub token also looks like a generic secret, it is reported once, as a GitHub token.

As a sanity check, I scanned the Python 3.13 standard library plus about 200 installed packages (2.1 GB, 43,000 files). Version 1.0 reports 5 findings there, all of them example values in documentation, down from 21 before these filters were added.

## How it works

```
src/leakwatch/
├── cli.py        argument parsing, exit codes
├── rules.py      detection rules and false-positive filters
├── scanner.py    walks folders, runs rules over file contents
├── git.py        --staged (git show :file) and --history (parses git log -p)
├── report.py     text, JSON and SARIF output
├── baseline.py   accept known findings by fingerprint
├── hook.py       installs the pre-commit hook
└── ignore.py     .leakwatchignore, binary and size checks
```

- Each rule runs over the **whole file at once** and match positions are mapped back to line and column with a binary search. Together with the keyword check below, this made a full scan about 2.5× faster than the first line-by-line version.
- A **cheap keyword check** (for example `"ghp_"`) runs before each regular expression, so most rules are skipped for most files.
- `--history` runs `git log -p --all --reverse --unified=0` and scans only the **added** lines of each commit, with their real line numbers. Because the log is read oldest-first, each finding points to the commit that **introduced** the secret.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest --cov          # 76 tests, ~94% coverage
ruff check . && ruff format --check .
```

The tests never contain a real-looking secret in the source code. Fake keys are assembled at runtime in [`tests/fakes.py`](tests/fakes.py), so neither GitHub push protection nor leakwatch itself flags the test suite.

CI runs the tests on Python 3.10 to 3.13 and then scans this repository's own history with the action.

## If leakwatch finds a real secret

1. **Revoke or rotate it first.** Assume it has been seen. Deleting it from the code is not enough.
2. Move the value to an environment variable or a secret manager, and add `.env` to `.gitignore`.
3. Optionally rewrite the history with [`git filter-repo`](https://github.com/newren/git-filter-repo), but only after rotating, since forks and clones keep the old commits.

## Roadmap

- [ ] Respect `.gitignore` when scanning a folder
- [ ] Custom rules from a config file
- [ ] Check whether a found token is still active (opt-in)
- [ ] Parallel scanning for very large repositories

## License

MIT
