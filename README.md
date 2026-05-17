# simplifiapi

An unofficial CLI and Python library for extracting your own Quicken Simplifi data — accounts, transactions, tags, and categories — to JSON or CSV.

## Security & Trust Model

This is an **unofficial** client for Quicken Simplifi. Before running it against your real account, understand the trust model:

- **OAuth client secret comes from your environment.** The OAuth client secret is no longer embedded in source. You must set `SIMPLIFI_CLIENT_SECRET` in your environment before invoking the CLI or the `Client` class. If it is unset, the tool fails loudly rather than silently proceeding.
- **Your Simplifi account password is never accepted on argv.** The `--password` CLI flag has been removed (it leaked via `ps`, shell history, and syslog). Provide your password by either setting `SIMPLIFI_PASSWORD` in your environment, or by letting the CLI prompt you via `getpass.getpass()` when run interactively. Non-interactive runs with no env var exit with a clear error.
- **MFA codes are read via `getpass.getpass()`** — they do not echo to the terminal and do not enter readline history.
- **The bearer token, refresh token, and Simplifi user id are never logged** at any level.
- **HTTP calls are timeout-bounded and host-guarded.** Every request carries a 30-second timeout. The `nextLink` value returned by Quicken during pagination is validated: it must be either a relative path or an absolute URL on `https://services.quicken.com/`. Anything else is rejected before the bearer token is sent.
- **`--filename` cannot escape the working directory.** Any path components in the value are stripped via `os.path.basename` before opening the output file.
- **CSV output is formula-injection-safe.** Cells whose stringified value starts with `=`, `+`, `-`, or `@` are prefixed with a single quote before writing.
- **The OAuth `clientSecret` cannot be rotated per-user.** Because this is an unofficial client, Quicken does not own a per-user relationship for the OAuth `clientSecret` and cannot revoke it for an individual user. Anyone running this client is implicitly accepting that the secret is shared across every user of the project. If the secret leaks, every user is affected — Quicken's only remediation would be invalidating the secret for the entire client, breaking the tool for everyone.
- **Run in an isolated environment.** Treat `SIMPLIFI_CLIENT_SECRET` and `SIMPLIFI_PASSWORD` as sensitive. Prefer a dedicated shell, container, or VM where those env vars do not bleed into your normal development environment or any background process that snapshots `/proc/<pid>/environ`. Export them via a sourced `.env` file you do not commit, not by typing them at a prompt that lands in shell history.

A starter `.env.example` is shipped at the repo root. Copy it to `.env` and fill in your values; do not commit `.env`.

## Install

Install from a clone of this repo:

```shell
# from a clone of this repo
pip install .

# or, in editable mode for local development
pip install -e .

# or, with dev/test extras (pytest + responses)
pip install -e '.[dev]'
```

Pinned runtime dependencies (from `pyproject.toml`): `requests>=2.31,<3`, `pandas>=2,<3`, `configargparse>=1.7,<2`. Python 3.9+.

## CLI

The package installs a `simplifiapi` entry point that extracts data from your Simplifi account to local files.

```shell
usage: simplifiapi [-h] [--email [EMAIL]] [--token [TOKEN]] [--accounts]
                   [--transactions] [--tags] [--categories]
                   [--filename FILENAME] [--format {json,csv}]

simplifiapi — extract Quicken Simplifi data to JSON or CSV. Requires the
SIMPLIFI_CLIENT_SECRET environment variable to be set (the OAuth client secret
is no longer embedded in source — see README.md > Security & Trust Model).

options:
  -h, --help           show this help message and exit
  --email [EMAIL]      The e-mail address for your Quicken Simplifi account
  --token [TOKEN]      Use existing token to bypass MFA check
  --accounts           Retrieve accounts
  --transactions       Retrieve transactions
  --tags               Retrieve tags
  --categories         Retrieve categories
  --filename FILENAME  Write results to file with this prefix (path
                       components stripped — see Security & Trust Model)
  --format {json,csv}  The format used to return data.
```

### Examples

```shell
# Interactive login: getpass prompts for password (and MFA code if challenged).
SIMPLIFI_CLIENT_SECRET=... simplifiapi --email=you@example.com --transactions

# Non-interactive: password from env, scrape to CSV with a date prefix.
SIMPLIFI_CLIENT_SECRET=... SIMPLIFI_PASSWORD=... \
    simplifiapi --email=you@example.com --transactions --filename=20251125 --format=csv

# Reuse an existing bearer token (skip OAuth + MFA).
SIMPLIFI_CLIENT_SECRET=... simplifiapi --token="..." --accounts --transactions
```

Output files are written to the current working directory as `{filename}_{resource}.{format}` (e.g. `output_transactions.csv`). Any path separators or `..` segments in `--filename` are stripped before the file is opened.

### Exit codes & errors

The CLI catches `SimplifiAPIError` (and its `AuthenticationError` subclass) at the boundary and exits with a one-line `simplifiapi: <message>` instead of a Python traceback. Missing `SIMPLIFI_CLIENT_SECRET` is treated as a developer-environment error and fails loudly with a `RuntimeError` so it is not silently miscategorised as an auth failure.

### Logging

Set `LOG_LEVEL=DEBUG` to see the per-request pagination log. Bearer tokens, refresh tokens, MFA channels, and user IDs are never logged.

## Python API

The `Client` class lets you call the same endpoints from your own scripts. Importing the package is logging-pure — it attaches only a `NullHandler` to the `simplifiapi` logger and does not touch root-level logging.

```python
import os
from simplifiapi import AuthenticationError, SimplifiAPIError
from simplifiapi.client import Client

# SIMPLIFI_CLIENT_SECRET must be set in the environment before calling get_token.
# When calling Client directly, your code passes `password=` explicitly —
# resolve it however you want (getpass, keyring, etc.), just don't read it
# from sys.argv.
os.environ["SIMPLIFI_CLIENT_SECRET"] = "<your-client-secret>"

client = Client()

try:
    # Option A: full OAuth + (optional) MFA flow.
    token = client.get_token(email="you@example.com", password="<resolved-via-env-or-getpass>")

    # Option B: reuse an existing bearer token instead of get_token.
    # token = "..."

    # verify_token raises AuthenticationError on a bad token and installs the
    # bearer header on the session on success. It does not return a value.
    client.verify_token(token)

    # Datasets own transactions and accounts.
    datasets = client.get_datasets()
    if not datasets:
        raise SystemExit("No datasets found for this account")
    dataset_id = datasets[0]["id"]

    # All four getters return list[dict] of fully-unpaginated resources.
    transactions = client.get_transactions(dataset_id)
    accounts     = client.get_accounts(dataset_id)
    tags         = client.get_tags(dataset_id)
    categories   = client.get_categories(dataset_id)
except AuthenticationError as exc:
    # OAuth / token-verify failure. Typed subclass of SimplifiAPIError.
    raise SystemExit(f"auth failed: {exc}")
except SimplifiAPIError as exc:
    # Pagination, JSON-decode, or unsafe nextLink rejection.
    raise SystemExit(f"api error: {exc}")
```

### Exception hierarchy

Both exception types are re-exported from the package root:

- `SimplifiAPIError` — base class for all boundary errors raised by `Client` (bad HTTP status on a resource fetch, invalid JSON in a response, refusal to follow an unsafe `nextLink`).
- `AuthenticationError` (subclass of `SimplifiAPIError`) — OAuth authorize/token failure, MFA mismatch, or `verify_token` failure.

`RuntimeError` is raised separately when `SIMPLIFI_CLIENT_SECRET` is missing; it is intentionally not a `SimplifiAPIError` so the CLI does not catch and prettify it.

## Development

```shell
pip install -e '.[dev]'
pytest                       # run the test suite
pytest --cov                 # with coverage (gate is fail_under=80)
pytest -k unit               # only unit-marked tests
```

The test suite uses `pytest` + the `responses` library to mock the Quicken HTTP surface. Tests live under [tests/](tests/).

## Thanks

This library is heavily inspired by [mintapi](https://github.com/mintapi/mintapi).
