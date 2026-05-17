import getpass
import json
import logging
import os
import sys

import configargparse
from pandas import json_normalize

from simplifiapi.client import Client
from simplifiapi import SimplifiAPIError

logger = logging.getLogger("simplifiapi")

JSON_FORMAT = "json"
CSV_FORMAT = "csv"

# AUDIT M2 / OUT-02 — CSV formula-injection escape prefixes.
# A cell whose stringified value starts with any of these characters
# is prefixed with a single quote before being written to CSV.
CSV_INJECTION_PREFIXES = ("=", "+", "-", "@")


def _escape_csv_cell(value):
    """Return `value` with a leading single quote if it would be
    interpreted as a formula by a spreadsheet app (Excel, LibreOffice,
    Google Sheets).

    Non-string and empty values are returned unchanged. NaN / None
    pass through.

    AUDIT M2 / OUT-02.
    """
    if not isinstance(value, str) or not value:
        return value
    if value[0] in CSV_INJECTION_PREFIXES:
        return "'" + value
    return value


def parse_arguments(args):
    parser = configargparse.ArgumentParser(
        description=(
            "simplifiapi — extract Quicken Simplifi data to JSON or CSV. "
            "Requires the SIMPLIFI_CLIENT_SECRET environment variable to be set "
            "(the OAuth client secret is no longer embedded in source — see README.md > Security)."
        ),
    )

    # Credential
    parser.add_argument('--email',
                        nargs="?",
                        default=None,
                        help="The e-mail address for your Quicken Simplifi account")
    parser.add_argument('--token',
                        nargs="?",
                        default=None,
                        help="Use existing token to bypass MFA check")

    # Datasets
    parser.add_argument('--accounts',
                        action="store_true",
                        default=False,
                        help="Retrieve accounts")
    parser.add_argument('--transactions',
                        action="store_true",
                        default=False,
                        help="Retrieve transactions")
    parser.add_argument('--tags',
                        action="store_true",
                        default=False,
                        help="Retrieve tags")
    parser.add_argument('--categories',
                        action="store_true",
                        default=False,
                        help="Retrieve categories")

    # Export
    parser.add_argument('--filename',
                        default="output",
                        help="Write results to file this prefix")
    parser.add_argument('--format',
                        choices=[JSON_FORMAT, CSV_FORMAT],
                        default=JSON_FORMAT,
                        help="The format used to return data.")

    return parser.parse_args(args)


def resolve_password() -> str:
    """Resolve the Simplifi account password.

    Priority:
      1. SIMPLIFI_PASSWORD environment variable (non-empty)
      2. Interactive getpass.getpass() prompt, but only when stdin is a TTY
      3. Otherwise, raise SystemExit with a clear message

    The password is never accepted on argv (AUDIT.md C2 / SEC-02).
    """
    env_password = os.environ.get("SIMPLIFI_PASSWORD")
    if env_password:
        return env_password
    if sys.stdin.isatty():
        return getpass.getpass("Simplifi password: ")
    raise SystemExit(
        "No password available: set SIMPLIFI_PASSWORD or run from a TTY so getpass can prompt. "
        "The --password CLI argument was removed because it leaks via process listings (see AUDIT.md C2)."
    )


def write_data(options, data, name):
    # AUDIT H3 / OUT-01 — strip path components from user-supplied filename
    # so `--filename=../../tmp/evil` cannot escape CWD. os.path.basename
    # reduces any input to its trailing component:
    #   "../../tmp/evil" -> "evil"
    #   "/etc/passwd"    -> "passwd"
    #   "evil/inner"     -> "inner"
    #   "evil"           -> "evil"
    safe_prefix = os.path.basename(options.filename)
    filename = "{}_{}.{}".format(safe_prefix, name, options.format)
    logger.info("Saving %s to %s", name, filename)
    if options.format == CSV_FORMAT:
        df = json_normalize(data)
        # AUDIT M2 / OUT-02 — escape every cell whose first character is
        # one of CSV_INJECTION_PREFIXES with a leading single quote.
        # DataFrame.map covers the whole frame elementwise; _escape_csv_cell
        # is a no-op for non-string and empty values, so numeric columns
        # round-trip unchanged. (pandas 2.1 deprecated DataFrame.applymap in
        # favor of DataFrame.map; getattr shim keeps compatibility with the
        # lower pin >=2 which includes pandas 2.0.x that pre-dates .map.)
        elementwise = getattr(df, "map", df.applymap)
        df = elementwise(_escape_csv_cell)
        # Explicit utf-8 — pandas defaults to utf-8 on modern versions but
        # being explicit costs nothing and protects against platform-locale
        # surprises on Windows (cp1252) for non-ASCII payees/memos.
        df.to_csv(filename, index=False, encoding="utf-8")
    elif options.format == JSON_FORMAT:
        # AUDIT M7 / OUT-03 — open for writing only; previous "w+" served
        # no purpose since we do not seek/read.
        # encoding="utf-8" is critical on Windows where open() defaults to
        # cp1252 and would mangle / raise UnicodeEncodeError on non-ASCII
        # payees, memos, and category names. ensure_ascii=False keeps the
        # JSON readable for non-ASCII text instead of \uXXXX-escaping it.
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def _configure_logging() -> None:
    """Configure logging for the CLI entry point.

    Called once from ``main()``. Reads an optional ``LOG_LEVEL``
    environment variable (default ``"INFO"``) so users can opt into
    DEBUG output without code changes. The library itself
    (``simplifiapi/__init__.py``) attaches only a ``NullHandler`` —
    this function is the single source of real logging configuration
    when the package is invoked as a CLI.
    """
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def main():
    _configure_logging()
    options = parse_arguments(sys.argv[1:])

    client = Client()

    # AUDIT ERR-03 / H7 + ERR-05 — wrap the workflow in a single
    # try/except SimplifiAPIError boundary. Typed errors raised inside
    # Client methods (AuthenticationError is a SimplifiAPIError subclass)
    # are converted to a clean SystemExit with a non-zero exit code, so
    # the user sees a one-line message instead of a Python traceback that
    # could otherwise echo URL params or partial headers.
    #
    # RuntimeError for missing SIMPLIFI_CLIENT_SECRET is NOT caught here —
    # developer-environment misconfig should fail loud with a stack trace
    # (see plan 02 task 2.2 and CLAUDE.md "Standing Constraints").
    try:
        token = options.token
        if not token:
            token = client.get_token(
                email=options.email,
                password=resolve_password(),
            )
        # verify_token now raises AuthenticationError on failure and
        # returns None on success (plan 02 task 2.3). The previous
        # boolean-compare-to-False check on the return value is dead code
        # and silently swallowed auth failures — gone (AUDIT M8 / M9).
        client.verify_token(token)

        # Retrieve first dataset
        # TODO: Support multiple datasets
        datasets = client.get_datasets()
        if not datasets:
            # AUDIT ERR-03 / H7 — empty-dataset guard.
            # Friendly message instead of IndexError on datasets[0].
            raise SystemExit("No datasets found for this account")
        datasetId = datasets[0]["id"]

        if options.accounts:
            accounts = client.get_accounts(datasetId)
            write_data(options, accounts, "accounts")

        if options.transactions:
            transactions = client.get_transactions(datasetId)
            write_data(options, transactions, "transactions")

        if options.tags:
            tags = client.get_tags(datasetId)
            write_data(options, tags, "tags")

        if options.categories:
            categories = client.get_categories(datasetId)
            write_data(options, categories, "categories")
    except SimplifiAPIError as error:
        raise SystemExit("simplifiapi: {}".format(error))
