"""Module-level exception hierarchy for simplifiapi.

All errors raised at the client/CLI boundary derive from `SimplifiAPIError`.
The CLI catches `SimplifiAPIError` at the boundary in `cli.py::main` and
converts it to a `SystemExit` with a non-zero exit code (see plan 05).

AUDIT.md origin: ERR-05 (CONCERNS.md — Quality). Used by H6 / M9 / H4 / H5
raise sites in `client.py` and the `cli.py::main` boundary handler.
"""


class SimplifiAPIError(Exception):
    """Base class for all errors raised by simplifiapi at the client boundary.

    Raise this (or a subclass) from any `Client` method when an upstream
    request fails in a way the caller is expected to handle: malformed JSON,
    unexpected response shape, validation failure on `nextLink`, etc.

    The CLI layer catches `SimplifiAPIError` and converts it to a
    user-facing `SystemExit` rather than propagating a stack trace.
    """


class AuthenticationError(SimplifiAPIError):
    """Raised when OAuth authentication or token verification fails.

    Subclasses `SimplifiAPIError` so a CLI-level
    `except SimplifiAPIError` will catch both auth and non-auth failures,
    while callers that care about auth specifically can catch this directly.
    """
