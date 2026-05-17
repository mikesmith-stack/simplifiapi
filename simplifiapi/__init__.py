"""simplifiapi — Quicken Simplifi extraction CLI (security-remediated fork).

Importing this package attaches a no-op log handler to the
``simplifiapi`` logger (the stdlib library idiom) so that library use
without a configured root logger does not emit "No handlers could be
found" warnings. It
deliberately does not configure log levels or attach any other handler
— that is the host application's job (and is done by
``simplifiapi.cli.main`` for the CLI entry point). See
``simplifiapi/cli.py::main`` for runtime log configuration.
"""

import logging

from simplifiapi.exceptions import AuthenticationError, SimplifiAPIError

logging.getLogger("simplifiapi").addHandler(logging.NullHandler())

__all__ = ["AuthenticationError", "SimplifiAPIError"]
