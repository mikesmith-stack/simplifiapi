"""Entry point for `python -m simplifiapi`.

All logging configuration lives in ``simplifiapi.cli.main``. This module
is a thin delegating shim.
"""

from simplifiapi.cli import main

if __name__ == "__main__":
    main()
