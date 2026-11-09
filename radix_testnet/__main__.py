"""`python -m radix_testnet` starts the app; arguments fall through to the CLI."""

import sys

from .app import main as app_main
from .cli import main as cli_main

if __name__ == "__main__":
    sys.exit(app_main() if len(sys.argv) == 1 else cli_main())
