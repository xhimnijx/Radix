"""`python -m radix_testnet` is the same entry point as `radix_testnet.cli`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
