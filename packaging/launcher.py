"""Entry point for the packaged executable.

PyInstaller runs its entry script as a top-level module, so relative imports fail
there. This launcher imports the package absolutely; `python -m radix_testnet`
keeps using the package's own __main__.
"""

import sys

from radix_testnet.app import main

if __name__ == "__main__":
    sys.exit(main())
