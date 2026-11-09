"""Version metadata for the packaged executable.

The version lives in the package so the app, the API and the binary cannot drift
apart.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from radix_testnet import __version__ as PACKAGE_VERSION

VERSION = PACKAGE_VERSION
COMPANY = "Radix testnet"
DESCRIPTION = "Valueless local testnet harness for the Candidate-B proof"
COPYRIGHT = "No value. No security claim. Not a cryptocurrency."
