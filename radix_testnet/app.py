"""The desktop launcher: start the node, open the wallet, stay out of the way.

This is what the packaged executable runs. It deliberately does nothing else --
no tray icon, no auto-update, no telemetry, no network access beyond the socket it
opens on localhost.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

from . import TESTNET_BANNER
from .node import Node, make_server
from . import store


def _free_port(host: str, preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, preferred))
            return preferred
        except OSError:
            probe.bind((host, 0))
            return probe.getsockname()[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="radix-testnet",
        description="Start the local Radix testnet node and wallet.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8642)
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--no-browser", action="store_true", help="do not open a window")
    args = parser.parse_args(argv)

    data_dir = args.data_dir or store.default_data_dir()
    port = _free_port(args.host, args.port)
    node = Node(data_dir=data_dir)
    server, node = make_server(args.host, port, node=node)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://{args.host}:{port}/"

    print(TESTNET_BANNER)
    print()
    print(f"node     {url}")
    print(f"data     {data_dir}")
    print(f"accounts {len(node.faucet.accounts)}")
    print()
    print("Ctrl+C to stop. No value, no security claim, no peers.")

    if not args.no_browser:
        webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
