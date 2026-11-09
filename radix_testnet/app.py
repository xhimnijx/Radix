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

from . import TESTNET_BANNER, __version__
from . import prover
from .node import Node, StateError, make_server
from . import store


def _free_port(host: str, preferred: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, preferred))
            return preferred
        except OSError:
            probe.bind((host, 0))
            return probe.getsockname()[1]


def start_auto_miner(node, interval: float) -> threading.Thread:
    """Mine whenever the mempool is non-empty, until the process exits.

    `Node.mine` takes the node lock, so this cannot race with the mine button or a
    second request.
    """

    def loop() -> None:
        from .chain import ChainError

        while True:
            try:
                if node.chain.mempool:
                    block = node.mine()
                    print(f"mined block {block['height']} with {block['transactions']} tx")
            except ChainError:
                pass
            except Exception as error:  # noqa: BLE001 - a background thread must not die
                print(f"miner error: {error}")
            time.sleep(interval)

    thread = threading.Thread(target=loop, daemon=True, name="auto-miner")
    thread.start()
    return thread


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="radix-testnet",
        description="Start the local Radix testnet node and wallet.",
    )
    # Defaults come from config.json in the data directory; flags override it.
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--no-browser", action="store_true", help="do not open a window")
    parser.add_argument("--version", action="version", version=f"radix-testnet {__version__}")
    parser.add_argument(
        "--backend",
        default="rust",
        choices=["python", "rust"],
        help="which prover to use (default: rust, the ported implementation); python is the slow reference oracle",
    )
    args = parser.parse_args(argv)

    try:
        prover.set_backend(args.backend)
    except prover.ProverUnavailable as error:
        print(f"cannot use the {args.backend} backend: {error}", file=sys.stderr)
        return 2

    data_dir = args.data_dir or store.default_data_dir()
    config = store.load_config(data_dir)
    host = args.host or config["host"]
    port = _free_port(host, args.port or int(config["port"]))
    try:
        node = Node(data_dir=data_dir, config=config)
    except StateError as error:
        print(f"cannot start: {error}", file=sys.stderr)
        return 2
    server, node = make_server(host, port, node=node)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://{host}:{port}/"

    print(TESTNET_BANNER)
    print()
    if node.wallet_created:
        print("NEW WALLET - write these twelve words down. They are the only way to")
        print("restore this wallet on another device, and nothing else stores them:")
        print()
        print(f"    {node.faucet.phrase}")
        print()
        print(f"(also saved to {data_dir / 'wallet.mnemonic'})")
        print()
    print(f"wallet   {node.faucet.fingerprint}")
    print(f"node     {url}")
    print(f"data     {data_dir}")
    print(f"accounts {len(node.faucet.accounts)}")
    print()
    print("Ctrl+C to stop. No value, no security claim, no peers.")

    if config.get("auto_mine"):
        start_auto_miner(node, float(config.get("auto_mine_interval", 3.0)))
        print("auto-miner  on")
    if not args.no_browser and config.get("auto_open_browser", True):
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
