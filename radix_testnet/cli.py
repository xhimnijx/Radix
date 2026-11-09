"""One entry point for node, miner and wallet.

    python -m radix_testnet.cli node
    python -m radix_testnet.cli status
    python -m radix_testnet.cli mine
    python -m radix_testnet.cli send --to rtx1... --amount 100 --fee 10
    python -m radix_testnet.cli address
    python -m radix_testnet.cli gui

Everything prints the TESTNET banner, because the one thing this must never be
mistaken for is a currency.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import webbrowser

from . import TESTNET_BANNER, __version__
from . import prover

DEFAULT_URL = "http://127.0.0.1:8642"


def _request(url: str, payload: dict | None = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method="POST" if data else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            message = json.loads(error.read()).get("error", str(error))
        except Exception:  # noqa: BLE001
            message = str(error)
        raise SystemExit(f"refused: {message}") from None
    except urllib.error.URLError:
        raise SystemExit(f"no node at {url} -- start one with: node") from None


def _print_banner() -> None:
    print(TESTNET_BANNER)
    print()


def command_node(args: argparse.Namespace) -> int:
    from .node import Node, serve

    # --data-dir is a top-level option, so it has to be honoured here or a systemd
    # unit would silently write to the default directory instead of the one it names.
    node = Node(data_dir=args.data_dir) if args.data_dir else None
    if node is not None and node.wallet_created:
        print("NEW WALLET - write these words down, they are the only backup:")
        print(f"    {node.faucet.phrase}")
        print()
        print(f"wallet fingerprint {node.faucet.fingerprint}")
    serve(host=args.host, port=args.port, node=node)
    return 0


def command_status(args: argparse.Namespace) -> int:
    status = _request(args.url + "/api/status")
    print(f"height        {status['height']}")
    print(f"tip           {status['tip']}")
    print(f"mempool       {status['mempool']}")
    print(f"utxo          {status['outputs']}")
    print(f"ring pool     {status['pool']}")
    print(f"faucet        {status['faucet']['balance']} over {status['faucet']['notes']} notes")
    print(f"backend       {status['backend']}")
    params = status["parameters"]
    print(f"parameters    q = {params['q']}, depth {params['depth']}, ring {params['ring']}, k' {params['tag_rows']}")
    return 0


def command_address(args: argparse.Namespace) -> int:
    status = _request(args.url + "/api/status")
    print(f"short  {status['faucet']['address']}")
    print(f"full   {status['faucet']['full_address']}")
    return 0


def command_mine(args: argparse.Namespace) -> int:
    if args.watch:
        import time

        while True:
            try:
                result = _request(args.url + "/api/mine", {})
                print(f"block {result['height']}  {result['hash'][:16]}...  {result['transactions']} tx")
            except SystemExit as error:
                if "nothing to mine" not in str(error):
                    raise
            time.sleep(args.interval)
    result = _request(args.url + "/api/mine", {})
    print(f"block {result['height']}  {result['hash'][:16]}...  {result['transactions']} tx")
    return 0


def command_send(args: argparse.Namespace) -> int:
    print("signing a real tagged ring signature over 1024 members; this takes 1-2 minutes")
    result = _request(args.url + "/api/send", {"to": args.to, "amount": args.amount, "fee": args.fee})
    print(f"submitted {result['id']} to the mempool")
    print("mine it with: mine")
    return 0


def command_wallet(args: argparse.Namespace) -> int:
    """Inspect or restore the wallet stored beside the chain.

    The phrase lives on the machine running the node, not behind the HTTP API, so
    this command reads the data directory directly rather than talking to a node.
    """
    from . import mnemonic as M
    from . import params as P
    from . import store
    from .node import WALLET_FILE
    from .wallet import Wallet

    data_dir = args.data_dir or store.default_data_dir()
    path = data_dir / WALLET_FILE
    parameters = P.parameters()

    if args.restore:
        if path.exists() and not args.force:
            raise SystemExit(
                f"a wallet already exists at {path}; pass --force to replace it "
                "(which loses the old one)"
            )
        if (data_dir / store.STATE_FILE).exists() and not args.force:
            raise SystemExit(
                "a chain exists here, so replacing the wallet would orphan its outputs; "
                "pass --force only if that is what you mean"
            )
        cleaned = M.normalise(args.restore)
        try:
            M.to_entropy(cleaned)
        except M.MnemonicError as error:
            raise SystemExit(f"that phrase is not valid: {error}") from None
        data_dir.mkdir(parents=True, exist_ok=True)
        path.write_bytes((cleaned + "\n").encode("utf-8"))
        wallet = Wallet.from_mnemonic(cleaned, parameters)
        print(f"restored wallet {wallet.fingerprint} to {path}")
        return 0

    if not path.exists():
        raise SystemExit(
            f"no wallet at {path}. Start the node once to create one, or restore an "
            "existing phrase with: wallet --restore \"word1 word2 ...\""
        )

    phrase = path.read_text(encoding="utf-8").strip()
    wallet = Wallet.from_mnemonic(phrase, parameters)
    print(f"fingerprint  {wallet.fingerprint}")
    print(f"file         {path}")
    print(f"accounts     {len(wallet.accounts)}")
    if args.show:
        print()
        print("WARNING: anyone who sees this phrase owns the wallet.")
        print(f"phrase       {wallet.phrase}")
    else:
        print("phrase       hidden (pass --show to print it)")
    return 0


def command_gui(args: argparse.Namespace) -> int:
    url = args.url + "/"
    print(f"opening {url}")
    webbrowser.open(url)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="radix-testnet",
        description="A valueless local testnet for the Candidate-B proof.",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help=f"node URL (default {DEFAULT_URL})")
    parser.add_argument("--data-dir", default=None, help="where the chain and wallet live")
    parser.add_argument(
        "--backend",
        default="python",
        choices=["python", "rust"],
        help="which prover to use; rust needs prove_request built",
    )
    parser.add_argument("--version", action="version", version=f"radix-testnet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    node = sub.add_parser("node", help="run the node and the GUI")
    node.add_argument("--host", default="127.0.0.1")
    node.add_argument("--port", type=int, default=8642)
    node.set_defaults(func=command_node)

    status = sub.add_parser("status", help="chain status")
    status.set_defaults(func=command_status)

    address = sub.add_parser("address", help="the faucet address")
    address.set_defaults(func=command_address)

    mine = sub.add_parser("mine", help="mine the mempool into a block")
    mine.add_argument("--watch", action="store_true", help="keep mining")
    mine.add_argument("--interval", type=float, default=2.0)
    mine.set_defaults(func=command_mine)

    send = sub.add_parser("send", help="sign and submit a spend")
    send.add_argument("--to", required=True, help="recipient rtx1... address")
    send.add_argument("--amount", type=int, required=True)
    send.add_argument("--fee", type=int, default=10)
    send.set_defaults(func=command_send)

    wallet = sub.add_parser("wallet", help="inspect or restore the wallet beside the chain")
    wallet.add_argument("--show", action="store_true", help="print the recovery phrase")
    wallet.add_argument("--restore", metavar="PHRASE", help="install a recovery phrase")
    wallet.add_argument("--force", action="store_true", help="replace an existing wallet")
    wallet.set_defaults(func=command_wallet)

    gui = sub.add_parser("gui", help="open the browser GUI")
    gui.set_defaults(func=command_gui)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Parse first: --help and --version must exit without the banner.
    args = build_parser().parse_args(argv)
    _print_banner()
    try:
        prover.set_backend(args.backend)
    except prover.ProverUnavailable as error:
        raise SystemExit(f"cannot use the {args.backend} backend: {error}") from None
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
