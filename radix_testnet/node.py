"""The node: an HTTP service over one in-memory chain, plus the browser GUI.

Single process, localhost only, no peer discovery and no fork choice. What it does
is run the real verifier on every submitted transaction and refuse a reused tag.
"""

from __future__ import annotations

import io
import json
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import chain as C
from . import params as P
from . import prover, store
from .chain import Chain, ChainError
from .tagged import SpendError
from .wallet import Wallet, WalletError, address_of

STATIC = Path(__file__).with_name("static")


class Node:
    """A chain, a faucet wallet, and the operations the HTTP layer exposes."""

    def __init__(
        self,
        chain: Chain | None = None,
        faucet: Wallet | None = None,
        data_dir: Path | None = None,
        persist: bool = True,
    ) -> None:
        self.parameters = P.parameters()
        self.data_dir = Path(data_dir) if data_dir is not None else store.default_data_dir()
        self.persist = persist
        self.faucet = faucet or Wallet(seed=P.faucet_seed(), parameters=self.parameters)

        loaded = None
        if chain is None and self.persist:
            try:
                loaded = store.load_chain(self.data_dir, self.parameters, prover.verify_tagged)
            except (OSError, ValueError):
                loaded = None
        self.chain = chain or loaded or Chain(parameters=self.parameters, depth=P.DEPTH)
        if not self.chain.blocks:
            # One note holding the whole faucet balance: identical outputs would
            # collapse into a single UTXO and silently shrink the supply.
            self.chain.genesis(
                [(self.faucet.accounts[0].public, P.GENESIS_VALUE * P.GENESIS_NOTES)]
            )
        self.faucet.scan(self.chain)
        self.lock = threading.Lock()
        self.addressbook = store.load_address_book(self.data_dir)
        self.settings = store.load_settings(self.data_dir)
        self._persist()

    def _persist(self) -> None:
        if not self.persist:
            return
        store.save_chain(self.chain, self.data_dir)

    # ---------------------------------------------------------------- wallet
    def accounts(self) -> list[dict]:
        spent = self.chain.spent_tags
        from .wallet import tag_of

        out = []
        for account in self.faucet.accounts:
            burned = tag_of(account.secret, self.parameters) in spent
            out.append(
                {
                    "index": account.index,
                    "name": f"Account {account.index + 1}",
                    "short": account.short,
                    "address": account.address,
                    "balance": account.balance,
                    "notes": len(account.notes),
                    "spent": burned,
                }
            )
        return out

    def history(self, limit: int = 50) -> list[dict]:
        entries = []
        for block in reversed(self.chain.blocks):
            for payload in reversed(block.transactions):
                entries.append(
                    {
                        "status": "confirmed",
                        "height": block.height,
                        "timestamp": block.timestamp,
                        "fee": payload.get("fee", 0),
                        "value": sum(int(note["value"]) for note in payload.get("outputs", [])),
                        "outputs": len(payload.get("outputs", [])),
                        "id": C._hash(str(payload).encode()).hex()[:16],
                    }
                )
        for identifier, payload in reversed(list(self.chain.mempool.items())):
            entries.append(
                {
                    "status": "pending",
                    "height": None,
                    "timestamp": None,
                    "fee": payload.get("fee", 0),
                    "value": sum(int(note["value"]) for note in payload.get("outputs", [])),
                    "outputs": len(payload.get("outputs", [])),
                    "id": identifier.hex()[:16],
                }
            )
        return entries[:limit]

    def qr_svg(self, text: str) -> bytes:
        try:
            import segno
        except ImportError:  # pragma: no cover - dependency is declared
            raise RuntimeError("segno is required for QR codes") from None
        buffer = io.BytesIO()
        segno.make(text, error="m").save(
            buffer, kind="svg", scale=6, border=2, dark="#e6edf3", light=None
        )
        return buffer.getvalue()

    # ---------------------------------------------------------------- reads
    def status(self) -> dict:
        return {
            "banner": "TESTNET - NO VALUE - NO SECURITY CLAIM",
            "height": self.chain.height,
            "tip": self.chain.tip.block_hash().hex(),
            "anchor": self.chain.anchor.hex(),
            "blocks": len(self.chain.blocks),
            "mempool": len(self.chain.mempool),
            "outputs": len(self.chain.outputs),
            "pool": len(self.chain.pool),
            "faucet": {
                "address": self.faucet.accounts[0].short,
                "full_address": self.faucet.accounts[0].address,
                "balance": self.faucet.balance,
                "notes": sum(len(account.notes) for account in self.faucet.accounts),
                "accounts": len(self.faucet.accounts),
            },
            "backend": prover.BACKEND.value,
            "parameters": {
                "q": 4294966337,
                "depth": P.DEPTH,
                "tag_rows": P.TAG_ROWS,
                "ring": 32 ** P.DEPTH,
            },
        }

    def blocks(self) -> list[dict]:
        return [
            {
                "height": block.height,
                "hash": block.block_hash().hex(),
                "nonce": block.nonce,
                "transactions": len(block.transactions),
                "timestamp": block.timestamp,
            }
            for block in reversed(self.chain.blocks)
        ]

    def mempool(self) -> list[dict]:
        out = []
        for identifier, payload in self.chain.mempool.items():
            out.append(
                {
                    "id": identifier.hex()[:16],
                    "fee": payload["fee"],
                    "outputs": len(payload["outputs"]),
                    "value": sum(int(note["value"]) for note in payload["outputs"]),
                }
            )
        return out

    # ---------------------------------------------------------------- writes
    def send(self, recipient: str, amount: int, fee: int) -> dict:
        """Build a real tagged spend and submit it. Slow: ~1-2 minutes."""
        with self.lock:
            self.faucet.scan(self.chain)
            spend, indices = self.faucet.build_spend(self.chain, recipient, amount, fee)
            identifier = self.chain.submit(spend, indices)
            self._persist()
            return {"id": identifier.hex()[:16], "fee": fee, "amount": amount}

    def mine(self) -> dict:
        with self.lock:
            block = self.chain.mine()
            self.faucet.scan(self.chain)
            self._persist()
            return {
                "height": block.height,
                "hash": block.block_hash().hex(),
                "transactions": len(block.transactions),
            }

    def submit_raw(self, payload: dict) -> dict:
        with self.lock:
            spend, indices = C.spend_from_wire(payload, self.chain.pool, self.chain.depth, self.chain.rows)
            identifier = self.chain.submit(spend, indices)
            self._persist()
            return {"id": identifier.hex()[:16]}


class Handler(BaseHTTPRequestHandler):
    node: Node

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        pass  # the GUI polls; the console stays readable

    # ---------------------------------------------------------------- plumbing
    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def _error(self, code: int, message: str) -> None:
        self._json(code, {"error": message})

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?")[0]
        try:
            if path in ("/", "/index.html"):
                page = STATIC / "index.html"
                self._send(200, page.read_bytes(), "text/html; charset=utf-8")
            elif path == "/api/status":
                self._json(200, self.node.status())
            elif path == "/api/blocks":
                self._json(200, {"blocks": self.node.blocks()})
            elif path == "/api/mempool":
                self._json(200, {"mempool": self.node.mempool()})
            elif path == "/api/accounts":
                self._json(200, {"accounts": self.node.accounts()})
            elif path == "/api/history":
                self._json(200, {"history": self.node.history()})
            elif path == "/api/addressbook":
                self._json(200, {"addressbook": self.node.addressbook})
            elif path == "/api/settings":
                self._json(200, {"settings": self.node.settings})
            elif path == "/api/qr":
                query = self.path.split("?", 1)[1] if "?" in self.path else ""
                text = urllib.parse.parse_qs(query).get("text", [""])[0]
                if not text:
                    self._error(400, "text is required")
                else:
                    self._send(200, self.node.qr_svg(text), "image/svg+xml")
            else:
                self._error(404, "no such route")
        except Exception as error:  # noqa: BLE001 - a demo server must not die
            traceback.print_exc()
            self._error(500, str(error))

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._error(400, "the body is not JSON")
            return
        try:
            if path == "/api/send":
                self._json(
                    200,
                    self.node.send(payload["to"], int(payload["amount"]), int(payload["fee"])),
                )
            elif path == "/api/mine":
                self._json(200, self.node.mine())
            elif path == "/api/tx":
                self._json(200, self.node.submit_raw(payload))
            elif path == "/api/addressbook":
                entry = {"name": str(payload["name"])[:40], "address": str(payload["address"])}
                if not entry["name"] or not entry["address"]:
                    raise ValueError("name and address are required")
                self.node.addressbook = [
                    existing
                    for existing in self.node.addressbook
                    if existing["address"] != entry["address"]
                ] + [entry]
                store.save_address_book(self.node.data_dir, self.node.addressbook)
                self._json(200, {"addressbook": self.node.addressbook})
            elif path == "/api/settings":
                self.node.settings.update(payload)
                store.save_settings(self.node.data_dir, self.node.settings)
                self._json(200, {"settings": self.node.settings})
            else:
                self._error(404, "no such route")
        except (ChainError, SpendError, WalletError, KeyError, ValueError) as error:
            self._error(400, str(error))
        except Exception as error:  # noqa: BLE001
            traceback.print_exc()
            self._error(500, str(error))


def make_server(
    host: str = "127.0.0.1", port: int = 8642, node: Node | None = None
) -> tuple[ThreadingHTTPServer, "Node"]:
    """Build the server without starting it, for the launcher and the tests."""
    node = node or Node()
    handler = type("BoundHandler", (Handler,), {"node": node})
    return ThreadingHTTPServer((host, port), handler), node


def serve(host: str = "127.0.0.1", port: int = 8642, node: Node | None = None) -> ThreadingHTTPServer:
    server, node = make_server(host, port, node)
    print(f"radix testnet node on http://{host}:{port}  (Ctrl+C to stop)")
    print("TESTNET - NO VALUE - NO SECURITY CLAIM")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
    return server
