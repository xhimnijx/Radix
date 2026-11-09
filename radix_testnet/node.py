"""The node: an HTTP service over one in-memory chain, plus the browser GUI.

Single process, localhost only, no peer discovery and no fork choice. What it does
is run the real verifier on every submitted transaction and refuse a reused tag.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from . import chain as C
from . import params as P
from . import prover, store
from .log import Log
from .chain import Chain, ChainError
from .tagged import SpendError
from .wallet import Wallet, WalletError, address_of

STATIC = Path(__file__).with_name("static")

#: The mnemonic phrase, stored beside the chain. It is a secret: anyone who reads
#: this file owns the wallet, which is why it is written 0600 and excluded from git.
WALLET_FILE = "wallet.mnemonic"


class StateError(RuntimeError):
    """Persisted state exists but cannot be read."""


class Node:
    """A chain, a faucet wallet, and the operations the HTTP layer exposes."""

    def __init__(
        self,
        chain: Chain | None = None,
        faucet: Wallet | None = None,
        data_dir: Path | None = None,
        persist: bool = True,
        config: dict | None = None,
        peers: list[str] | None = None,
    ) -> None:
        self.parameters = P.parameters()
        self.data_dir = Path(data_dir) if data_dir is not None else store.default_data_dir()
        self.persist = persist
        self.config = dict(config) if config is not None else store.load_config(self.data_dir)
        self.log = Log(
            self.data_dir / "node.log" if persist else None,
            level=self.config.get("log_level", "info"),
        )
        self.log.event("node.start", data_dir=str(self.data_dir), persist=persist)
        loaded = None
        if chain is None and self.persist:
            state = self.data_dir / store.STATE_FILE
            if state.exists():
                # Deliberately not caught: silently starting a fresh chain over a
                # corrupt file would look like the data was never there.
                try:
                    loaded = store.load_chain(
                        self.data_dir, self.parameters, prover.verify_tagged
                    )
                except (OSError, ValueError) as error:
                    raise StateError(
                        f"{state} could not be read ({error}). Move it aside to start "
                        "a new chain; the old file is left untouched."
                    ) from None
        self.chain = chain or loaded or Chain(parameters=self.parameters, depth=P.DEPTH)

        # After the chain, not before: a corrupt chain file should report itself
        # rather than being masked by the wallet check.
        self.peers: list[str] = list(peers or [])
        #: Transaction keys already seen, so relay does not loop. Keyed by a hash of
        #: the wire payload rather than by the id `chain.submit` returns, because the
        #: loop has to be broken BEFORE submitting: a second submission of the same
        #: transaction is an error, and an error reply per relay hop is noise.
        self.seen_txs: set[str] = set()
        self.wallet_created = False
        if faucet is not None:
            self.faucet = faucet
        else:
            self.faucet, self.wallet_created = self._load_or_create_wallet()
        if not self.chain.blocks:
            # The allocation is a protocol constant, not a property of this node's
            # wallet, so two independently started nodes agree on block zero. One note
            # holding the whole balance: identical outputs would collapse into a single
            # UTXO and silently shrink the supply.
            self.chain.genesis(P.genesis_allocations(self.parameters))
        self.faucet.scan(self.chain)
        self.lock = threading.Lock()
        self.addressbook = store.load_address_book(self.data_dir)
        self.settings = store.load_settings(self.data_dir)
        if self.persist:
            store.save_config(self.data_dir, self.config)
        self._persist()
        self.log.event(
            "chain.ready",
            height=self.chain.height,
            outputs=len(self.chain.outputs),
            pool=len(self.chain.pool),
        )

    def _load_or_create_wallet(self) -> tuple[Wallet, bool]:
        """The node's wallet, from `wallet.mnemonic` or freshly generated.

        A wallet that does not match the chain is worse than no wallet: every output
        on the chain would belong to keys nobody holds. So a missing phrase beside an
        existing chain is an error, not a reason to mint a new wallet.
        """
        params = self.parameters
        if not self.persist:
            # Default to the protocol's genesis wallet, not a random one: a random
            # wallet gives every node a different allocation, therefore a different
            # genesis, therefore a different chain.
            return P.genesis_wallet(params), True

        path = self.data_dir / WALLET_FILE
        if path.exists():
            phrase = path.read_text(encoding="utf-8").strip()
            if not phrase:
                raise StateError(f"{path} is empty")
            try:
                return Wallet.from_mnemonic(phrase, params), False
            except Exception as error:
                raise StateError(
                    f"{path} could not be read as a wallet phrase ({error}). "
                    "Move it aside only if you accept losing this wallet."
                ) from None

        if (self.data_dir / store.STATE_FILE).exists():
            raise StateError(
                f"{path} is missing but a chain exists. The chain's outputs belong to "
                "keys derived from that phrase; starting a new wallet would orphan them. "
                "Restore the phrase or remove the chain deliberately."
            )

        # The protocol's genesis wallet, not a random one: a random wallet gives
        # every node a different allocation and therefore a different chain, which
        # is exactly what the genesis constant exists to prevent.
        wallet = P.genesis_wallet(params)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path.write_bytes((wallet.phrase + "\n").encode("utf-8"))
        try:
            os.chmod(path, 0o600)
        except OSError:
            # Windows has no POSIX mode bits; the directory permissions apply instead.
            pass
        return wallet, True

    # ------------------------------------------------------------ peer to peer
    def handle_p2p(self, message: dict) -> dict:
        """Answer one peer message. The protocol lives in `p2p.py`; the decisions here.

        A peer is trusted to propose a chain. It is not trusted to have a valid one:
        every block goes through `Chain.append`, which checks the height, the link to
        our tip and the proof of work before anything is applied.
        """
        from . import chain as C
        from . import p2p

        kind = message.get("type")

        if kind == "hello":
            return {
                "type": "hello",
                "height": self.chain.height,
                "work": self.chain.cumulative_work(),
                "tip": self.chain.tip.block_hash().hex(),
                "genesis": self.chain.blocks[0].block_hash().hex(),
            }

        if kind == "getchain":
            return {
                "type": "chain",
                "blocks": [block.to_wire() for block in self.chain.blocks],
            }

        if kind == "getpeers":
            # A node serves the peers it already knows. There is no gossip protocol and
            # no address book beyond this: discovery is one hop, and a node that is not
            # introduced by a peer has to be configured by hand. Stated plainly because
            # one-hop discovery is a real limitation, not a placeholder name for
            # something more.
            return {"type": "peers", "peers": list(self.peers)}

        if kind == "tx":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                return {"type": "error", "reason": "tx has no payload"}
            key = self.transaction_key(payload)
            if key in self.seen_txs:
                return {"type": "ok", "known": True}
            self.seen_txs.add(key)
            try:
                result = self.submit_raw(payload)
            except Exception as error:  # noqa: BLE001 - a peer must not kill the server
                self.log.event("tx.rejected", reason=str(error), route="relay")
                return {"type": "error", "reason": str(error)}
            return {"type": "ok", "id": result["id"]}

        if kind == "block":
            try:
                block = C.Block.from_wire(message["block"])
                self.chain.append(block)
            except (C.ChainError, KeyError, TypeError, ValueError) as error:
                self.log.event("block.rejected", reason=str(error))
                return {"type": "error", "reason": str(error)}
            self._persist()
            self.log.event("block.accepted", height=self.chain.height,
                     source="peer", hash=block.block_hash().hex()[:16])
            return {"type": "ok", "height": self.chain.height}

        raise p2p.PeerError(f"unknown message type {kind!r}")

    def discover(self, peer_text: str) -> list[str]:
        """Ask a peer for its peers and remember the ones we did not already know.

        Returns the addresses added. This is the whole discovery mechanism: one hop, no
        gossip, no self-announcement. It turns "configure every peer by hand" into
        "configure one", which is the difference between a private testnet and something
        another operator can join.
        """
        from . import p2p

        reply = p2p.Peer.parse(peer_text).call({"type": "getpeers"})
        heard = [str(entry) for entry in reply.get("peers", []) if entry]
        added = []
        for candidate in heard:
            if candidate == peer_text or candidate in self.peers:
                continue
            self.peers.append(candidate)
            added.append(candidate)
        if added:
            self.log.event("peers.discovered", from_peer=peer_text, added=len(added))
        return added

    def sync_from(self, peer_text: str) -> dict:
        """Adopt a peer's chain if it has strictly more work than ours."""
        from . import chain as C
        from . import p2p

        peer = p2p.Peer.parse(peer_text)
        hello = peer.call({"type": "hello"})
        # A peer on a different genesis is on a different network, whatever its work.
        # The allocation is part of the chain, so adopting without this check would
        # silently migrate this node to somebody else's chain.
        if hello.get("genesis") != self.chain.blocks[0].block_hash().hex():
            raise p2p.PeerError(
                "that peer is on a different chain: its genesis does not match ours"
            )
        remote_work = int(hello.get("work", 0))
        local_work = self.chain.cumulative_work()
        if remote_work < local_work:
            return {"adopted": False, "local_work": local_work, "remote_work": remote_work}
        if remote_work == local_work:
            # Equal work is a tie, and a tie must break deterministically or two nodes
            # will each keep their own chain and never converge. The lower tip hash wins,
            # which is arbitrary but identical on both sides of the comparison.
            remote_tip = str(hello.get("tip", ""))
            local_tip = self.chain.tip.block_hash().hex()
            if not remote_tip or remote_tip >= local_tip:
                return {
                    "adopted": False,
                    "local_work": local_work,
                    "remote_work": remote_work,
                    "reason": "equal work, tie broken by tip hash",
                }

        payload = peer.call({"type": "getchain"})
        blocks = [C.Block.from_wire(item) for item in payload["blocks"]]
        # Derived, not received. A peer no longer supplies the allocation, so it cannot
        # hand us a chain whose block zero pays a different set of keys.
        allocations = P.genesis_allocations(self.parameters)
        try:
            # verify_transactions=True: this chain came from a stranger, so every
            # proof in it is checked rather than trusted.
            rebuilt = C.Chain.rebuild(
                self.parameters, self.chain.depth, allocations, blocks,
                verify=self.chain.verify, verify_transactions=True,
            )
        except (C.ChainError, KeyError, TypeError, ValueError) as error:
            raise p2p.PeerError(f"the peer's chain does not validate: {error}") from None

        self.chain = rebuilt
        self._persist()
        self.log.event("chain.adopted", height=self.chain.height, source=peer_text)
        return {"adopted": True, "height": self.chain.height, "remote_work": remote_work}

    def broadcast_block(self, block) -> dict:
        """Best-effort push of a newly mined block to every configured peer."""
        from . import p2p

        results = {}
        for peer_text in self.peers:
            try:
                results[peer_text] = p2p.Peer.parse(peer_text).call(
                    {"type": "block", "block": block.to_wire()}
                ).get("type")
            except (p2p.PeerError, OSError) as error:
                results[peer_text] = f"unreachable: {error}"
        return results

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

    def qr_png(self, text: str, scale: int = 8) -> bytes:
        """PNG for the Android app, which cannot render SVG natively."""
        try:
            import segno
        except ImportError:  # pragma: no cover - dependency is declared
            raise RuntimeError("segno is required for QR codes") from None
        if len(text) > 2953:
            raise ValueError("that value is too large for a QR code")
        buffer = io.BytesIO()
        try:
            segno.make(text, error="l").save(
                buffer, kind="png", scale=scale, border=2, dark="#000000", light="#FFFFFF"
            )
        except Exception as error:  # noqa: BLE001 - segno raises its own type
            raise ValueError(f"cannot encode that value as a QR code: {error}") from None
        return buffer.getvalue()

    def qr_svg(self, text: str) -> bytes:
        try:
            import segno
        except ImportError:  # pragma: no cover - dependency is declared
            raise RuntimeError("segno is required for QR codes") from None
        if len(text) > 2953:
            raise ValueError("that value is too large for a QR code")
        buffer = io.BytesIO()
        try:
            segno.make(text, error="l").save(
                buffer, kind="svg", scale=6, border=2, dark="#e6edf3", light=None
            )
        except Exception as error:  # noqa: BLE001 - segno raises its own type
            raise ValueError(f"cannot encode that value as a QR code: {error}") from None
        return buffer.getvalue()

    # ---------------------------------------------------------------- reads
    def status(self) -> dict:
        return {
            "banner": "TESTNET - NO VALUE - NO SECURITY CLAIM",
            "version": __version__,
            "height": self.chain.height,
            "tip": self.chain.tip.block_hash().hex(),
            "anchor": self.chain.anchor.hex(),
            "blocks": len(self.chain.blocks),
            "mempool": len(self.chain.mempool),
            "outputs": len(self.chain.outputs),
            "pool": len(self.chain.pool),
            "wallet": {
                "fingerprint": self.faucet.fingerprint,
                "fresh": self.wallet_created,
                "phrase_file": WALLET_FILE,
            },
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
            self.log.event("tx.accepted", id=identifier.hex()[:16], fee=fee, amount=amount)
            payload = C.spend_to_wire(spend, indices)
            result = {"id": identifier.hex()[:16], "fee": fee, "amount": amount}
        # Outside the lock, and after the spend is safely in our own mempool: a peer
        # that is slow or dead must not turn a successful send into a failure.
        self.seen_txs.add(self.transaction_key(payload))
        if self.peers:
            self.relay_tx(payload)
        return result

    def mine(self) -> dict:
        with self.lock:
            block = self.chain.mine()
            self.faucet.scan(self.chain)
            self._persist()
            self.log.event(
                "block.mined",
                height=block.height,
                hash=block.block_hash().hex()[:16],
                transactions=len(block.transactions),
            )
        # After the lock is released: a peer that is slow must not stall the node.
        self.broadcast_block(block)
        return {
            "height": block.height,
                "hash": block.block_hash().hex(),
                "transactions": len(block.transactions),
            }

    def transaction_key(self, payload: dict) -> str:
        """A stable key for a transaction payload, used to suppress relay loops."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def relay_tx(self, payload: dict) -> dict:
        """Best-effort flood of a transaction to every configured peer."""
        from . import p2p

        results = {}
        for peer_text in self.peers:
            try:
                reply = p2p.Peer.parse(peer_text).call({"type": "tx", "payload": payload})
                results[peer_text] = reply.get("type")
            except (p2p.PeerError, OSError) as error:
                results[peer_text] = f"unreachable: {error}"
        return results

    def submit_raw(self, payload: dict) -> dict:
        with self.lock:
            spend, indices = C.spend_from_wire(payload, self.chain.pool, self.chain.depth, self.chain.rows)
            identifier = self.chain.submit(spend, indices)
            self._persist()
            self.log.event("tx.accepted", id=identifier.hex()[:16], route="raw")
            result = {"id": identifier.hex()[:16]}
        # Outside the lock: a slow peer must not block the node's own submission.
        self.seen_txs.add(self.transaction_key(payload))
        if self.peers:
            self.relay_tx(payload)
        return result


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
            elif path == "/api/qr.png":
                query = self.path.split("?", 1)[1] if "?" in self.path else ""
                text = urllib.parse.parse_qs(query).get("text", [""])[0]
                if not text:
                    self._error(400, "text is required")
                else:
                    self._send(200, self.node.qr_png(text), "image/png")
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
            self.node.log.event("request.rejected", level="warn", route=path, reason=str(error))
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

