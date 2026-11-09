"""A deliberately minimal peer-to-peer layer: make two nodes agree.

What this is
------------
Framed, length-prefixed JSON messages over TCP. A node connects to a peer, says hello
with its height and cumulative work, and — if the peer is ahead — asks for the whole
chain and rebuilds from it. A node that mines a block pushes it to its peers.

What this is NOT
----------------
- **Not a network.** There is no discovery, no gossip, no address book, no encryption,
  no authentication. A node trusts whoever it connects to and adopts their chain if it
  is longer. That is fine for two machines on a LAN and unacceptable anywhere else.
- **Not fork resolution.** A genuine fork (two chains of equal or greater work that
  diverge below the tip) is detected and refused, not reconciled. Reconciliation needs
  an undo journal that the chain does not have. `docs/CONSENSUS.md` §6 specifies fork
  choice by cumulative work; this implements the comparison and the linear case, and the
  divergence case fails loudly.
- **Not a consensus change.** Difficulty is constant, so "cumulative work" is exactly
  the height today. The comparison is written in the general form so that adding a
  difficulty target later does not need this file rewritten.

The honest summary: two nodes can reach the same tip, and a chain that *forks* is
rejected rather than resolved.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import struct
from dataclasses import dataclass

#: A message is a 4-byte big-endian length followed by that many bytes of JSON.
HEADER = struct.Struct(">I")
MAX_MESSAGE = 64 * 1024 * 1024


class PeerError(RuntimeError):
    """A peer was unreachable, or sent something this node will not accept."""


def _mac(secret: bytes, message: dict) -> str:
    """HMAC over the canonical message, with the `mac` field excluded."""
    body = {key: value for key, value in message.items() if key != "mac"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def send(connection: socket.socket, message: dict, secret: bytes | None = None) -> None:
    """Frame and send. With a secret, the message is authenticated.

    Without one this is an open testnet channel: anything on the path can read or alter
    a message, and the receiver has no way to tell. That is stated in the module
    docstring rather than left to be inferred from the absence of a flag.
    """
    outgoing = dict(message)
    if secret is not None:
        outgoing["mac"] = _mac(secret, message)
    payload = json.dumps(outgoing, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE:
        raise PeerError(f"message too large: {len(payload)} bytes")
    connection.sendall(HEADER.pack(len(payload)) + payload)


def receive(connection: socket.socket, secret: bytes | None = None) -> dict:
    header = _read_exactly(connection, HEADER.size)
    (length,) = HEADER.unpack(header)
    if length > MAX_MESSAGE:
        raise PeerError(f"peer announced an absurd message: {length} bytes")
    payload = _read_exactly(connection, length)
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PeerError(f"peer sent malformed JSON: {error}") from None
    if not isinstance(message, dict) or "type" not in message:
        raise PeerError("peer sent a message with no type")

    if secret is not None:
        claimed = message.get("mac")
        if not isinstance(claimed, str):
            raise PeerError("peer sent an unauthenticated message")
        # compare_digest, so a wrong MAC cannot be discovered byte by byte.
        if not hmac.compare_digest(claimed, _mac(secret, message)):
            raise PeerError("message authentication failed")
    return message


def _read_exactly(connection: socket.socket, count: int) -> bytes:
    chunks = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise PeerError("peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@dataclass
class Peer:
    """One connected peer, for the client side of the protocol."""

    host: str
    port: int
    timeout: float = 30.0
    secret: bytes | None = None

    @classmethod
    def parse(cls, text: str, timeout: float = 30.0,
              secret: bytes | None = None) -> "Peer":
        host, _, port = text.rpartition(":")
        if not host or not port.isdigit():
            raise PeerError(f"a peer must look like host:port, not {text!r}")
        return cls(host=host, port=int(port), timeout=timeout, secret=secret)

    def connect(self) -> socket.socket:
        try:
            connection = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as error:
            raise PeerError(f"cannot reach {self.host}:{self.port}: {error}") from None
        connection.settimeout(self.timeout)
        return connection

    def call(self, message: dict) -> dict:
        """Send one request and read one reply.

        An `error` reply is raised rather than returned: a caller that had to check the
        type on every reply would eventually forget.
        """
        with self.connect() as connection:
            send(connection, message, self.secret)
            reply = receive(connection, self.secret)
        if reply.get("type") == "error":
            raise PeerError(reply.get("reason", "the peer reported an error"))
        return reply


class Server:
    """Accept one message per connection and reply once.

    Deliberately request/response rather than a long-lived session: it is trivial to
    reason about, it cannot deadlock, and a node that crashes mid-sync loses nothing.
    """

    def __init__(self, node, host: str = "127.0.0.1", port: int = 0) -> None:
        self.node = node
        self.host = host
        self.port = port
        self._socket: socket.socket | None = None
        self._thread = None

    def start(self) -> int:
        """Bind and listen, returning the port (useful when 0 was requested)."""
        import threading

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(16)
        self._socket = server
        self.port = server.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _serve(self) -> None:
        import threading

        while self._socket is not None:
            try:
                connection, _address = self._socket.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        secret = getattr(self.node, "secret", None)
        with connection:
            connection.settimeout(120.0)
            try:
                message = receive(connection, secret)
            except PeerError as error:
                reply = {"type": "error", "reason": str(error)}
            except Exception as error:  # noqa: BLE001 - a peer must not kill the server
                reply = {"type": "error", "reason": f"{type(error).__name__}: {error}"}
            else:
                try:
                    reply = self.node.handle_p2p(message)
                except PeerError as error:
                    reply = {"type": "error", "reason": str(error)}
                except Exception as error:  # noqa: BLE001
                    reply = {"type": "error", "reason": f"{type(error).__name__}: {error}"}
            try:
                send(connection, reply, secret)
            except OSError:
                pass
