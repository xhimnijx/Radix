"""On-disk state so a restart does not throw the chain away.

Two things are persisted: the chain (blocks, unspent outputs, spent tags, the keys
appended to the ring pool beyond the deterministic decoys) and the small
key-value stores the wallet needs (address book, settings).

Blocks are **not** re-verified on load. A local file that this process wrote is
trusted, and re-verifying a 1024-member proof per block would cost ~20 s each. That
is a deliberate choice, and it is why the data directory must not be shared between
machines: a harness that trusts its own file is fine, a node that trusts a peer's
file is not.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from radix_core.candidate_b.lattice import ring
from radix_core.candidate_b.lattice.params import SMILE
from radix_core.candidate_b.lattice.spend import Output

from .chain import Block, Chain, output_id

STATE_FILE = "chain.json"
ADDRESS_BOOK_FILE = "addressbook.json"
SETTINGS_FILE = "settings.json"
CONFIG_FILE = "config.json"
STATE_VERSION = 1


def default_data_dir() -> Path:
    """A per-user directory: LOCALAPPDATA on Windows, XDG elsewhere."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(base) / "RadixTestnet"


def atomic_write(path: Path, data: str) -> None:
    """Write to a temporary file and replace, so a crash cannot truncate state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", text=True)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        leftover = Path(temporary)
        if leftover.exists():
            leftover.unlink()
        raise


def write_json(path: Path, payload) -> None:
    atomic_write(path, json.dumps(payload, indent=1, sort_keys=True))


def read_json(path: Path, default=None):
    """Read JSON, tolerating a UTF-8 BOM.

    Notepad and PowerShell both write one, and a config file that fails to load
    because of an invisible character is a bad first experience.
    """
    if not path.exists():
        return default
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


# --------------------------------------------------------------------- keys
def key_to_wire(key: tuple) -> list[list[int]]:
    return [list(poly) for poly in key]


def key_from_wire(data) -> tuple:
    return tuple(tuple(int(value) for value in poly) for poly in data)


def output_to_wire(note: Output) -> dict:
    return {"key": key_to_wire(note.key), "value": note.value}


def output_from_wire(payload: dict) -> Output:
    return Output(key=key_from_wire(payload["key"]), value=int(payload["value"]))


def tag_bytes(tag) -> bytes:
    return b"".join(ring.encode(tuple(poly), SMILE) for poly in tag)


# -------------------------------------------------------------------- chain
def chain_to_dict(chain: Chain) -> dict:
    return {
        "version": STATE_VERSION,
        "depth": chain.depth,
        "blocks": [
            {
                "height": block.height,
                "previous": block.previous.hex(),
                "anchor": block.anchor.hex(),
                "transactions": list(block.transactions),
                "nonce": block.nonce,
                "timestamp": block.timestamp,
            }
            for block in chain.blocks
        ],
        "outputs": [output_to_wire(note) for note in chain.outputs.values()],
        "spent_tags": sorted(tag.hex() for tag in chain.spent_tags),
        "extra_pool": [key_to_wire(key) for key in chain.pool[chain.decoy_count :]],
        "mempool": [
            {"id": identifier.hex(), "payload": payload}
            for identifier, payload in chain.mempool.items()
        ],
    }


def chain_from_dict(payload: dict, parameters, verify) -> Chain:
    if payload.get("version") != STATE_VERSION:
        raise ValueError("unsupported chain state version")
    chain = Chain(parameters=parameters, depth=int(payload.get("depth", 2)), verify=verify)
    for entry in payload["blocks"]:
        chain.blocks.append(
            Block(
                height=int(entry["height"]),
                previous=bytes.fromhex(entry["previous"]),
                anchor=bytes.fromhex(entry["anchor"]),
                transactions=tuple(entry["transactions"]),
                nonce=int(entry["nonce"]),
                timestamp=int(entry["timestamp"]),
            )
        )
    for entry in payload["outputs"]:
        note = output_from_wire(entry)
        chain.outputs[output_id(note)] = note
    chain.spent_tags = {bytes.fromhex(value) for value in payload["spent_tags"]}
    for entry in payload["extra_pool"]:
        key = key_from_wire(entry)
        if key not in chain.pool:
            chain.pool.append(key)
    for entry in payload["mempool"]:
        chain.mempool[bytes.fromhex(entry["id"])] = entry["payload"]
        for tag in entry["payload"].get("tags", []):
            chain.pending_tags.add(tag_bytes(tag))
    return chain


def save_chain(chain: Chain, data_dir: Path) -> None:
    write_json(data_dir / STATE_FILE, chain_to_dict(chain))


def load_chain(data_dir: Path, parameters, verify) -> Chain | None:
    payload = read_json(data_dir / STATE_FILE)
    return None if payload is None else chain_from_dict(payload, parameters, verify)


# ------------------------------------------------------------- small stores
def load_address_book(data_dir: Path) -> list[dict]:
    return read_json(data_dir / ADDRESS_BOOK_FILE, []) or []


def save_address_book(data_dir: Path, entries: list[dict]) -> None:
    write_json(data_dir / ADDRESS_BOOK_FILE, entries)


def load_settings(data_dir: Path) -> dict:
    return read_json(data_dir / SETTINGS_FILE, {}) or {}


def save_settings(data_dir: Path, settings: dict) -> None:
    write_json(data_dir / SETTINGS_FILE, settings)


# ------------------------------------------------------------------- config
DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 8642,
    "log_level": "info",
    "auto_open_browser": True,
    # When true the app mines the mempool itself, so a transaction settles without
    # the operator pressing anything. Off by default: a node that silently mines is
    # surprising, and surprising is the last thing a testnet harness should be.
    "auto_mine": False,
    "auto_mine_interval": 3.0,
}


def load_config(data_dir: Path) -> dict:
    """The node's configuration, with defaults filled in and unknown keys dropped.

    A malformed config falls back to the defaults rather than refusing to start:
    the file is a convenience, not a security boundary.
    """
    try:
        stored = read_json(data_dir / CONFIG_FILE, {}) or {}
    except (OSError, ValueError):
        stored = {}
    config = dict(DEFAULT_CONFIG)
    config.update({key: value for key, value in stored.items() if key in DEFAULT_CONFIG})
    return config


def save_config(data_dir: Path, config: dict) -> None:
    merged = dict(DEFAULT_CONFIG)
    merged.update({key: value for key, value in config.items() if key in DEFAULT_CONFIG})
    write_json(data_dir / CONFIG_FILE, merged)
