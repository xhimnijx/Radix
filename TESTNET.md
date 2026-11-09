# Radix testnet

A local harness for exercising the Candidate-B proof end to end: a wallet that
signs a real 1024-member ring signature, a node that verifies it with the real
verifier, and a miner that settles it in a block.

> **This is not a cryptocurrency.** No value, no consensus, no peer-to-peer
> network, no economic layer, no security claim. One process on localhost, one
> chain, one miner. See `STATUS.md` for where the cryptography actually stands.

## Run it

From source:

```powershell
python -m radix_testnet                 # starts the node and opens the wallet
python -m radix_testnet --no-browser    # headless
```

From the packaged executable (Windows):

```powershell
.\dist\RadixTestnet.exe
```

Either way you land on <http://127.0.0.1:8642/> with the wallet open. Ctrl+C stops
it. State lives in `%LOCALAPPDATA%\RadixTestnet` on Windows and
`~/.local/share/RadixTestnet` elsewhere; `--data-dir` overrides it.

## Build the packaged app

PyInstaller **cannot cross-compile**. The Windows `.exe` must be built on Windows,
the macOS binary on macOS, the Linux binary on Linux. `.github/workflows/build.yml`
does exactly that on three native runners and uploads one artefact per platform —
that is the supported way to get all three.

```powershell
# Windows, from the repository root
.\packaging\build-windows.ps1            # -> dist\RadixTestnet.exe
.\packaging\build-windows.ps1 -Clean     # from scratch
```

```bash
# macOS and Linux
python -m pip install -e . pyinstaller
python -m PyInstaller --noconfirm --clean --distpath dist --workpath build packaging/radix-testnet.spec
```

The bundle contains the Python runtime, `segno` for QR codes, and the GUI as static
data. It does not contain a browser engine: the window is your own browser pointed
at the local server.

## The wallet

Four accounts derived from one seed, a send flow with a review step, receive with a
locally generated QR code, history, an address book, and light/dark themes. The
banner on every screen says TESTNET · NO VALUE · NO SECURITY CLAIM, because a
finished-looking wallet over unaudited cryptography is how people get hurt.

**Why accounts, not notes.** Two facts from the cryptography force this:

1. A ring signature hides *which* output it spends, so the chain can never remove
   one. Every output ever created is kept; double spends are prevented by tags.
2. The same-witness tag is `T = A' s` — a function of the **secret**, not of the
   note. One keypair therefore owns one tag and can be spent exactly once.

So an account is the unit of spendability, and change goes to the next account. A
real wallet gives every output its own key through one-time addressing; that is B2
work and is not built here.

**Addresses.** A lattice public key is 4 x 512 = 2048 bytes, so an address is
`rtx1` followed by base64url of the key: 2,735 characters. Hex would be 4,096 and
would **not fit in a QR code** (byte mode tops out at 2,953), which is why the
encoding is base64url and the QR uses error-correction level L. The UI shows a
truncated address with Copy and Show full rather than a wall of text.

**What a send costs.** Two backends, both real:

| backend | prove | verify |
|---|---|---|
| python (reference) | ~1–2 min | ~20–38 s |
| **rust** | **0.5–0.9 s** | ~110 ms |

The Rust backend is the same protocol, ported and cross-checked: a Rust proof is
accepted by the Python verifier and vice versa. Build it with

```powershell
cd proof_rust
cargo build --release --bin prove_request
```

and select it with `python -m radix_testnet.cli --backend rust (the default) ...`, or by setting
`RADIX_PROVE_BIN` to the binary. If the binary is missing, `--backend rust (the default)` **refuses**
rather than silently falling back to Python — a demo that claims the fast path and
quietly uses the slow one is worse than no demo.

## Version and packaging details

`--version` on the launcher and the CLI, `version` in `/api/status`, and the same
string in the Settings page all come from `radix_testnet.__version__`, so they
cannot drift. The executable carries that version plus the disclaimer as Windows
file metadata, and ships with an icon: right-click it in Explorer and the
description reads "Valueless local testnet harness for the Candidate-B proof".

## Configuration and logs

First start writes `config.json` next to the chain:

```json
{
  "host": "127.0.0.1",
  "port": 8642,
  "log_level": "info",
  "auto_open_browser": true,
  "auto_mine": false,
  "auto_mine_interval": 3.0
}
```

Set `"auto_mine": true` and the app mines the mempool itself, so a send settles
without pressing anything. It is off by default: a node that silently mines is
surprising, and surprising is the last thing a testnet harness should be.

Command-line flags override it. Events are written as JSON lines to stderr and to
`node.log` in the same directory — `node.start`, `chain.ready`, `tx.accepted`,
`block.mined`, and `request.rejected` with the reason. A packaged app has no console
to read, so the file is the record.

## CLI

```powershell
python -m radix_testnet.cli status
python -m radix_testnet.cli address
python -m radix_testnet.cli send --to rtx1... --amount 100 --fee 10
python -m radix_testnet.cli mine
python -m radix_testnet.cli gui
```

## Node API

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | the wallet page |
| `/api/status` | GET | height, tip, balances, parameters, backend |
| `/api/accounts` | GET | the four accounts, balances and whether spent |
| `/api/history` | GET | confirmed and pending transactions |
| `/api/mempool` | GET | pending transactions |
| `/api/blocks` | GET | block list |
| `/api/addressbook` | GET/POST | saved contacts |
| `/api/settings` | GET/POST | theme and preferences |
| `/api/qr?text=` | GET | SVG QR code, generated locally |
| `/api/send` | POST | sign and submit a spend *(slow: 1–2 min)* |
| `/api/mine` | POST | mine the mempool into a block |
| `/api/tx` | POST | submit a pre-built envelope |

## Layout

| File | Role |
|---|---|
| `chain.py` | blocks, trivial proof of work, mempool, outputs, 1024-key decoy pool, tag rejection |
| `tagged.py` | tagged spend builder and verifier |
| `wallet.py` | seed → accounts, addresses, tags, notes, send with change |
| `prover.py` | the python/rust seam |
| `codec.py` | `Proof` decoder and the spend envelope |
| `store.py` | atomic on-disk chain, address book, settings and config |
| `log.py` | JSONL event log to stderr and `node.log` |
| `node.py` | HTTP API and GUI server |
| `app.py` | desktop launcher |
| `miner.py` | mine the mempool |
| `cli.py` | command line |
| `static/index.html` | the wallet page, no external dependencies |
| `log.py` | JSONL event log |
| `packaging/` | PyInstaller spec, icon, version metadata, build script |

Rings travel as **pool indices**, not keys: a depth-2 ring is 1024 lattice keys
(≈2 MB) and no chain would put that in a block, so an envelope is ~70 KB.

## Limitations, stated rather than hidden

* **No consensus.** One node, no peers, no fork choice.
* **No persistence of trust.** The chain file is trusted on load and is not
  re-verified; do not share a data directory between machines.
* **No economic layer.** The faucet is funded at genesis from nothing.
* **The faucet seed is a public constant.** Anyone running this harness can derive
  the same keys and spend the same units. That is deliberate — a faucet nobody can
  use is not a faucet — and it is why there is no encrypted keystore: encrypting a
  seed that is printed in the source would imply a security property the harness
  does not have. `radix_core/wallet_keystore.py` has the sealed-key machinery if a
  real wallet ever needs it.
* **One key per account.** Spending an account burns it; change moves to the next.
* **Trivial proof of work.** `POW_BITS = 10`, for block shape, not security.
* **Deterministic parameters.** A fixed seed so node, wallet and tests agree; a real
  deployment takes parameters from a reviewed manifest and keys from entropy.

## Tests

```powershell
python -m pytest -q tests/test_testnet_chain.py        # 9 tests, ~4 s, stub verifier
python -m pytest -q tests/test_testnet_node.py         # 17 tests, ~30 s, HTTP over a real socket
python -m pytest -q tests/test_testnet_end_to_end.py   # real proof, ~5 min
```

The fast suite tests the plumbing with a stub verifier. The slow one runs an actual
proof through the node, checks the recipient's note and the sender's change, and
checks that the second spend is refused by its tag.
