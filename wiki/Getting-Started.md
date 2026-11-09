# Getting started

## Option 1 — prebuilt app

Download from **[Releases](https://github.com/xhimnijx/Radix/releases)**:

| platform | file | note |
|---|---|---|
| Windows | `RadixTestnet-windows-x64.exe` | unsigned, so SmartScreen warns |
| macOS | `RadixTestnet-macos` | may need `xattr -d com.apple.quarantine <file>` |
| Linux | `RadixTestnet-linux` | `chmod +x` then run |

Each is built natively on its own platform; PyInstaller cannot cross-compile.

Run it and your browser opens the wallet at <http://127.0.0.1:8642/>.

## Option 2 — from source

```powershell
git clone https://github.com/xhimnijx/Radix.git
cd Radix
python -m pip install -e .
python -m radix_testnet
```

Python 3.12 or newer.

## Send your first transaction

1. Open the wallet; the node's faucet already holds 4,000 testnet units.
2. Go to **Receive**, choose an account, copy the address (or scan the QR).
3. Go to **Send**, paste the address, choose an amount and fee.
4. **Review** shows the totals; **Confirm & sign** starts the proof.

On the Python backend a proof takes **1–2 minutes** — the UI shows elapsed time while it
runs. Mine the mempool from the wallet or with `python -m radix_testnet.cli mine`.

## Use the fast backend

```powershell
cd proof_rust
cargo build --release --bin prove_request
cd ..
python -m radix_testnet.cli --backend rust send --to rtx1... --amount 100 --fee 10
```

Proving drops from minutes to about half a second. If the binary is missing the backend
**refuses** rather than silently falling back.

## Common problems

| symptom | cause |
|---|---|
| `no node at http://127.0.0.1:8642` | the node is not running — start it with `python -m radix_testnet` |
| state seems stale after an experiment | delete `%LOCALAPPDATA%\RadixTestnet` (Windows) or `~/.local/share/RadixTestnet` |
| `the Rust prover is not built` | run the `cargo build` command above, or set `RADIX_PROVE_BIN` |
