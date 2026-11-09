# Deploying a stagenet node

How to run the testnet node on a second machine (a spare Ubuntu laptop) so that your
PC, your phone and other people can use it.

> [!WARNING]
> **Research prototype. No value, no security claim.**
> The node has **no authentication**: anyone who can reach the port can spend the
> faucet. It has **no rate limiting**, and a bad proof costs it 110 ms (Rust) or up to
> 20 s (Python), so a trivial loop is a denial of service. Do not put it on the public
> internet. The section on access explains what to do instead.

## Read this before you plan anything: there is no peer-to-peer layer

`radix_testnet` is **one process with one chain**. Two nodes do not discover each
other, do not sync, and do not agree. Consequences that matter:

- The Ubuntu laptop is **the** node. Your PC and phone are *clients* pointing at it.
  That is what a stagenet is here — one server, several clients — not a network of
  peers.
- **The data directory is the only copy of the chain.** There is nothing to re-sync
  from. Back it up, or treat it as disposable and accept starting over.
- Two independent nodes are two *separate* universes with different chains. Useful for
  testing, misleading if you call it a network.

## The shape of the setup

```text
      Ubuntu laptop                          your devices
  ┌────────────────────┐              ┌──────────────────────┐
  │ radix-node.service │◄── WireGuard │ Windows PC (browser) │
  │  127.0.0.1:8642    │   or Tailscale│ Android app          │
  │  /var/lib/radix    │              │ a reviewer's browser │
  └────────────────────┘              └──────────────────────┘
```

The node binds `127.0.0.1` by default. Remote clients reach it through a private
network, never through a port forward.

## Install on the Ubuntu laptop

```bash
sudo apt-get install -y git
git clone https://github.com/xhimnijx/Radix.git
cd Radix
sudo ./deploy/install-node.sh
```

The script installs to `/opt/radix`, prints the recovery phrase **once**, and enables
`radix-node.service` with the chain and wallet in `/var/lib/radix`.

Check it:

```bash
curl -s http://127.0.0.1:8642/api/status | head -c 400
sudo -u radix python -c "print(open('/var/lib/radix/wallet.mnemonic').read())"
```

### If Python is older than 3.12

```bash
sudo apt-get install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt-get install -y python3.12 python3.12-venv
sudo ./deploy/install-node.sh   # re-run; it picks up python3
```

## Access from your other devices

### Option A — Tailscale (easiest)

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4          # e.g. 100.101.102.103
```

Then on every device, install Tailscale and use `http://100.101.102.103:8642`.
Nothing is exposed to the internet; Tailscale handles NAT and encryption.

### Option B — WireGuard (no third party)

On the laptop, create `/etc/wireguard/wg0.conf` with a key pair and one peer per
device, then `sudo systemctl enable --now wg-quick@wg0`. Clients use the laptop's
WireGuard address (`10.8.0.1:8642`).

### Option C — same LAN, for testing only

```bash
sudo systemctl edit radix-node.service      # add:
# [Service]
# ExecStart=
# ExecStart=/opt/radix/.venv/bin/python -m radix_testnet.cli --data-dir /var/lib/radix node --host 0.0.0.0 --port 8642
sudo systemctl daemon-reload && sudo systemctl restart radix-node
```

Now `http://<laptop-LAN-IP>:8642` works from the same Wi-Fi. **Anyone on that Wi-Fi
can spend the faucet.** Turn it back off when you are done.

## Why not `radix.maximgil.com` yet

It is the right name for the future and the wrong move now. Three reasons:

1. **No authentication.** A public URL makes the faucet spendable by anyone who finds
   it, including scanners.
2. **No rate limiting.** 110 ms per proof means a few hundred requests per minute saturate
   the node. That is a one-line denial of service.
3. **It is a privacy coin.** Pointing a domain at your home connection permanently ties
   your identity and address to node activity. That is exactly the correlation the
   project exists to avoid.

When there is something worth publishing — after Phase 0 and a batch-verification
fix — put it on a **VPS** behind Caddy or Cloudflare with rate limits and proof-of-work
admission, and keep your home IP out of it entirely.

## Backups

| What | Where | What happens if lost |
|---|---|---|
| **Wallet phrase** | `/var/lib/radix/wallet.mnemonic` | **You lose the wallet.** Write the 12 words on paper; that file is a convenience copy. |
| Chain state | `/var/lib/radix/chain.json` | The chain is gone — there is no p2p to re-sync from. Restart from genesis, or restore the file. |
| Address book, settings | same directory | Cosmetic |

The phrase and the chain are a matched pair: outputs on the chain belong to keys
derived from the phrase. The node **refuses to start** if the phrase is missing while a
chain exists, precisely so this cannot happen by accident.

Back up the whole directory while the service is stopped:

```bash
sudo systemctl stop radix-node
sudo tar czf radix-backup-$(date +%F).tar.gz -C /var/lib radix
sudo systemctl start radix-node
```

## Operating it

```bash
sudo systemctl status radix-node
sudo journalctl -u radix-node -f          # logs
sudo journalctl -u radix-node -n 200      # recent
sudo systemctl restart radix-node
```

The node also writes JSONL events to `/var/lib/radix/node.log`
(`node.start`, `chain.ready`, `tx.accepted`, `block.mined`, `request.rejected`).

### Upgrading

```bash
cd Radix && git pull
sudo ./deploy/install-node.sh     # re-runs rsync, keeps /var/lib/radix
```

Because the wallet is a phrase and the chain is a file, an upgrade is only a code
swap. **A parameter change would not be** — it would be a new derivation version, and
the phrase would need to keep deriving the old wallet. That is what the `v1` tag in
`mnemonic.wallet_seed` is for.

### If you want the fast prover

```bash
sudo apt-get install -y cargo
cd /opt/radix/proof_rust && sudo cargo build --release --bin prove_request
sudo systemctl edit radix-node.service    # change --backend python to --backend rust
```

Proving goes from ~2 minutes to ~1 second; verifying from ~20 s to ~110 ms.

## Resources

- **Disk:** the chain grows monotonically — spent outputs cannot be pruned, because a
  ring signature hides which output was spent. A testnet is small; this is the scaling
  problem a real network would face.
- **CPU:** proving is the expensive part, and only the node's wallet does it when you
  send from the web UI. Verification is 110 ms per transaction with the Rust backend.
- **RAM:** a few hundred MB. The ring pool is 1024 lattice keys, ~2 MB.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `could not be read as a wallet phrase` | the phrase file is corrupt; restore your written phrase with `wallet --restore` |
| `missing but a chain exists` | the phrase was deleted; restore it or remove the chain deliberately |
| `no node at http://127.0.0.1:8642` | the service is not running — `systemctl status radix-node` |
| app shows `error: HTTP 400` on Send | the node rejected the spend; the reason is in the response and in `node.log` |
| `the Rust prover is not built` | `cargo build --release --bin prove_request` in `proof_rust/` |

## Related

- [`TESTNET.md`](TESTNET.md) — running locally and building the app
- [`SECURITY.md`](SECURITY.md) — what is in scope for a report
- `vault/The Android App.md` — pointing the phone at this node
