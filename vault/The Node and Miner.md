---
title: The Node and Miner
tags: [node, testnet, implementation]
---

# The node and the miner

`radix_testnet/node.py` and `miner.py`. One process, one chain, localhost only.

## What the node is

An HTTP service over an in-memory chain, plus the wallet page. It:

- verifies every submitted transaction with the **real** verifier before admitting it;
- refuses reused tags;
- mines on request (or automatically, if configured);
- persists chain, address book and settings to disk;
- logs structured events to `node.log`.

## The API

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | the wallet page |
| `/api/status` | GET | height, tip, balances, parameters, version, backend |
| `/api/accounts` | GET | the four accounts, balances, spent flags |
| `/api/history` | GET | confirmed + pending transactions |
| `/api/mempool` | GET | pending transactions |
| `/api/blocks` | GET | block list |
| `/api/addressbook` | GET/POST | saved contacts |
| `/api/settings` | GET/POST | theme and preferences |
| `/api/qr?text=` | GET | SVG QR, generated locally by `segno` |
| `/api/send` | POST | **sign and submit a spend** (slow on Python) |
| `/api/mine` | POST | mine the mempool |
| `/api/tx` | POST | submit a pre-built envelope |

Status codes are meaningful: 404 for unknown routes, 400 with a reason for refused
transactions or malformed JSON, 500 only for genuine faults.

## Concurrency

`ThreadingHTTPServer` so status polling continues while a 1–2 minute proof runs.
A single `threading.Lock` guards chain mutation, so the mine button, the miner thread
and an API call cannot interleave.

## Configuration

`config.json` in the data directory, written on first start:

```json
{ "host": "127.0.0.1", "port": 8642, "log_level": "info",
  "auto_open_browser": true, "auto_mine": false, "auto_mine_interval": 3.0 }
```

- Read with `utf-8-sig`, because Notepad and PowerShell both write a BOM and a config
  that fails on an invisible character is a terrible first experience.
- A **malformed config** falls back to defaults; a **corrupt chain** refuses to start.
  The asymmetry is deliberate: config is a convenience, chain state is data.
- `auto_mine: true` makes transactions settle without pressing anything. Off by
  default, because a node that silently mines is surprising.

## Logging

JSON lines to stderr and `node.log`:

```json
{"ts":"2026-11-09T11:33:30","event":"node.start","data_dir":"...","persist":true}
{"event":"chain.ready","height":0,"outputs":1,"pool":1025}
{"event":"tx.accepted","id":"0ec1d852f1","fee":10,"amount":140}
{"event":"block.mined","height":1,"hash":"...","transactions":1}
{"event":"request.rejected","route":"/api/send","reason":"..."}
```

A packaged app has no console to read, so the file is the record.

## The miner

`miner.py`:

- `mine_once(chain)` — mine one block, return a summary;
- `mine_forever(chain, interval)` — mine whenever the mempool is non-empty;
- `start_auto_miner(node, interval)` (in `app.py`) — a daemon thread, guarded by the
  node's lock.

The proof of work is 10 leading zero bits. It exists so a block must be *found*.

## Graceful shutdown

`serve()` catches `KeyboardInterrupt`, closes the socket, prints `stopped`. The
launcher catches `StateError` and exits with code 2 and a message naming the file,
rather than starting a fresh chain over unreadable state.

## What the node is not

No peers, no consensus, no fork choice, no difficulty adjustment. `radix_core/launch.py`
holds the mainnet gate and it is closed.
