# Radix — Plan to Mainnet

**Status:** draft, 2026-11-10. Nothing in this file is done. 159 tracked checkboxes across 17 sections.
**Baseline:** ~18% of mainnet readiness, measured by reading the code and running it (see "Baseline" below).
**Purpose:** the complete list of work between this commit and a mainnet launch. Every actionable line is a checkbox. Tick only when the *done when* condition is true and a test or artifact proves it.

---

## How to use this file

One checkbox per deliverable; do not tick a parent item because a sub-item shipped. An item is closed by evidence: a merged change **and** the test or artifact named in *done when*. IDs are stable — reference them in commits, issues and review notes (`closes P0-2`). Sizes are for one competent engineer: **S** < 1 week, **M** 1–4 weeks, **L** 1–3 months, **XL** 3+ months. Tags: **blocker** = mainnet cannot launch without it; **launch** = required for a credible launch; **hardening** = can follow launch only with an explicit written exception. Phases are not strictly sequential, but the milestone order is (see `M. Milestones`).

---

## Baseline (reference, not tasks)

This plan starts from a two-and-a-half-day-old research tree (177 commits, 8–10 Nov 2026) containing a genuine SMILE lattice ring signature with a cross-verified Rust port, wrapped in a chain harness that is not yet a currency.

The decisive measured fact: on 2026-11-10 a spend claiming a **1,000,000,000-atom input** against a **4,000-atom genesis** was accepted by the real verifier, admitted by `Chain.submit`, and mined into a block. The recipient held 999,999,999 atoms afterwards. Value is not bound to notes, so supply is not conserved.

Other confirmed defects feeding this plan:

| Finding | Evidence |
|---|---|
| Peer blocks are applied without verifying transactions | `node.py:226` calls `append()` with the default `verify_transactions=False` (`chain.py:507`) |
| Block hash commits to transaction *count*, not contents | Two blocks with different transactions hash identically (`chain.py:89–101`) |
| "Work" is block count | `cumulative_work()` returns `len(blocks)` (`chain.py:563–570`) |
| No fork resolution | `append()` refuses any non-successor (`chain.py:515–523`) |
| Restart loses consensus state | `store.chain_to_dict` drops `target`, `coinbase`, `minted`, `immature`, `treasury` (`store.py:98–120`) |
| No shipped peer listener | `p2p.Server` is started only in tests; `app.py` never imports it |
| Relay auth is broken | `node.py:596` drops the shared secret |
| Supply cap checks emission only | `check_supply` called on `minted` only (`chain.py:632–633`) |
| Amounts are public | `input_values` and output values in the clear on the wire (`chain.py:699–717`) |
| One spend per keypair, forever | Tag is `A'·s`, a function of the secret (`wallet.py:1–15`) |
| Debug prints inside the verifier | 14 `RADIX_DEBUG_VERIFY` lines (`setmembership.py:892–1190`) |
| The mainnet "switch" is not wired | `radix_testnet` never imports `radix_core.launch`; it gates a different (STARK) design |

The cryptography is the strongest part; the ledger, network, storage, wallet and launch machinery are the work.

---

## 0. Start here — next 10 working days

- [ ] **S-01** (S) Reproduce the inflation failure as a regression test that currently passes (i.e. the forgery is accepted), then invert it when P0-1 lands.
- [ ] **S-02** (S) Make `Chain.append` verify by default and pass `verify_transactions=True` from `node.py:226`. Land with a test that a peer block with a bad proof is refused.
- [ ] **S-03** (S) Remove the 14 `RADIX_DEBUG_VERIFY` prints and the dead code after `return` in `setmembership.py:1173–1188`.
- [ ] **S-04** (S) Persist `target`, `coinbase`, `minted`, `immature` and `treasury` in `store.chain_to_dict` / `chain_from_dict`; add a restart test asserting identical `next_target` and preserved supply accounting.
- [ ] **S-05** (S) Fix `node.relay_tx` to pass the p2p secret; add a relay+auth test.
- [ ] **S-06** (S) Write the header-commitment design note (transaction root, state root, where they go, how they are proven) for P0-3.
- [ ] **S-07** (S) Freeze D1 and D2 (architecture and privacy claim) in a one-page decision record.
- [ ] **S-08** (S) Add one node-wide mutation lock around peer append, `getchain` and mining; add a threaded stress test.
- [ ] **S-09** (S) Start `p2p.Server` behind a config flag in `app.py` and `cli.py`; prove two packaged nodes can exchange a block.
- [ ] **S-10** (S) Put a CI gate on: no bare `print` in library code, no debug env vars, duplicate definitions, unreachable code.

---

## D. Decisions (must be made before the corresponding work starts)

- [ ] **D1** (M) **Pick one architecture.** Launch path is either Candidate B (lattice ring signature + spent-tag ledger, what `radix_testnet` runs) or Candidate A (`radix_core` commitment/nullifier/Merkle/ML-KEM reference core). `launch.py` describes a third, unimplemented STARK design. *Done when:* one tree is the launch path, the others are archived out of the release build, and `launch.py` describes the chosen system.
- [ ] **D2** (M) **State the privacy claim precisely.** Ring anonymity with public amounts, or confidential amounts. The value-binding research is unfinished. *Done when:* one normative sentence in the spec, reflected exactly in the proof statement and the RPC documentation.
- [ ] **D3** (M) **Pick consensus.** PoW as designed, a redesigned PoW, or PoS/BFT. *Done when:* decision record plus a security-budget model that states the assumed hashrate (PoW) or validator set (PoS) and the cost of an attack.
- [ ] **D4** (S) **Fix unit, decimals and supply cap.** Today 100 atoms/unit (2 decimals) and a cap chosen to fit under `q/2`. *Done when:* the frozen constant table is in the spec and in one code location.
- [ ] **D5** (M) **Pick the wallet model.** One-time addresses (B2) so a keypair is not burned by one spend, or an explicit account model. *Done when:* scope and UX are written down; `wallet.py` redesign or patch is scheduled against it.
- [ ] **D6** (M) **Define the launch bar and sign-off.** *Done when:* the go/no-go gate in section G is signed by named owners.

---

## P0. Correctness blockers

- [ ] **P0-1** (XL) **Bind value to notes.** Every output carries a value commitment; the spend proof proves the input values open real notes, that outputs are in range, and that balance holds as a proven relation rather than `sum(input_values) == sum(outputs) + fee`. *Where:* `chain.py:376–390`, `wallet.py:238`, `tagged.py:128–139`. *Done when:* the 1,000,000,000-atom forgery against a 4,000-atom note is rejected by the real verifier, and the regression test from S-01 is green in both proof backends.
- [ ] **P0-2** (S) **Verify foreign transactions on every path.** `Node.handle_p2p` must not use the `verify_transactions=False` default. *Where:* `node.py:226`, `chain.py:507`. *Done when:* a peer-supplied block with an invalid proof is rejected, and the default of `append` is fail-closed.
- [ ] **P0-3** (M) **Commit the header to its contents.** Add a transaction Merkle root and a UTXO/state root to `Block.header()`. *Where:* `chain.py:89–101`. *Done when:* two blocks with different transaction sets can never share a hash, and an inclusion proof verifies.
- [ ] **P0-4** (L) **Fork choice and undo journal.** Compare cumulative work (`Σ work()`), deterministic tie-break, roll back N blocks, replace the "fork reconciliation is not implemented" error. *Where:* `chain.py:507–538`, `:563–570`. *Done when:* a 100-block fork test converges both nodes on the higher-work branch and a deep-reorg test passes.
- [ ] **P0-5** (M) **Persist all consensus state.** `target`, `coinbase`, `minted`, `immature`, `treasury`. *Where:* `store.py:98–120`. *Done when:* a mid-chain restart yields identical `next_target`, identical block acceptance, preserved `minted`, and immature coinbase still matures.
- [ ] **P0-6** (M) **Single-writer node.** Peer append and `getchain` currently mutate/serialize outside `node.lock`. *Where:* `node.py:223–233` vs `:548–582`. *Done when:* a HTTP + p2p + miner stress test runs clean with no corruption or serializer exceptions.
- [ ] **P0-7** (M) **Ledger-wide conservation invariant.** Assert per block: `Σ unspent outputs + fees + treasury == emission`. Today only emission is counted. *Where:* `chain.py:632–633`. *Done when:* a total-supply RPC is exact and monotone, and the 10⁹ test trips the invariant.
- [ ] **P0-8** (S) **One canonical transaction ID.** `submit` hashes `str(payload)` (`chain.py:369`); `transaction_key` hashes canonical JSON (`node.py:584–587`). *Done when:* a single encoder produces one id in Python, Rust and the wire spec, with a test vector.
- [ ] **P0-9** (S) **Purge debug and dead code from the verifier.** 14 `RADIX_DEBUG_VERIFY` prints, duplicate `tag_of`/`sign_tagged`/`verify_tagged` in `ring_signature.py`, unreachable code at `setmembership.py:1173`. *Done when:* CI gates listed in S-10 are green.

---

## L. Ledger and consensus

- [ ] **L-1** (M) Block size, transaction count and max proof byte limits. *Done when:* oversized blocks are refused with a specific error and a test.
- [ ] **L-2** (M) Deterministic transaction ordering (mempool insertion order is consensus today). *Done when:* two nodes with different arrival orders build identical blocks from the same mempool.
- [ ] **L-3** (M) Block validation completeness: duplicate tx ids, coinbase bounds, tx count, timestamp bounds, `chain_id`/network magic in every signed message. *Done when:* each rule has a negative test.
- [ ] **L-4** (L) Independent review of the difficulty algorithm (custom LWMA + slow start, `chain.py:412–455`) against a reference implementation. *Done when:* a written review and oscillation tests at the clamps.
- [ ] **L-5** (M) Timestamp policy: median-time-past, future drift, clock skew. *Done when:* adversarial timestamp tests pass.
- [ ] **L-6** (M) Replay protection between devnet, testnet, stagenet and mainnet. *Done when:* a mainnet-signed transaction is rejected on testnet and vice versa.
- [ ] **L-7** (L) Finality or weak-subjectivity checkpoint policy. *Done when:* the policy is specified, implemented and visible in the RPC.
- [ ] **L-8** (M) Genesis tooling: deterministic, versioned genesis; allocation committed; no hardcoded public key. *Where:* `params.py:48–51`. *Done when:* three independent parties reproduce the same genesis hash.
- [ ] **L-9** (M) Protocol versioning and activation (height-based hard forks, downgrade rules). *Done when:* a testnet upgrade is rehearsed end to end.
- [ ] **L-10** (L) Normative consensus specification with executable test vectors. *Done when:* an implementation from the spec alone passes the vectors.
- [ ] **L-11** (M) Adversarial consensus tests: selfish mining, timestamp manipulation, difficulty oscillation, long-range attack. *Done when:* each is a deterministic simulation test in CI.

---

## C. Cryptography and privacy

- [ ] **C-1** (XL) **Close the value-binding / range-proof research.** The trace-pairing route was measured and reverted; the coefficient-domain bridge is open. This is the schedule-critical item. *Done when:* a written construction, a soundness argument, and a working proof in both languages.
- [ ] **C-2** (L) Run a lattice estimator against the final parameters and publish the security level. *Done when:* estimator output committed and referenced by the audit.
- [ ] **C-3** (XL) **Independent audit #1**: protocol and proof system (SMILE transcription, tag, range, balance). *Done when:* signed report received, findings tracked as issues.
- [ ] **C-4** (L) Remediate audit findings and run **audit #2** on the fixes. *Done when:* no open critical or high findings, retest letters attached.
- [ ] **C-5** (XL) Written soundness proofs for the range/carry/balance layer and the same-witness tag. *Done when:* proofs reviewed by an external cryptographer and referenced from the spec.
- [ ] **C-6** (M) **CSPRNG everywhere.** Keygen uses `random.Random` seeded by SHA-256 (`wallet.py:39–41`); proof masks default to `random.Random()` (`wallet.py:230`). *Done when:* no cryptographic randomness comes from `random`, and nonce derivation is deterministic with domain separation.
- [ ] **C-7** (M) Key-derivation review: `wallet_seed` is a single SHA-256 of the phrase (`mnemonic.py:338–347`). *Done when:* a reviewed KDF is in use, BIP-39 conformance is tested, and the derivation is versioned.
- [ ] **C-8** (L) One-time addressing / stealth (B2) wired end to end. `stealth.py` exists and is tested but nothing uses it. *Done when:* a wallet can receive to a meta-address, the sender derives a one-time key, and the recipient scans and spends it.
- [ ] **C-9** (M) Address format: version byte, network prefix, checksum, strict length validation. *Where:* `wallet.py:63–77`. *Done when:* a single-character typo is rejected, not silently accepted.
- [ ] **C-10** (L) Constant-time / side-channel review of signer and verifier; audit the Rust port. *Done when:* a written review and fixes for secret-dependent branches.
- [ ] **C-11** (M) Proof-decoder hardening: strict bounds, no unbounded allocation, fuzzing. *Done when:* a fuzz corpus runs in CI for a fixed budget per build.
- [ ] **C-12** (M) Retire the withdrawn tag path. `tag.py` is marked *KNOWN BROKEN — DO NOT USE* and is still imported; the forgery test is a strict `xfail` (`test_candidate_b_tag.py:108`). *Done when:* the path is removed from the launch tree and the xfail is deleted with the code.
- [ ] **C-13** (L) Proof size and verification cost: 23–32 KB and 110 ms are far from a phone budget. *Done when:* measured on the declared target device and inside the budget, or the budget is renegotiated.
- [ ] **C-14** (M) Post-quantum transport key exchange (ML-KEM) if post-quantum is a network-level claim. *Done when:* the handshake is specified, implemented and audited with the transport.
- [ ] **C-15** (L) A second independent implementation or a formal spec for differential testing. Python and Rust currently share one author and one mental model. *Done when:* a third implementation or a mechanised specification agrees on all vectors.
- [ ] **C-16** (S) Remove or archive the classical LSAG track (`candidate_b/lsag.py`, `group.py`, `protocol.py`). *Done when:* it is out of the launch tree and out of the release build.

---

## N. Networking

- [ ] **N-1** (M) **Start a peer listener in the shipped product.** `p2p.Server` is started only in tests; `app.py` never imports it and `cli.py` only dials. *Done when:* a packaged node accepts an inbound peer.
- [ ] **N-2** (L) Peer identity: signed handshake with a node key; drop the shared-secret HMAC model. *Where:* `p2p.py:52–88`. *Done when:* a peer is identified by key, and a message from an unknown key is refused.
- [ ] **N-3** (L) Transport encryption (Noise or TLS) with replay resistance. *Done when:* a passive observer cannot read or replay traffic, demonstrated by test.
- [ ] **N-4** (S) Fix `relay_tx` dropping the secret (`node.py:596`) and add a relay+auth test. *Done when:* transaction relay works with authentication enabled.
- [ ] **N-5** (L) Real gossip: inv/getdata, block and transaction relay, compact blocks, mempool sync, dedup. *Done when:* a 50-node network propagates a block under the target latency.
- [ ] **N-6** (M) Address discovery: DNS seeds, peer store, gossip; eclipse-attack resistance. *Done when:* a new node bootstraps from a seed and an eclipse simulation fails to isolate it.
- [ ] **N-7** (M) Peer scoring, banning, connection limits, per-peer rate limits. *Done when:* a misbehaving peer is banned automatically and a test proves it.
- [ ] **N-8** (L) DoS hardening: message count and size budgets, verification queue with backpressure, CPU accounting. *Done when:* a flood test degrades gracefully instead of stalling the node.
- [ ] **N-9** (M) NAT traversal, inbound/outbound policy, optional Tor. *Done when:* a node behind NAT accepts inbound via the documented mechanism.
- [ ] **N-10** (L) Sync redesign: headers-first, verified checkpoint sync, state snapshots with proofs; drop whole-chain `getchain` (`node.py:194–198`). *Done when:* a node 1,000,000 blocks behind syncs under the target time with bounded memory.
- [ ] **N-11** (S) Buffer the 64 MB single-message path and the whole-chain-in-memory serialization. *Done when:* a maximum-size message cannot allocate unbounded memory.
- [ ] **N-12** (M) Wire-protocol spec, version negotiation, test vectors. *Done when:* two implementations interoperate from the spec.

---

## S. Storage, state and sync

- [ ] **S-1** (XL) Replace the JSON file with a database: atomic batches, WAL, crash recovery. `save_chain` currently rewrites the whole chain and all outputs on every block and transaction (`store.py:153–155`). *Done when:* a kill -9 during write recovers to a consistent tip, and block apply is O(block), not O(chain).
- [ ] **S-2** (M) Schema versioning and migrations. `STATE_VERSION` currently rejects anything unknown, so there is no upgrade path. *Done when:* an old database migrates forward and a newer one refuses cleanly.
- [ ] **S-3** (L) Indexed UTXO/note set and spent-tag set. Spent outputs are never removed and every output is appended to the ring pool (`chain.py:617–619`). *Done when:* storage growth is bounded by the pruning policy and index lookups are O(log n).
- [ ] **S-4** (M) Ring references by key hash, not positional index into a mutable list. *Done when:* a pool-order difference cannot invalidate a valid proof.
- [ ] **S-5** (M) Pruning policy and archival-vs-pruned node modes. *Done when:* both modes run the same validation and report their storage profile.
- [ ] **S-6** (M) Integrity check tool, backup/restore, snapshot export/import. *Done when:* a corrupted page is detected by the tool and a restore is rehearsed.
- [ ] **S-7** (M) Signed, verifiable checkpoints. The current checkpoint is explicitly "trust whoever produced it" (`checkpoint.py:12–21`). *Done when:* a checkpoint verifies against a signer set and a bad one is refused.
- [ ] **S-8** (M) Disk-growth model and disk-full behaviour; block-apply throughput benchmarks. *Done when:* published numbers and a graceful degraded mode.

---

## W. Wallet and key management

- [ ] **W-1** (L) Multi-input spends and real coin selection. Today exactly one input, one note, one ring (`wallet.py:202–244`). *Done when:* a spend from many notes is built, proven and verified, and change is handled correctly.
- [ ] **W-2** (L) Fix one-spend-per-key: one-time addresses or key rotation. Change currently cycles through four accounts (`wallet.py:32, 227`). *Done when:* an account can be spent more than once, or the constraint is removed by design.
- [ ] **W-3** (M) Wire the encrypted keystore. `radix_core/wallet_keystore.py` exists and is tested; the node stores the mnemonic in plaintext (`node.py:139–170`). *Done when:* the phrase is encrypted at rest with a user password.
- [ ] **W-4** (L) Hardware wallet or OS-keystore integration. *Done when:* signing happens outside the node process on at least one platform.
- [ ] **W-5** (L) View keys, watch-only wallets, scanning performance, light-client mode. *Done when:* a watch-only wallet follows the chain without holding spend keys.
- [ ] **W-6** (M) Recovery: seed restore, rescan, gap limit, derivation versioning. *Done when:* a wallet restored from phrase sees all historical notes.
- [ ] **W-7** (M) Decide threshold/multisig for treasury and large holders; implement if required. *Done when:* the decision is recorded and, if affirmative, a threshold spend is tested.
- [ ] **W-8** (M) Fee estimation, RBF/cancel, history and labels, confirmation UX. *Done when:* a stuck transaction can be replaced.
- [ ] **W-9** (L) Mobile wallet holding keys on-device. The Android app is a thin HTTP client to a local node (`android/.../NodeClient.java`). *Done when:* the app signs locally and never sends the seed to a node.
- [ ] **W-10** (M) Offline signing, QR workflows, address validation. *Done when:* an air-gapped sign/verify round trip is possible.
- [ ] **W-11** (L) Wallet security review and pen test. *Done when:* report received and findings closed.

---

## A. API, tooling and ecosystem

- [ ] **A-1** (L) Stable, versioned RPC (JSON-RPC or gRPC) with auth, TLS, rate limits, pagination. *Done when:* the RPC spec is frozen and an SDK is generated from it.
- [ ] **A-2** (S) Remove unauthenticated `/api/send` from any non-loopback deployment; add CSRF protection. *Where:* `node.py:686–690`. *Done when:* a remote caller cannot spend the node's wallet.
- [ ] **A-3** (M) Block explorer and explorer API. *Done when:* transactions, blocks and addresses are browsable.
- [ ] **A-4** (L) SDKs: JS/TS, Python, Rust, mobile. *Done when:* each SDK builds a transaction, signs it and submits it against a testnet.
- [ ] **A-5** (M) CLI: keys, transaction building, signing, queries. *Done when:* every RPC action has a CLI equivalent.
- [ ] **A-6** (M) Exchange integration docs and deposit confirmation policy; testnet faucet. *Done when:* an exchange can integrate from the document alone.
- [ ] **A-7** (M) Merchant indexer and webhooks. *Done when:* a payment is confirmed by webhook with reorg handling.
- [ ] **A-8** (M) API reference and quickstarts. *Done when:* published and tested by an external developer.

---

## F. Performance and device fit

- [ ] **F-1** (L) Prover on target devices. Measured: 128.5 s per spend in Python, ~0.5 s in Rust on this machine. *Done when:* a phone-class device produces a spend inside the declared UX budget.
- [ ] **F-2** (L) Proof size (23–32 KB) and verification cost (110 ms) against a stated device budget. *Done when:* the budget is met or formally renegotiated.
- [ ] **F-3** (M) Parallel and batch verification; mempool admission under load. *Done when:* throughput scales with cores.
- [ ] **F-4** (M) Block propagation latency and mempool throughput targets. *Done when:* measured on the 50-node testnet.
- [ ] **F-5** (M) Annual storage growth and minimum full-node hardware. *Done when:* published and reproduced on the reference machine.
- [ ] **F-6** (L) Native Rust library for mobile (JNI/Swift bridge), memory and battery budget. *Done when:* the mobile wallet uses it in a release build.
- [ ] **F-7** (M) Sustained-load test at the declared TPS. *Done when:* a 24-hour run holds the target without degradation.

---

## O. Operations and release engineering

- [ ] **O-1** (M) Reproducible builds, signed releases, SBOM, dependency pinning and audit. *Done when:* two independent machines produce bit-identical artifacts.
- [ ] **O-2** (M) Packaging: Windows, macOS, Linux, Docker; hardened systemd unit (`deploy/radix-node.service`). *Done when:* each platform installs, starts and upgrades.
- [ ] **O-3** (M) Config and secrets management, data-directory permissions, least privilege. *Done when:* a default install exposes no secret and no privileged port.
- [ ] **O-4** (L) Monitoring: metrics, dashboards, alerting, log aggregation. There is a text log and nothing else. *Done when:* an operator sees tip lag, peer count, mempool depth and disk pressure.
- [ ] **O-5** (M) Runbooks: start/stop, upgrade, rollback, reindex, restore, chain halt. *Done when:* each runbook is rehearsed by someone who did not write it.
- [ ] **O-6** (M) Incident response plan, on-call rota, disclosure policy, bug bounty. *Done when:* an incident drill is run and timed.
- [ ] **O-7** (L) Seed nodes, bootstrap infrastructure, DDoS protection, status page. *Done when:* the network survives a seed-node outage.
- [ ] **O-8** (M) Multi-region deployment and failover. *Done when:* a region loss does not stop block production.
- [ ] **O-9** (M) Upgrade and downgrade rehearsal (blue-green). *Done when:* a bad release is rolled back in one step.
- [ ] **O-10** (M) Release cadence and support policy. *Done when:* published with a versioning scheme.

---

## E. Economics, genesis, legal and governance

- [ ] **E-1** (L) Final monetary policy: supply cap, emission, tail, fee market, treasury. Treasury is booked but unspendable today (`chain.py:264–265`). *Done when:* the policy is specified and every parameter is consensus-enforced.
- [ ] **E-2** (L) Security-budget analysis: cost of a 51% attack, miner revenue, hashrate assumptions. *Done when:* the model is published and the assumed attacker cost is stated.
- [ ] **E-3** (XL) Genesis ceremony: multi-party, verifiable, air-gapped; allocation commitment; published hash. *Done when:* three independent parties reproduce the genesis block and hash.
- [ ] **E-4** (L) Allocation and distribution: vesting, treasury multisig, audited cap table. *Done when:* the allocation is committed and reproducible from the genesis data.
- [ ] **E-5** (XL) Legal: entity, jurisdiction, securities/tax/AML/KYC analysis, terms, privacy policy. *Done when:* counsel signs off in the launch jurisdictions.
- [ ] **E-6** (L) Governance: upgrade and parameter-change process, foundation, stewardship. *Done when:* a documented process exists and one parameter change is executed through it.
- [ ] **E-7** (M) Exchange listings, market makers, liquidity (if applicable). *Done when:* at least one venue is operationally ready.
- [ ] **E-8** (S) Unit and decimals standard, display rules. *Done when:* wallets and explorers agree on formatting.
- [ ] **E-9** (M) Communications: whitepaper, website, responsible-disclosure policy. *Done when:* published before genesis.

---

## T. Testing and assurance

- [ ] **T-1** (L) Full consensus test suite with adversarial nodes. Node tests currently stub the verifier; only one end-to-end test uses real proofs. *Done when:* a multi-node adversarial suite runs in CI nightly.
- [ ] **T-2** (L) Property-based ledger invariants: conservation, no double spend, no inflation, deterministic replay. *Done when:* randomized property tests run for a fixed budget per build.
- [ ] **T-3** (M) Fuzzing: wire decoder, proof decoder, RPC, p2p parser. *Done when:* a corpus and a fuzz target run in CI.
- [ ] **T-4** (M) Differential testing Python vs Rust vs spec, extended to consensus. *Done when:* every consensus rule has a cross-implementation vector.
- [ ] **T-5** (L) Multi-week soak test on a real network. *Done when:* a four-week run has no consensus failure and no memory growth.
- [ ] **T-6** (L) Chaos: partitions, reorgs, crashes, disk full, clock skew, byzantine peers. *Done when:* each scenario is automated and passes.
- [ ] **T-7** (XL) Public testnet phases with incentives and a live bug bounty. *Done when:* at least 90 consecutive days of public operation with no critical incident.
- [ ] **T-8** (L) Stagenet with mainnet parameters; full mainnet rehearsal and abort drill. *Done when:* the rehearsal executes the entire launch runbook.
- [ ] **T-9** (XL) Independent security audit of node, network, storage and wallet (beyond the cryptography). *Done when:* report received and critical/high findings closed.
- [ ] **T-10** (M) Pen test of RPC/API, desktop app and Android app. *Done when:* report received and findings closed.
- [ ] **T-11** (M) Formal verification of arithmetic (modulus, CRT, NTT) if feasible. *Done when:* the decision is recorded and, if done, the proofs are reviewed.

---

## X. Launch execution

- [ ] **X-1** (M) Go/no-go checklist with named owners and explicit criteria. *Done when:* section G is signed.
- [ ] **X-2** (M) Genesis block generation, hash publication, independent verification. *Done when:* the hash is published and reproduced by third parties.
- [ ] **X-3** (M) Seed nodes and monitoring live before genesis. *Done when:* a pre-launch health check is green.
- [ ] **X-4** (M) Abort and rollback plan if genesis or early blocks are wrong. *Done when:* the plan is rehearsed on stagenet.
- [ ] **X-5** (M) Comms, status page, support channels, incident rota. *Done when:* every channel is staffed for launch week.
- [ ] **X-6** (M) Post-launch monitoring window and fast-response process. *Done when:* the first 30 days have a named owner per subsystem.
- [ ] **X-7** (S) Publish hard-fork and emergency-response policy. *Done when:* published before genesis.
- [ ] **X-8** (S) Post-launch retro and audit follow-up. *Done when:* scheduled and owned.

---

## M. Milestones

- [ ] **M0 — Safe to demo.** S-01…S-10, P0-2, P0-3, P0-5, P0-6, P0-8, P0-9, N-4. *Exit:* no known path to mint coins without a valid proof on a peer-connected node.
- [ ] **M1 — Sound single node.** P0-1, P0-4, P0-7, L-1…L-3, S-1. *Exit:* value is bound, forks converge, restart is lossless, supply is conserved.
- [ ] **M2 — Real network.** Phase N, S-3…S-6, C-6. *Exit:* a 50-node testnet survives partitions and restarts.
- [ ] **M3 — Feature-complete testnet.** Phases W, A, O, E-3…E-6. *Exit:* a stranger can install, receive, spend and recover without help.
- [ ] **M4 — Audited.** C-2…C-5, C-10, T-1…T-9; two audit cycles and remediation. *Exit:* no open critical or high findings, and soundness proofs are written.
- [ ] **M5 — Launch.** T-7, T-8, Phase X. *Exit:* section G is fully ticked.

**Rough shape:** 60–90 engineer-months of implementation plus two audit cycles. For ~8 engineers and 2 cryptographers that is 18–30 months, call it about two years. Critical path: **C-1 → C-5 → C-3/C-4**. Nothing shortens it except narrowing D2, because the audit cannot start on a protocol that is still changing.

---

## G. Go/no-go gate (all required)

- [ ] **G-1** Every P0 item is closed with a regression test that fails without the fix.
- [ ] **G-2** Value binding and the range proof are implemented, proven and audited (P0-1, C-1, C-5).
- [ ] **G-3** Two independent audits are closed with no open critical or high findings (C-3, C-4, T-9).
- [ ] **G-4** 90 consecutive days of public testnet with no consensus failure and no inflation (T-7).
- [ ] **G-5** Fork, partition, reorg and restart tests pass on a 100-node network (P0-4, T-6).
- [ ] **G-6** Genesis ceremony reproduced by three independent parties (E-3, X-2).
- [ ] **G-7** Monitoring, on-call, rollback and abort drills are rehearsed (O-4, O-5, O-6, X-4).
- [ ] **G-8** Legal, allocation and distribution are signed off (E-4, E-5, E-6).

---

## Z. Delete rather than fix (remove from the launch path)

- [ ] **Z-1** `radix_core` Candidate-A reference core (unused by the running node) — archive or delete.
- [ ] **Z-2** `archive/` — keep out of the release build and out of the launch tree.
- [ ] **Z-3** `candidate_b/lsag.py`, `group.py`, `protocol.py` — classical LSAG, a different scheme.
- [ ] **Z-4** `candidate_b/lattice/tag.py` — marked *KNOWN BROKEN — DO NOT USE*, still imported.
- [ ] **Z-5** `spend.TagSet` — unused and only meaningful for a withdrawn construction.
- [ ] **Z-6** `codec.py` spend envelope (`spend_to_dict`, `spend_from_dict`, `envelope_bytes`) — dead; the live format is `chain.spend_to_wire`.
- [ ] **Z-7** `pruned_storage_model.py` — not wired to anything.
- [ ] **Z-8** The STARK/ML-KEM fiction in `launch.py` — either implement it or describe the system that exists.
- [ ] **Z-9** `miner.py` stale docstring ("no difficulty adjustment") and any other comment that contradicts the code.

---

## Schedule notes

**What compresses the plan.** Dropping the confidentiality claim removes the range proof from the critical path and turns a research bet into an engineering project; it is the single largest saving. Choosing PoS removes PoW economics and 51%-cost analysis but adds validator-set and finality work, roughly neutral unless that expertise already exists. Keeping ring size at 32² and accepting 30 KB proofs avoids the proof-size research track.

**What extends it a lot.** If the lattice proof system genuinely cannot express value balance (the `R`-linearity bridge), a second proof subsystem is needed — that is a new protocol, not a patch, and pushes past 36 months. If audit #1 finds a soundness break in the ring signature itself, the SMILE track may need replacing.

**What must never happen.** Shipping with P0-1 open because "the demo works"; calling an informal review an audit; treating a signed checkpoint as consensus; opening `MAINNET_SWITCH` before G-1 through G-8 are true.

---

## Bottom line

The list is long, but only one item decides the schedule: **P0-1**, proving value without breaking the lattice proof. Until that closes, everything else is built on a ledger that cannot count. The first ten days are about stopping the bleeding, not features.
