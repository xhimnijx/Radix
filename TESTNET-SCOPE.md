# Non-value testnet scope

**Status:** scope only. Nothing here is implemented. This document exists so the
testnet milestone is a plan with exit criteria rather than an aspiration.

A testnet is the first artefact that can honestly be called "running". It carries
no value, has no token, and promises nothing beyond determinism and measurability.

---

## 1. What a testnet must have

| Component | Requirement | Exists today |
|---|---|---|
| Block wire format | Canonical, versioned, length-bounded, hash-compatible with the statement codec | No |
| Header + chain | Parent links, height, timestamp rules, chain ID, genesis | Only a `BlockHeaderRef` fixture with no serialization |
| PoW | One algorithm, exact target rule, chainwork, retarget | No |
| State | Persistent output tree, nullifier set, commitment set, atomic apply | In-memory only, quadratic replay |
| Proof verification | Injected verifier; a real component verifier for one profile | Component verifiers exist; no complete transaction verifier |
| Mempool | Admission rules, fee floor, eviction, relay | No |
| P2P | Peer discovery, handshake, block/tx propagation, anti-eclipse basics | No |
| Wallet | Key generation, encryption, send/receive, recovery, scan | Note create/recover/scan exist; no recovery phrase, no address text format |
| Genesis | Reproducible genesis construction and hash | No |
| Observability | Logs, metrics, a way to reproduce a failure | No |
| Resource caps | Enforced per-block and per-transaction limits | Caps are caller policy only |

## 2. Order of work and why

Dependencies are strict; doing these out of order is what produced the current
half-built state.

1. **Block wire format + header serialization.** Every other component needs a
   canonical byte representation, and it is cheap to get wrong later.
   *Exit:* vectors for a block with 0/1/max transactions; an independent parser
   rejects truncation, trailing bytes, and non-canonical counts.
2. **Persistent state.** Replace `validate_integrity()`-per-block and full clones
   with an incremental frontier and a durable key-value store.
   *Exit:* replay 10^5 blocks in under a minute on the reference laptop; restart
   resumes from disk with an identical root.
3. **Reference miner + difficulty.** One PoW function (RandomX candidate or a
   placeholder hash for the first testnet), exact integer target comparison,
   chainwork, and a retarget rule with test vectors.
   *Exit:* two independent implementations agree on 10,000 synthetic headers.
4. **P2P.** Handshake with protocol version/chain ID, block and transaction
   relay, peer scoring, and an eclipse-resistant bootstrap list.
   *Exit:* three nodes on one host converge after a partition and a 20-block reorg.
5. **Wallet send/receive.** Transaction builder, fee selection, local proving
   (desktop only), seed-based recovery, and a human address encoding.
   *Exit:* restore a wallet from a 24-word phrase on a clean machine and recover
   every unspent note.
6. **Adversarial soak.** Parser fuzzing, proof spam, nullifier races, reorgs across
   anchors, and withheld-data tests.
   *Exit:* 30 consecutive days of a public testnet with no unresolved critical
   finding, and published resource measurements.

## 3. What the testnet must *not* claim

- No security or privacy guarantee while the launch gate is closed.
- No value, no token, no exchange listing, no "mainnet soon".
- No mobile wallet claim until a packed-path proof is measured under 1 GiB with
  production FRI parameters (today it is exactly at the cap or over it).
- No "quantum-proof" language. The honest phrase is "post-quantum-oriented, under
  stated assumptions".

## 4. Effort estimate

For a small team (2-4 engineers) after the proof milestone passes:

| Phase | Duration | Blocking dependency |
|---|---|---|
| Wire format + persistent state | 6-10 weeks | none |
| Miner + PoW + difficulty | 4-6 weeks | wire format |
| P2P + mempool | 8-12 weeks | wire format |
| Wallet send/receive/recovery | 8-12 weeks | wire format, proving |
| Soak + hardening | 12+ weeks | all of the above |

That is 9-15 months of focused work, which is why the roadmap says 12-24 months.
None of it is research-risk work; it is engineering that has been done before by
other projects. The research risk is concentrated in the proof milestone and the
recipient-privacy construction, not in the node.

## 5. First testnet parameters (provisional, not consensus)

| Parameter | Provisional value | Why |
|---|---|---|
| Block interval | 120 s | matches the draft; slow enough to iterate |
| Chain ID | a fixed testnet constant, separate from mainnet | prevents cross-network replay |
| Per-block item caps | 16 transfers / 16 outputs | matches the current statement codec |
| Block payload cap | 1 MiB | forces the proof-size question early |
| Proof profile | pinned test profile, clearly labelled | never claim soundness |
| Genesis | reproducible build from a published script | auditability |
| Faucet | none; mining only | no privileged issuance |

## 6. Exit criteria for calling it a testnet

1. Three independent operators run nodes from a clean checkout.
2. A documented genesis and block 1 reproduced by all three.
3. A wallet restored from a phrase recovers its notes.
4. A 30-day soak with a published incident log.
5. Every resource claim in `MEASUREMENTS.md` re-measured on testnet hardware.
6. The launch gate is still closed, and `MAINNET-SWITCHOVER.md` preconditions are
   listed as open.

Until then the honest description is "research library with component proofs".
