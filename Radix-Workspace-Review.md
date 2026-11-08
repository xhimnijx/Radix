# Radix workspace review — holes, improvements, and feasibility

**Review date:** 2026-11-08
**Scope:** `C:\Radix` as found (no version-control baseline; see §4.1)
**Method:** read every design document, read the Python core and the Rust constraint code, re-ran every documented command, re-derived the project's own cost numbers, and added independent measurements (hash throughput, tree/state scaling). Doc claims are cited as claims; measurements are marked **[measured]**; arithmetic on the project's own constants is marked **[derived]**.

---

## 0. Verdict in one page

**What this is.** An unusually disciplined, executable *feasibility dossier* for a post-quantum private-payment L1 — not a node, not a wallet, not a coin. ~3.3k LOC Python (codecs, ML-KEM/AES adapters, wallet primitives, in-memory state machine), ~13.4k LOC Rust (Plonky3 STARK component proofs for one-input transfer sub-relations), and ~58k words of specification, review, and decision logs. It is roughly 3–5 % of the code a working shielded-currency node needs, but a much larger fraction of the *thinking*.

**Does it work?** Partly, and less than the docs claim at this exact commit:

| Check | Result |
|---|---|
| `python -m pytest -q` | **3 failed, 191 passed** — failures are stale static-audit regexes against renamed Rust symbols |
| `python Radix-Serialization-Test-Vectors.py` | passes |
| `python Radix-Gate-1-Reference-Model.py` | passes |
| `python -m examples.wallet_note_demo` | runs; real ML-KEM-768 + AES-256-GCM round trip and Merkle membership succeed |
| `cargo check --locked` (documented toolchain, MSVC) | **fails**: `link.exe` not found (no VS Build Tools installed) |
| `cargo +stable-x86_64-pc-windows-gnu check --locked` | **fails: 14 × E0425 `AES256_KEY_SCHEDULE_BITS_OFFSET` not found — the crate does not compile** |

Three further facts found by auditing the source rather than the docs:

- **The shipped FRI parameters give roughly 4–6 bits of soundness.** Every component prover calls `amount_opening::make_config()`, which calls `FriParameters::new_testing_zk` (`proof_harness/src/amount_opening.rs:210-223`). In the pinned Plonky3 revision that is `log_blowup = 2`, **`num_queries = 2`**, and 1-bit PoW (`fri/src/config.rs`, `new_testing_zk`) — a forgery succeeds on the order of tens of attempts. The `log_blowup=4, num_queries=32` "test profile" described in `proof_harness/README.md:16` belongs to `main.rs`'s separate demo config, not to the provers/verifiers that back every `*-prove`/`*-verify` CLI command. No numeric claim is made in the docs, but this is a *configuration* defect, not a disclosed limitation: a production config must exist and the testing one must be `#[cfg(test)]`-gated.
- **There is one verified, remotely exploitable liveness bug in the wallet.** Anyone who knows a victim's *public address* can permanently stop that wallet from ever syncing again (§3.I7). It is a small, contained fix, but it is the kind of defect that must be closed before any testnet touches real users.
- **The half-landed key-schedule refactor is not merely a missing constant.** The overlay/tail split (`depth64_path_opening.rs:111-118`) reserves 1,152 bits overlaid on the input-KDF source bank plus a 768-bit tail, but all 14 call sites address one contiguous 1,920-bit span. No single offset makes that correct: anchored at the tail it overwrites the AES stage columns; anchored at the source bank it overwrites the 32-byte input KDF key and the AEAD nonce/ciphertext witness. The fix requires an accessor `key_schedule_bit(i) = i < 1152 ? row[SRC+i] : row[TAIL+i-1152]` plus a disjointness test over every column slice — not a one-line constant.

The Rust edit at 12:30 on 2026-11-06 (the last source edit in the tree) half-landed that trace-width optimisation and left 14 dangling references; the docs were written 1–9 minutes earlier and describe a compiling tree. **The proof system, i.e. the entire novel part, currently does not build, and the Python suite that would have caught the drift is itself stale.** That is the single most urgent fact about this workspace.

**The idea itself.** Candidate A (global depth-64 hash tree + transparent STARK + ML-KEM/AES notes) is *internally coherent* and honestly specified. It is **not** currently feasible as a usable cryptocurrency, for reasons that are structural rather than a matter of more engineering:

1. **Memory:** the best *measured* profile that covers only the **input half** of one transfer needs **9.5 GiB** peak RSS — 2.4× the project's own 4 GiB laptop budget and 9.5× its phone budget. A complete transfer adds output KEM/AEAD on top; the project's own static estimate for adding just the GCM tag is a **8.8 GiB** workspace floor.
2. **Throughput:** measured component proofs are 175–327 kB. Against the project's own 2 MB block-payload cap that is **≤ 6 transfers per block ≈ 0.05 tx/s ≈ 4.3k tx/day**. To reach the storage model's assumed 100 spends + 100 outputs per block you need **33 MB blocks**, 16× the cap, which blows both the 1 TB pruned-node target and the 15-year archive estimate by roughly an order of magnitude.
3. **Privacy:** recipient key privacy is unsolved by design (an observer holding a candidate viewing key can test ciphertexts), and there is no proof of key possession, so outputs can be provably unspendable.
4. **Security:** no soundness, zero-knowledge, or QROM number exists for any profile; the only proving path is a monolithic AIR with `#[ignore]`d tests and a resource preflight that is *designed to fail closed*, so end-to-end transaction proving has never run.

**What it would take.** A working non-value private testnet is a 3–9 month solo effort *if* the proof side is deliberately narrowed (desktop-only proving, one-in/one-out, no recipient privacy claim). A credible private currency is the roadmap's own 2–4+ years with a funded team, and — critically — **the current all-in-one AIR should not be carried forward**; the cost model has to be re-based on a different circuit architecture (see §5.3). A value-bearing mainnet is not supportable on current evidence and should stay off the table.

---

## 1. What is actually in the workspace

| Area | Size | What it is |
|---|---|---|
| `radix_core/` | 3.3k LOC, 15 modules | Strict LE codecs + `Frame`/`Bytes`/`Vec`; SHAKE256 domain-separated hashes; real `cryptography==50.0.2` ML-KEM-768 + AES-256-GCM adapters; Scrypt wallet file; process-local + SQLite nonce registry; sparse depth-64 tree; anchor and balance rules; atomic in-memory `apply_block`; wallet keygen/note create/recover/scan with authenticated-path scanning; pruned-storage arithmetic model |
| `tests/` | 194 tests, 19 files | Codec/adversarial parsing, KEM/AEAD vectors, wallet flows, Merkle, state atomicity, storage model, plus 16 *static source-audit* tests that grep the Rust source |
| `proof_harness/` | 13.4k LOC Rust | Plonky3 @ pinned `fe5e46d`; nine component profiles (`RDXZAM01`, `RDXZSK01`, `RDXZOW01`, `RDXBND01`, `RDXZNC01`, `RDXZNF01`, `RDXZTN01`, `RDXZ2P01`, `RDXZ64P1`) and six statement-bound compositions (`RDXT/RDXS/RDXI/RDXJ/RDXK/RDXL`) |
| `*.md` | 58.5k words | Charter, protocol draft, Gate A crypto review, feasibility log, roadmap, proof scope, delegated-proving research, MPC design, Akita compatibility note |
| `proof_harness/target/` | **4.07 GB** | build artifacts (98.5 % of the workspace) |
| `_audit_probe.py` | stray | leftover from a prior audit session ("temporary; deleted at end") |

**Genuinely strong, and worth saying before the criticism:** the writing distinguishes candidate hypotheses from facts; every headline number carries its assumption; the state machine snapshots caller data before verifier callbacks and refuses to invent an accepting stub; the codecs are genuinely canonical and rejection-tested; and the decision log records *why* fork context, memo-length leakage, and module-layout choices were made. Most crypto projects at this stage have none of that. The failure mode here is not dishonesty — it is scope.

---

## 2. Blocking cryptographic / design holes

### H1. The flagship transaction profile cannot execute, by construction
`ensure_rdxl_process_budget()` compares a computed randomized-matrix + LDE payload against **`min(desktop 4 GiB, mobile 1 GiB) = 1 GiB`** and returns `ResourceBudgetExceeded` whenever it is larger (`proof_harness/src/depth64_path_opening.rs:237-254`). The current estimate is **4,745,134,080 B = 4.42 GiB** (`:5496`), so every RDXL prove call fails before allocating anything. A Rust unit test asserts that failure (`:5504-5511`), and all seven proof tests are `#[ignore]`d. Consequences:
- No end-to-end transaction proof has ever been produced, so every statement about "proving time" and "mobile fit" is an estimate, not a measurement.
- The project's headline "feasibility" number is a *preflight that always says no*; it can never turn green without a design change, which the docs treat as a deferred benchmark rather than a closed gate.
- Because the guard uses the **mobile** cap for desktops too, even a profile that would comfortably fit a workstation is refused. There is no runtime policy switch, so "desktop proving" is not merely unmeasured — it is disabled.

### H2. The measured cost already falsifies the device budget, before ML-KEM
Measured peaks, from the project's own runs [as reported, unsampled/exploratory]:

| Profile | Scope | Envelope | Prove | Verify | Peak WS |
|---|---|---:|---:|---:|---:|
| `RDXZ64P1` | path only | 175 kB | 15.5–44.4 s | 25 ms | — |
| `RDXS64P1` | path + source leaf | 229 kB | 25.5 s | 32 ms | 5.74 GiB |
| `RDXI64P1` | + note opening | 293 kB | 44.8 s | 70 ms | 7.91 GiB |
| `RDXJ64P1` | + spend key + owner | 327 kB | 41.8 s | 46 ms | **9.52 GiB** |
| `RDXK64P1` | + nullifier | 328 kB | 37.7 s | 71 ms | — |

`RDXJ64P1` is **input-side only** and already exceeds the 4 GiB laptop gate by 2.4×. The complete relation must add output-leaf hashing, output KDF/AES, and ML-KEM on both sides. The docs project +364 active rows and a 16,384-row domain just for the GCM tag ⇒ **7.59 GB LDE, 9.49 GB coexistence floor**. ML-KEM has *no* estimate at all.

**Why ML-KEM in-circuit is worse than "just expensive".** FIPS 203 encapsulation requires regenerating `Â = SampleNTT(ρ)` by **rejection sampling** from a SHAKE XOF: the number of XOF bytes consumed is data-dependent, and the 12-bit candidates must be compacted into coefficient slots. A fixed-row AIR cannot express data-dependent consumption without either (a) an unbounded/recursive treatment, (b) witnessing the count and proving a compaction/permutation relation (lookups or a sorting network), or (c) grinding the sender's encapsulation randomness until it fits a fixed bound and accepting a small proving-failure rate. Add 3×3 polynomial NTTs mod 3329, `Compress_d` rounding, and the fact that `ρ` is *private* (so `Â` cannot be precomputed by the verifier), and you have a primitive that is structurally hostile to a single monolithic AIR — plausibly 5–50× the current trace. The docs' phrasing ("may make transactions too slow") understates this: **the chosen proof architecture and the chosen KEM are a poor fit, not merely an expensive pairing.**

### H3. Proof size versus block cap fixes throughput at ~0.05 tx/s
[derived] With a ≥327 kB proof per transfer and the project's own 2,000,000-byte canonical block payload:

- 2,000,000 ÷ 327,502 ≈ **6 transfers/block** (ignoring headers, framing, and the larger complete-tx proof).
- At 120 s blocks: **0.05 tx/s ≈ 4,320 tx/day**.
- The storage model simultaneously assumes **100 spends + 100 outputs per block**. That implies 100 × 327 kB ≈ **32.8 MB** per block — 16× the payload cap — i.e. 23.6 GB/day, 8.6 TB/year, ≈129 TB archive over 15 years versus the 20.9 TB the model reports.
- The 30-day retained window then holds 21,600 blocks × 32.8 MB ≈ **0.7 TB at 720 blocks/day** (≈1.4 TB at the storage model's own 1,440/day) — approaching or exceeding the 1 TB pruned-node target before indexes.
- So the two arms of the design are mutually exclusive: **either keep the 2 MB cap and get 0.05 tx/s, or keep 100 tx/block and lose both storage targets.** The protocol draft notes the caps' "joint feasibility is not established"; it should say *infeasible by 10–30×* on measured sizes.
- The same ceiling feeds the security budget: at ~4.3k tx/day, fee revenue cannot plausibly secure a PoW chain at a meaningful market cap, and tail issuance is only ~0.17 %/yr of supply.

### H4. The biggest untaken simplification: the circuit probably does not need KEM or AEAD
This is the finding I would most want the authors to examine, because it changes the whole cost picture and is absent from every document.

The relation currently proves, per output, that `ct_kem` is a real ML-KEM encapsulation and that `C` is a real AES-GCM ciphertext over the committed plaintext. Ask what safety property that buys:

- **No inflation / no double spend:** unrelated. Supply safety comes from the proven commitment opening (`cm` opens to `owner, v, rho, r`), integer conservation, and consensus uniqueness of `cm`/`nf`. None of that touches KEM or AEAD.
- **Recipient detection:** the recipient decapsulates `ct_kem`, derives `p = H(pk_s, K)`, decrypts `C`, recomputes `cm`, and rejects the output if it does not match. So any inconsistency between ciphertext and commitment is **already caught by the party that matters**, at scan time.
- **Tamper-resistance:** `leaf = H(cm, ct_kem, nonce, C)` is committed in the tree, so flipping any byte of `C` invalidates membership.
- **Burn prevention:** a malicious sender can already burn value by paying a valid `pk_v` whose secret they discard. Proving encapsulation does not prevent burn.

So the in-circuit KEM + GCM constraints appear to buy only *third-party auditability of the ciphertext*, which no consensus rule consumes. Dropping them would remove the input KDF, output KDF, both AES key schedules and 18 CTR blocks — the 289 output witness columns, the 1,920 key-schedule bits and the AES banks that dominate the 14,477-column width. A realistic estimate is a **30–50 % width reduction and a larger time reduction**, which is the difference between "cannot fit a laptop" and "might fit a laptop".

Two caveats that make this a *research task*, not a patch: (i) it needs a two-page soundness note and independent review, because "the recipient checks it" assumes the recipient's check is part of the security argument rather than an implementation detail; (ii) it must be a **versioned relation change** with the burn/griefing properties explicitly documented, not a silent optimisation. But if it holds, the project's central "proof cost may be prohibitive" blocker is substantially smaller than stated — and if it does not hold, the docs should say precisely which property forces the constraints. Either way the current documents never ask the question.

### H5. Recipient privacy is unsolved, and it is a charter-level failure
`Radix-Gate-1-Feasibility-Log.md:49-57` states it plainly: any observer holding a candidate viewing secret can decapsulate each ciphertext, derive the AEAD key, and test the commitment — ML-KEM IND-CCA is not key privacy. Since charter P-03 makes recipient privacy a target property, Candidate A as specified **cannot satisfy its own product requirement**. The log's stop condition is correctly recorded; what is missing is a decision: commission a PQ stealth-address design (the draft cites eprint 2025/112), switch to a candidate where discovery is key-private by construction, or formally narrow the claim. Until then, calling the design "private by default" is not supportable, and every downstream estimate (output size, scan cost) may change when the discovery scheme changes.

### H6. No proof of possession ⇒ provably unspendable outputs are legal
The relation accepts arbitrary 64-byte `pk_s` and only checks that `pk_v` is a canonical encoding. A payer (or a buggy wallet, or a malicious address provider) can therefore create a perfectly valid output that nobody can ever spend, and the reference wallet only warns. The docs list this as P1 "sender safety"; it is really a **consensus-visible correctness property** (a note that can never be spent is indistinguishable on-chain from one that can), and it interacts with H4: if in-circuit KEM were dropped, the same class of unspendability would be undetectable even in principle.

### H7. Maturity, anonymity set, and timing are coupled to the throughput ceiling
The 60-block anchor minimum imposes a **2-hour wait** on every spend (1 hour at the storage model's 60 s blocks). Combined with H3's 4.3k tx/day, the spendable anonymity set at the anchor is a few hundred to a few thousand notes, all of which are *recent* — so timing correlation is unusually powerful. The docs admit "a small active note set can still deanonymize" but never connect it to the block-cap arithmetic. There is also **no maximum anchor age**: `anchor_ok()` walks the parent chain from tip to `anchor_height` (`radix_core/rules.py:94-107`), so a spend anchored 4 million blocks back costs 4 million dict lookups *per transfer*, and pruned nodes must retain every historical header/root to serve it. Either bound the anchor window (e.g. ≤ 10⁴ blocks) or make ancestry resolution indexed — and note that the storage model's `anchor_root_history_blocks = 60` quietly assumes the bound that the consensus rule does not impose.

### H8. No security statement exists — and "ZK" is aspirational
There is no soundness error, no extraction argument, no QROM analysis, no quantified ZK claim, and no parameter sheet. The component profiles use `TwoAdicFriPcs` (non-hiding), while only the amount demo uses `HidingFriPcs`, so the profiles that touch secrets are **not** the hiding configuration. And the prover configuration actually shipped is the 2-query test stub described above, nowhere near the project's stated 128-bit target. That is acceptable for a constraint-debugging prototype, but it means every sentence containing "zero-knowledge" must be read as "witness-hiding interface, unproven", and the harness must not be able to emit a "verified" proof that means anything about security.

### H9. Issuance is specified but not provable, and genesis is undefined
`R_mintA` has no circuit, no witness layout, no serialization, and no fee-accumulator width (`Radix-Protocol-Draft.md:205`). The reference `apply_block` takes `scheduled_subsidy` as a caller-supplied integer and trusts the injected verifier to check the sum. Genesis and migration have no relation at all, so the induction "every leaf came from a verified mint or transfer" starts from an unproved base case. Supply integrity — the one property a currency cannot get wrong — is therefore the least implemented part.

### H10. Anchor/wire/state gaps that would be consensus bugs
- `TransactionStatementV1` has **no `tx_version` field**; the codec hardcodes version 1 (`radix_core/wire.py:170`). The stated crypto-agility goal is not representable in the object model.
- There is **no block wire format** at all — no `serialize_block`/`parse_block`/block envelope anywhere. The state machine's caps are local policy on proof/statement byte counts, not a block payload rule, so the 2 MB cap that all the feasibility arithmetic rests on is not enforceable by any code in the repo.
- Nullifier set is a `frozenset` replayed from genesis with no authenticated root, so bootstrap cannot be verified; the docs admit this, but it means the pruned-node model is a storage calculation for a state representation that does not exist.
- No maximum input/output count per *block* is enforced anywhere (only per transaction), so block size in transactions is unbounded except by the local proof-byte policy.

### H11. Soundness/zero-knowledge configuration is a test stub, not a parameter set
Beyond the 2-query FRI profile above: there is no OOD proof-of-work, the RDXL trace replicates every secret witness across all 8,192 rows, and hiding rests on four random codewords. `main.rs:215-216` contains a **non-hiding** `TwoAdicFriPcs`/`MerkleTreeMmcs` config in the same crate; pointing a depth-64 profile at it would publish the spend secret, values, `rho`, and note randomness. Nothing in the type system prevents this, and there is no leakage regression test. Treat "zero-knowledge" everywhere in the docs as an unproven interface contract.

### H12. The proof does not bind the output to any recoverable recipient secret
`output_shared_secret` is a **free witness** (`depth64_path_opening.rs:5299-5304, 4444-4450`); the output owner is a witness bound only through the commitment (`:5361-5369`); the statement's `kem_ciphertext` is used only as KDF input (`:2570-2572`). Nothing asserts `ss = Decaps(dk, ct)` and nothing ties `ss` to `owner` or to the recipient's key. So a prover can commit an output whose owner it chooses, whose ciphertext it encrypts under a key nobody holds, and the proof still verifies. The same holds on the input side (`:4043-4057`). This is the formal restatement of §2.H5/H6: at the proof level the design does not establish that a recipient can ever spend an output.

### H13. Statement semantics are byte-bound but not checked
`chain_id` and `anchor_height` are parsed (`transaction_statement.rs:43-45, 105-106`) and bound as public values, but no constraint or post-verification check compares them to a chain ID, a root-at-height, or a freshness window. `verify_..._output_balance` (`depth64_path_opening.rs:5442-5473`) returns the statement without a semantic check, so cross-chain replay and stale-anchor acceptance are entirely the caller's responsibility — and no API forces the caller to do it.

### H14. Ciphertext bytes that are committed but unconstrained
Ciphertext bytes 140–155 (the GCM tag) are written into the trace (`:4390-4395`) and read by nothing; validity gates are `< 140` (`:2388, 2396`). No GHASH relation exists. So the committed field includes 16 bytes the proof says nothing about — and the type names still say AES-GCM. Either implement GHASH+tag compare, or shrink the committed ciphertext to 140 bytes and call the relation AES-256-CTR.

### H15. Smaller but real correctness inconsistencies
- Zero-value notes **parse and serialize** (`transaction_statement.rs:120`) but **cannot be proven** (nonzero-popcount constraint at `:2698-2707`; both provers hard-reject zero). The rule should be in the codec.
- Public values are compared as `lo + hi*256` without byte-range constraints (`:1013-1014, 1690-1691, 2826-2828`). Sound only because the prover/verifier re-derive every byte from canonical statement bytes; any future caller-supplied public vector would be unsound.
- `MAX_PROOF_SEQUENCE_ELEMENTS = 248_837` (`bounded_postcard.rs:45`) is the sole traversal budget for up to 64 MiB payloads and is hand-derived; a dependency bump silently breaks it in either direction.
- `INPUT_KDF_ACTIVE_OFFSET` has no first/last-row constraint, so a trailing row can enable the stage with arbitrary bytes (currently harmless).

---

## 3. Implementation holes

### I1. Block validation is O(total leaves) — replay is quadratic, measured
`OutputTree.validate_integrity()` recomputes every sparse level with SHAKE, and it is called from `append_many`, from `LedgerState.__init__`, and again at the start of `apply_block`; `clone()` copies every level map, twice per block (`state.py:303`, `:410`). **[measured]** on this machine: `SHAKE256` framed hash = 9.6 µs; appending one leaf after N leaves costs ~10–12 µs per existing leaf; `LedgerState(tree)` costs 2.5 ms at 256 leaves, 9.0 ms at 1,024, 33.5 ms at 4,096. Extrapolated to one year of the model's own 100-output blocks (26.3M leaves), **one block transition costs ~5 minutes, and replaying the year costs years.** The reference state machine is a correctness oracle, not a node; but nothing in the tree records that the design is unimplementable beyond toy size, and no incremental/persistent tree exists even as a sketch.

### I2. The node half of the product is entirely absent
No persistence, no database, no networking, no mempool, no PoW, no chainwork/fork choice, no header chain, no genesis, no CLI node, no RPC, no miner, no seed/mnemonic derivation, no transaction builder, no fee estimation, no sync. The roadmap acknowledges this; what is missing from the repo is a *plan* for how a 3.3k-LOC in-memory model becomes a node without a rewrite — the O(n) tree is the keystone of that gap.

### I3. Wallet recovery contradicts the charter
There is no mnemonic/seed and no deterministic KDF from a phrase to `s` and to the ML-KEM keypair, so a wallet cannot be restored on a new device from a backup. `wallet_keystore.py` writes an encrypted blob (Scrypt + AES-GCM) with no anti-rollback and no derivation. Charter P-02 and the roadmap's Ownership section both promise "understandable backups, restore-on-new-device". This is a product-blocking hole, not a nice-to-have, and the ML-KEM key has no standard BIP-39-style derivation to lean on.

### I4. There is no usable address
An address is 1,318 bytes; the demo prints it as 1,760 Base64 characters, explicitly "not a defined textual address format". No checksum, no human encoding, no QR strategy, no subaddresses, no rotation. For a payment system this is a first-order UX blocker that also compounds H5 (a static, 1.3 kB, reusable viewing key is the worst case for linkability).

### I5. Resource bounds are local policy, not protocol
`max_total_proof_bytes`, `max_total_statement_bytes`, `max_transfers`, `aggregate_fee_limit` are all caller-supplied. The docs are honest about this, but it means the "block cap" used in every storage and throughput calculation has **no implementation anywhere**, so the numbers are unfalsifiable by test.

### I6. Reference implementations of the wrong layer
`transaction_relation.py` is a *host oracle* that recomputes hashes and checks membership — useful for cross-checking a Rust circuit, but it is not connected to `apply_block`, and the wallet scan helpers deliberately accept caller-asserted positions in legacy mode. The result is three partially-overlapping "sources of truth" (Python codec, Python oracle, Rust AIR) with no differential test harness tying them together.

### I7. **[exploitable]** Anyone can permanently brick a victim's wallet scan
`_recover_note_from_snapshot_v1` (`wallet.py:442-449`) catches only `AeadAuthenticationError`; a note that **authenticates but fails commitment recomputation** raises `NoteRecoveryError`, and `_recover_scan_snapshots` (`:550-562`) has no per-output containment — so the exception aborts the whole chunk, the cursor is not advanced, and the next attempt fails identically. Because an attacker only needs the victim's *public* address to encapsulate to their viewing key (and therefore knows `ss`), they can craft exactly such an output:

```
cm  = note_commitment(note_owner(victim_pk_s, ss), 999, rho, r)   # wrong value
C   = AES-GCM(KDF(ss, ct, cm), plaintext for value 5, AAD(cm, ct))
```

It is wire-canonical, decrypts for the victim, then fails the commitment check — and the victim's wallet can never sync past it. Verified end-to-end with the real ML-KEM-768/AES-GCM adapters; an honest note in the same chunk is recovered and then discarded when the call raises. A second abort primitive exists via `providers.py:432-435`, which turns a canonical-but-invalid plaintext (e.g. `value = 0`) into a `CryptoBackendError`. **This is a one-line-containment fix** (treat authenticated-but-inconsistent outputs as non-matches, never as fatal, and keep per-output errors out of the chunk loop) but it is a genuine remote DoS against every wallet, and it must be fixed before any user-facing build.

### I8. The default nonce registry permanently breaks note creation
`AeadNonceRegistry(max_entries=100_000)` is the process-local default (`providers.py:175`) and it never evicts (`:170-172`). After 100k outputs in one process, every `create_note_output_v1` with `nonce_registry=None` raises `NonceRegistryFullError` forever; new random nonces do not help, and the history is lost on restart anyway. Default to unbounded (the nonce is 96-bit random and the KDF key is already unique per commitment) or require an explicit capacity policy.

### I9. `append_many` materialises an unbounded iterable before checking capacity
`merkle.py:112-117` does `items = tuple(leaves)` *before* `check_append_capacity`, so a streaming caller can OOM or hang the validator. Contrast `encode_vec` (`encoding.py:52-61`), which caps consumption. Fix: consume at most `CAPACITY - leaf_count + 1` items.

### I10. Output creation accepts noncanonical viewing keys
`wallet.py:254-258` validates only the 1,184-byte length, while `wire.py:114` calls `validate_mlkem768_public_key`. So a typo'd or copied address yields an unspendable note, and acceptance depends on which KEM provider is injected. `test_wallet.py:161-163` currently *relies* on the lax path (`b"p"*1184` accepted).

### I11. The mandatory nonce-burn guard can be bypassed by a subclass
`wallet_keystore.py:75` uses `isinstance(...)` and `:91` calls the **overridable** `reserve`; a subclass that reports `is_persistent` and no-ops `reserve` seals a wallet with no nonce history. `providers.py:385-388` does it correctly with an exact type check and an unbound `AeadNonceRegistry.reserve(registry, ...)`. Same defect class the state machine already defends against elsewhere — it should be the codebase-wide pattern.

### I12. The nullifier does not commit to the note commitment
`nf = H(s, K, rho)` (`crypto.py:51-58`) omits `cm`. A sender who reuses one KEM ciphertext and `rho` for two outputs with different `r` creates two distinct, globally-unique commitments that share a nullifier — one of them can never be spent, and a wallet may spend the wrong one. Bind `cm` (or `r`) into the nullifier preimage, and mirror it in the Rust AIR.

### I13. Error taxonomy creates a membership oracle and masks bugs
`None` (AEAD failure) versus an exception (authenticates but wrong commitment) is externally observable (`providers.py:432-435`, `wallet.py:442-449`), which distinguishes "not mine" from "mine but malformed". Separately, `state.py:372-395` catches bare `Exception` around verifier hooks and rewrites the type into a rejection message, so a verifier's own `BlockRejected` or a `MemoryError` is indistinguishable from a bad proof. Introduce a common base class, catch specific faults, and re-raise `BlockRejected` unchanged.

### I14. Assorted correctness/robustness defects
- `monetary.py:19-28` has an unbounded `while schedule[-1] > TAIL:` loop; a governance change to the decay multiplier that floors above the tail hangs `import radix_core`.
- `wallet_keystore.py:161-162, 187-188` get `O_NOFOLLOW` via `getattr(..., 0)`, which is `0` on Windows — symlink protection silently disappears; the file is unlinked by path after a failure (replacement race) and no directory fsync occurs.
- The keystore format is not self-describing: Scrypt `N/r/p` and the 64-byte ML-KEM seed layout are hard-coded with no parameter/format tag inside the authenticated plaintext, so any future parameter change makes old wallets report "password is incorrect".
- Duplicated magic numbers: ciphertext bounds `156..668` appear in `crypto.py:68`, `providers.py:399,421`, `wire.py:21,89`; the statement cap appears as `4096` in `pruned_storage_model.py:21` and `32_385` in `wire.py:29`; the 16-item cap in `wire.py:18` and `state.py:27`.
- `wire.py:11` imports the concrete pyca adapter, so the *codec* cannot be used without `cryptography`; `wallet_keystore.py` likewise binds `AESGCM`/`Scrypt` and the concrete KEM provider instead of protocols. A second backend cannot be dropped in.
- `MAX_SCAN_CHUNK_RAW_FIELD_BYTES` / `MAX_SCAN_CHUNK_AUTH_PATH_BYTES` are exported and asserted but never enforced; `rules.anchor_ok:95-99`'s cycle guard is unreachable (heights strictly decrease).

---

## 4. Test, quality, and process holes

### 4.1 No version control at all
`git status` → *not a git repository*. There is no history, no bisect, no way to see what the last edit broke (it broke the Rust build), no attribution, and no recoverable state. Together with the 4 GB of unversioned build artifacts and a 300 kB single Rust source file, this is the highest-ratio fix available: `git init` + `.gitignore` costs seconds and makes everything else reviewable.

### 4.2 The suite is red at HEAD
3 of 194 tests fail because a refactor renamed `ensure_rdxl_desktop_process_budget → ensure_rdxl_process_budget` and the static-audit tests still grep for the old name. This is a *self-inflicted* failure mode: 16 of the Python tests assert on **the text of Rust source** (`"builder.assert_zero(b.clone()*(b-one.clone()))" in air`), which is brittle by construction, duplicates what the Rust tests should assert, and rots silently whenever formatting or naming changes. Better: keep the *properties* in Rust (compile a mutated witness and expect AIR failure) and reserve Python for byte-level vector conformance.

### 4.3 The only real proving path never runs
Seven proof tests are `#[ignore]`d for memory reasons, and the RDXL entry point is fail-closed. So "the STARK works" rests on earlier, narrower profiles executed on a machine that is no longer available (the current one can't link MSVC or build GNU). There is no CI, no container, no recorded toolchain, and no `rust-toolchain.toml`. A reviewer cannot reproduce a single proof today.

### 4.4 No property-based or coverage-guided testing
The docs correctly say "the deterministic random-byte/mutation sample is not coverage-guided fuzzing". There is no `hypothesis`, no `cargo-fuzz`, no AFL target, no differential parser, no model checker, and no conformance vectors consumable by a second implementation. For a protocol whose entire safety story is "the parser and the circuit agree", this is the biggest *test-strategy* hole.

Worse, one adversarial test is **vacuous**: `tests/test_adversarial_parsing.py:26-48` asserts a round-trip only *when* parsing succeeds and never asserts a minimum success count, so a parser that rejects every input passes. It also mutates only the first 128 bytes, the midpoint and the last byte, skipping nested field-length prefixes — precisely where canonicality bugs live. Other tests assert implementation details rather than behaviour (`test_state.py:92-111` requires exactly one `append_many` call; `test_state.py:623-652` fails if `serialize_statement_v1` runs at all; `test_wallet.py:415-439` monkeypatches a private snapshot helper; `test_merkle.py:47-48,135` mutate `_nodes` directly). Only `output_leaf` has a cross-language vector — `note_commitment`, `note_owner`, `nullifier` and `note_kdf` are never checked against the Rust AIR's bytes, so a second implementer *will* drift silently.

### 4.5 No benchmarks as gates
All timing/memory figures live in prose with dates and "exploratory, single-run" caveats. Nothing fails when a metric regresses. The project defines pre-benchmark thresholds in the roadmap (§6) but has no harness that computes them.

### 4.6 Documentation drift and internal inconsistencies
| Claim | Where | Reality |
|---|---|---|
| RDXL LDE = 3.598 GiB, coexistence = 4.497 GiB | `README.md:50` | Actual constants: **3.535 GiB** and **4.419 GiB** (`depth64_path_opening.rs:5495-5496`) |
| Tail adds 26,280 RAD/year | `Radix-Protocol-Draft.md:155` | 0.1 × 31,557,600/120 = **26,298 RAD/year** (365.25-day basis used elsewhere) |
| "cargo check passes" | proof scope, multiple dates | **Crate does not compile** (14 errors) |
| "154 passed" / "107 passed" | scope doc / feasibility log | 194 collected, 191 pass |
| FRI "test profile: log_blowup=4 … num_queries=32" | `proof_harness/README.md:16` | The component provers use `new_testing_zk` = **blowup 2, 2 queries, 1-bit PoW**; the quoted values belong to `main.rs`'s demo config |
| 2 MB cap + 100/100 per block | storage model | Mutually exclusive by ~16× given measured proof sizes |
| 380 GB pruned node | protocol draft | Only reachable at ~6 tx/block; at 100 tx/block it is ≈1.4 TB in the window alone |

The deeper problem is **format**: the docs are an append-only log of dated claims, so a reader cannot tell which statement is current. Reading `README.md`, then `TRANSACTION-PROOF-PROTOTYPE-SCOPE.md`, then `depth64_path_opening.rs` gives three different descriptions of what RDXL proves — the last one being true.

### 4.7 Project-level gaps
No `LICENSE` (so it is legally "all rights reserved" — nobody may reuse or contribute safely), no `CONTRIBUTING`, no `SECURITY.md`, no `CITATION`, no changelog, no release process, no SBOM, no dependency hashing for Python (`cryptography==50.0.2` unpinned by hash), no `rust-toolchain.toml`, no CI, no container, no reproducible-build recipe. The name "Radix" collides with an existing L1 (Radix DLT / XRD) and with the radix tree/sort ecosystem; the docs flag it, but the directory, package name, and module prefix (`radix_core`) all bake it in, making the eventual rename a global refactor.

---

## 5. Improvements, ranked by leverage

### 5.1 Do this week (hours, no design decisions)
1. **`git init`, `.gitignore` (`target/`, `__pycache__/`, `.pytest_cache/`, `*.egg-info/`, `.dsh-pdf-reader/`), first commit.** Everything below becomes reviewable.
2. **Fix the wallet-scan containment bug (I7)** and add hostile-output regression tests. This is the only *exploitable* defect in the repo.
3. **Fix the Rust build**: add the `key_schedule_bit()` accessor (overlay vs tail) and a column-disjointness test; get `cargo check` + `cargo test --no-run` green on a documented toolchain.
4. **Repair the stale static-audit tests** and convert the fragile source-grep assertions into Rust-side mutated-witness tests. Note that `tests/test_proof_decoder_static_audit.py:117` also expects the mangled token `PCS_LOG_BLOWUPasu32`, so it would still fail after the rename.
5. **Add `LICENSE`** (Apache-2.0 or MIT OR Apache-2.0), `rust-toolchain.toml`, and a minimal CI job (Python 3.11–3.14 matrix + `cargo check` + `pytest`).
6. **Delete `_audit_probe.py`**, the 4 GB of `target/`, and stale `.pyc`s.
7. **Write one `STATUS.md`** (≤1 page): what compiles, what passes, what is measured, what is estimated, what is not implemented. Make it the single source of truth and date it. Everything else becomes a historical log.

### 5.2 Do this month (small decisions, high leverage)
8. **Write the H4 soundness note**: argue precisely which safety property requires in-circuit ML-KEM/AEAD. If none does, specify a versioned relation without them and re-measure. This is the single largest cost lever in the project.
9. **Separate the FRI configurations**: a `production_config()` (≥100 queries, blowup ≥3, PoW ≥16) and a `#[cfg(test)]` testing config, so a release binary cannot produce a 6-bit-soundness proof. Also type-separate the hiding and non-hiding PCS configs (H11).
10. **Derive the resource budget bottom-up, before coding further**: pick a target (desktop 1-in/1-out proof ≤ 4 GiB, ≤ 120 s; mobile ≤ 1 GiB, ≤ 600 s), then allocate it across sub-relations, and record which sub-relation must shrink by what factor. The existing "row-domain reduction threshold" analysis (`TRANSACTION-PROOF-PROTOTYPE-SCOPE.md:98-110`) is exactly the right tool — extend it to the whole relation and make it a gate.
11. **Bound the anchor window** (e.g. 60 ≤ h−a ≤ 10,000) and index ancestry; make the storage model and the consensus rule agree.
12. **Add hypothesis-based property tests** for `Frame`/`Bytes`/`Vec`/statement round-trips and for `apply_block` invariants (no state change on rejection, uniqueness monotonicity, balance non-negativity), plus a differential fuzzer Rust-vs-Python for the 1-in/1-out codec. Replace the vacuous adversarial test with one that asserts a minimum acceptance rate.
13. **Replace the O(n) tree** with an incremental, persisted store (SQLite or a flat file with a node cache) so replay is O(changed nodes) per block; measure a 10⁵-leaf replay.
14. **Close the remaining small correctness holes**: canonical KEM-key validation in output creation (I10), `cm` in the nullifier preimage (I12), unbounded/streaming `append_many` (I9), a sane default nonce registry (I8), and exact-type/unbound-call in the keystore (I11).

### 5.3 Do this quarter (architecture decisions that decide feasibility)
15. **Re-cost three candidate circuit architectures** and pick one *with numbers*: (a) current monolithic SHAKE AIR, (b) split AIRs + recursive aggregation, (c) a zkVM with a Keccak/ML-KEM-friendly precompile and an optionally recursive wrapper. Only (b)/(c) plausibly reach phone-scale proving; (c) is by far the fastest route to a *correct* complete relation at the cost of proof size and a mature-ish dependency.
16. **Evaluate an algebraic in-circuit hash** (Poseidon2/Monolith) for tree/commitment/nullifier, as already prototyped for the amount demo. The arithmetic is decisive: a 2,937-column Keccak permutation versus a few hundred columns for a 16-wide Poseidon2 permutation is a ~10–20× width reduction, i.e. exactly the factor needed to move the LDE from 3.6 GiB to a few hundred MB. This changes the consensus hash and requires re-vectorisation — a versioned decision, not a patch — but without something like it, mobile self-custody is arithmetically out of reach.
17. **Decide recipient discovery**: commission a PQ stealth-address review, or adopt a key-private construction, or formally narrow the charter. Do this before optimising output size, because it may change the 1,088-byte payload entirely.
18. **Design the block/transaction wire format** so a block cap is enforceable, then re-run the storage model with that cap and measured proof sizes — and publish the throughput (tx/s) and the fee/security-budget implication alongside it.
19. **Wallet recovery**: define seed derivation for `s` and the ML-KEM keypair (e.g. hash-based KDF from a BIP-39-style entropy, with ML-KEM `KeyGen` made deterministic from a seed per FIPS 203 `d,z`); produce recovery test vectors.
20. **Address encoding**: a human-oriented encoding with checksum (bech32m-style) plus a subaddress/rotation scheme, and a QR budget (≤ 500 bytes target implies a much shorter address, which loops back to item 17).

### 5.4 Park or drop
- **Candidate B** (lattice OOM/LRS) is documented as a comparator and has no instantiation. It is *not* a fallback — but note that its published economics (~30 kB for 2-in/2-out at 2¹⁵ anonymity) are 10× better on the dimension that matters most here. It deserves a *decision*, not an open-ended bookmark: either fund a scoped construction for the global cross-ring tag, or remove it from the critical path.
- **Monetary policy and PoW selection** should stay frozen where they are; they are not the bottleneck and tuning them now creates false progress.
- **The 15-year storage model** should be re-labelled as "arithmetic under unenforced assumptions" until a block codec exists; its current precision (380,375,853,376 bytes) implies a confidence the inputs do not support.

---

## 6. Feasibility

### 6.1 By ambition level

| Ambition | What it means | Time (solo / small team) | Feasible? |
|---|---|---|---|
| **A. Executable spec** | What exists now, plus a green build and a passing suite | 1–2 weeks | **Yes** |
| **B. End-to-end demo** | One real 1-in/1-out shielded transfer: CLI wallet, real STARK proof, single-node toy chain, no networking, desktop-only, no privacy claims beyond the proof | 3–6 months solo | **Yes, with scope discipline** — requires the proof to fit a desktop, which currently it does not (see H2/H4) |
| **C. Private testnet** | P2P node, PoW, mempool, genesis, restart-safe wallet, multi-node, adversarial soak | 12–24 months, team of 3–6 | **Possible**, but only after a circuit-architecture change; no recipient privacy unless discovery is solved |
| **D. Usable private currency** | C + phone-wallet proving + ≥1k tx/s-scale throughput (or an explicit settlement-only thesis) + audits | 2–4+ years, team of 8–15 + external cryptographers | **No on current architecture.** Plausible only with (b)/(c) in §5.3, an algebraic hash, a new discovery scheme, and recursive aggregation. Probability of clearing all gates: low-to-moderate |
| **E. Value-bearing mainnet** | D + independent soundness/ZK/QROM review + consensus audit + legal + distribution | 3–5+ years | **Not supportable on current evidence; keep off the table** |

### 6.2 The arithmetic that decides D

| Metric | Project's assumption | What the code/docs actually imply |
|---|---|---|
| Peak memory, full tx | 4 GiB desktop / 1 GiB mobile | 9.5 GiB measured for input half; 8.8 GiB *static floor* for adding only the GCM tag; ML-KEM unestimated |
| Prove time | 120 s desktop / 600 s mobile | 42–50 s for input-half components on an i7-1185G7; full tx plausibly 5–60 min |
| Verify time | <1 s | 25–71 ms ✅ |
| Proof size | "unknown" | 175–327 kB for components; full tx ≥ 400 kB |
| Throughput | 100 spends + 100 outputs/block | ≤6 tx/block at the 2 MB cap ≈ 0.05 tx/s |
| Archive growth | 20.9 TB / 15 y | ≈129 TB / 15 y at the assumed 100 tx/block |
| Pruned node | <1 TB / 15 y | ≈1.4 TB retained window alone at 100 tx/block |
| Anonymity set | "bounded by valid unspent notes" | hundreds–thousands, with strong timing correlation at 0.05 tx/s |
| Soundness | "no numeric claim" | shipped prover config ≈ **4–6 bits**; a forged proof is cheaper than an honest one |
| Security budget | tail 0.1 RAD/block | 0.17 %/yr of supply + ~4.3k tx/day of fees — thin for PoW at scale |

**The read-through:** verification is cheap and proofs are small enough for a chain; **proving is the wall, and block space is the second wall**. Everything else (networking, consensus, wallet UX) is ordinary engineering by comparison. That is actually good news for planning: the two things that could kill the project are both measurable in the next quarter, on one desktop, without writing a node.

### 6.3 What would have to be true for this to become a real coin
1. A complete 1-in/1-out relation that proves on a 16 GiB desktop in < 2 minutes, with a written soundness/ZK argument and a measured peak < 4 GiB.
2. A proof/block budget that yields ≥ 100 tx/s at the target block interval (recursive aggregation, an algebraic hash, or a much smaller proof), *or* an explicit, honest repositioning as a low-throughput settlement chain.
3. A key-private PQ recipient-discovery scheme with a written privacy game, or a formally narrowed privacy claim.
4. Seed-based recovery, a human address format, and a wallet that proves locally on a phone — all three are first-order product requirements, not polish.
5. An independent cryptographer who will put a number on soundness and a consensus engineer who will reproduce the block transition from genesis.
6. Funding and legal review, neither of which exists today.

If (1) or (2) fails — and on current numbers (1) fails by 2.4× and (2) by ~1,000× versus a payment network — the honest outcome is a **published research result**, not a launch. The documents already say this; the workspace just needs to stop accumulating implementation before those two measurements exist.

### 6.4 Recommended 90-day sequence
- **Weeks 1–2:** git, green build, green suite, LICENSE, `STATUS.md`. (Cheap, unblocks everything.)
- **Weeks 3–6:** H4 soundness note → versioned "lean" relation without KEM/AEAD → measure it (rows, columns, prove time, peak). This single experiment decides whether a desktop demo is reachable.
- **Weeks 5–8:** in parallel, split-AIR + recursion scoping memo, and a Poseidon2 width experiment for the path/commitment relation; pick a direction with numbers.
- **Weeks 9–12:** if the lean relation fits 4 GiB / 120 s, build the end-to-end demo (wallet → prove → `apply_block` → verify) and publish the measurement table. If it does not, write the stop/redesign decision and take it to the charter's kill criteria rather than continuing to add components.

---

## 7. Summary judgements

**Strengths to preserve:** the canonical codec discipline; the honest failure-mode catalogues; the decision logs; the fail-closed state machine; the refusal to populate proof stubs; the explicit non-value posture. These are the project's real assets and they are rarer than the code.

**The three things that are actually wrong:** (1) the workspace is a broken, unversioned snapshot presented as a passing one — the Rust does not compile, the suite is red, and the FRI parameters are a 6-bit test stub; (2) the cost model was built on a circuit architecture that cannot fit its own device budget, and the one simplification that could change that (dropping KEM/AEAD from the circuit) was never analysed; (3) throughput and storage were modelled independently and are mutually inconsistent by an order of magnitude.

**The one thing that is actually dangerous:** anyone who knows a victim's public address can permanently stop that victim's wallet from syncing (§3.I7). It is a small bug with a small fix, but it is the difference between "prototype" and "something a person could safely run".

**Bottom line:** *feasible as research, not yet feasible as a product — and the next decision is a circuit-architecture decision, not a coding decision.* Spend the next quarter proving or killing the lean relation on one desktop; do not write a node, a miner, or a wallet UI until that number exists.
