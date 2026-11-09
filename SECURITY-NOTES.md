# Security notes — audit remediation (2026-11-08)

Each entry records a defect found in the 2026-11-08 workspace audit, its impact,
the fix, and the regression test that now covers it. Severities are pragmatic,
not CVSS scores.

---

## S-1 (Critical, remote DoS) — a hostile output could permanently stop a wallet scan

**Impact.** Anyone who knows a victim's public address can encapsulate to the
victim's viewing key and therefore knows the KEM shared secret. They could craft a
wire-canonical output that decrypts correctly for the victim but does not open to
its published commitment (or opens to a non-canonical plaintext such as
`value = 0`). The recovery path raised `NoteRecoveryError`, the scan loop had no
per-output containment, and `WalletScanCursorV1` only advances on a fully
successful chunk. The result: the victim's wallet could **never** advance past
that output, permanently and remotely.

**Fix.** `radix_core/wallet.py`:
- `_recover_scan_snapshots` treats an authenticated-but-inconsistent output as a
  non-match (`continue`) instead of aborting the chunk.
- `_recover_note_from_snapshot_v1` treats `NotePlaintextError` like an AEAD
  failure (non-match).
- Infrastructure faults (`CryptoBackendError`, `EntropyError`, …) still abort, so
  a real backend failure is not silently hidden.
- `providers.py` gains `NotePlaintextError` for "authenticated but not a
  canonical note plaintext", distinct from a backend fault.

**Regression tests.** `tests/test_wallet_scan_containment.py` (5 tests): hostile
output before and after an honest note, the non-canonical-plaintext variant,
cursor advancement, and the single-output API still reporting the inconsistency.

**Residual risk.** A hostile output still costs one KEM decapsulation per scan;
scan CPU remains a griefing surface (unauthenticated scanning has no free
filter). That is a performance concern, not a liveness break.

---

## S-2 (High) — the default nonce registry permanently broke note creation

**Impact.** `AeadNonceRegistry` defaulted to `max_entries=100_000` and never
evicts. After 100k outputs in one process, every note creation using the default
registry raised `NonceRegistryFullError` forever; random nonces could not help.

**Fix.** Default is now `None` (unbounded). A caller that wants a bound must ask
for it explicitly. Note keys are already unique per commitment, so the registry
is defence in depth rather than the primary separation mechanism.

**Regression test.** `tests/test_audit_regressions.py::test_nonce_registry_default_is_unbounded`.

---

## S-3 (High) — `append_many` could consume an unbounded iterable

**Impact.** `OutputTree.append_many` materialised `tuple(leaves)` before checking
capacity, so a streaming or hostile caller could exhaust memory before the
capacity rule ran.

**Fix.** It now consumes at most `min(capacity, limit) + 1` items, validates each
digest as it goes, and remains atomic (no partial append). `apply_block` passes
the preflighted `output_count` as the limit.

**Regression tests.** `tests/test_audit_regressions.py` (three tests: unbounded
generator, stream longer than the limit, exact-limit acceptance).

---

## S-4 (High) — output creation accepted non-canonical ML-KEM viewing keys

**Impact.** `create_note_output_v1` checked only the 1,184-byte length, while
`wire.parse_address` validated the canonical coefficient encoding. A typo'd or
copied address could therefore produce a permanently unspendable output, and
acceptance depended on which provider was injected.

**Fix.** `_validate_note_output_request` now calls
`validate_mlkem768_public_key` before any entropy or KEM work.

**Regression test.** `tests/test_audit_regressions.py::test_output_creation_rejects_a_noncanonical_viewing_key`.

---

## S-5 (Medium) — the wallet-seal nonce guard could be bypassed by subclassing

**Impact.** `seal_wallet_keys_v1` used `isinstance(...)` and called the overridable
`reserve`. A subclass reporting `is_persistent` while no-opping `reserve` sealed a
wallet with no nonce history, defeating the mandatory burn guard.

**Fix.** Exact type check plus the unbound `AeadNonceRegistry.reserve(...)`, the
same pattern already used in `providers.encrypt_note_v1`.

**Regression test.** `tests/test_audit_regressions.py::test_wallet_sealing_rejects_a_subclass_that_skips_reservation`.

---

## S-6 (Low) — the subsidy schedule loop was unbounded

**Impact.** `_build_epoch_schedule` looped until the subsidy fell to the tail. A
governance edit to the decay multiplier that floors above the tail would hang
`import radix_core`.

**Fix.** `MAX_PROPOSED_EPOCHS = 100_000` (the real tail epoch is 9,693) with an
explicit `ValueError`.

**Regression test.** `tests/test_audit_regressions.py::test_subsidy_schedule_cannot_hang_on_a_non_decaying_multiplier`.

---

## Not fixed here (tracked in `archive/candidate-a/Radix-Workspace-Review.md`)

- Quadratic block validation / lack of an incremental persistent tree (§3.I1).
- No seed/mnemonic wallet recovery (§3.I3).
- No human address format (§3.I4).
- Nullifier does not commit to the commitment (§3.I12) — a protocol change with
  vector impact, deferred to a versioned relation change.
- Error-taxonomy conflation between "not mine" and "mine but malformed" (§3.I13);
  partially mitigated by S-1's containment but not fully redesigned.
- The Rust FRI configuration is a 2-query test profile (§2.H11). The launch gate
  refuses to open on it, which is the control that matters until a production
  profile is measured.


## What `2^158` means, and what it does not (2026-11-09)

A delta-model sanity check of the two M-SIS instances puts them at roughly `2^158` (the
untagged `A` relation at `k = 4`) and `2^175` (`B_0` at `W = 33`). Two things must not
be inferred from that.

**It is the cost of the assumption, not the security of the scheme.** The soundness
argument extracts a witness from four transcripts by rewinding, in the random-oracle
model. A forger's advantage crosses that reduction with a polynomial loss, so the
scheme's bit-security is strictly less than the assumption's cost by an amount this
project has not analysed. Quote it as "the M-SIS assumption is about 2^158", never as
"the scheme is 157-bit".

**It is a heuristic, not an estimator run.** The numbers come from inverting the
root-Hermite `delta` model, not from `lattice-estimator`. They are consistent under
both dimension conventions that were checked, and the binding relation is the untagged
base at `k = 4` either way, but a real estimator run is still the outstanding item.

## The modulus class costs a theorem, not an estimate (2026-11-09)

`q = 4,294,966,337` has `ord_256(q) = 4`, which is what makes the quartic slots fields
and closes both the challenge-difference and slot-constancy problems. Two consequences
worth recording:

- **The lattice is unchanged.** Unrolling `A` in the coefficient basis gives the same
  integer matrix -- same dimension, same determinant, same Gaussian heuristic -- for any
  `q` with the same `log q`, however `X^128 + 1` factorises. The factorisation changes
  how products are computed and what can be proved about the algebra, not the M-SIS /
  M-LWE instance.
- **The hardness *proofs* are stated for `q = 1 mod 2n`.** At `ord_256(q) = 4` the
  published module-LWE hardness results do not directly apply. We hold a conjecture
  where a split modulus would have held a theorem, and that is a confidence cost that
  does not appear in any estimate.

If a published result covers this modulus class, cite it and this paragraph can go. If
not, it stays.


## The discrete Gaussian is now a real sampler (2026-11-09)

The previous sampler rounded a continuous Gaussian. C1 and C2 both held that Lemma A.6
could not be invoked until that changed, and C2 supplied the decisive reason: a
rejection argument compares the sampled distribution to a fixed one, and if Python and
Rust each round a float Gaussian, `libm` disagreement makes them *different*
distributions — so the analysis applies to neither while the cross-language tests appear
to pass.

Both now sample from a **cumulative distribution table stored in one binary file**.
Python reads it at runtime; Rust `include_bytes!`s the same file. There is one
distribution, so drift is impossible rather than merely tested.

- Tables: `radix_core/candidate_b/lattice/tables/gaussian_w{33,29,13}.bin` (83, 78, 52 KB).
- Widths are `W = 25 + rows` for the masks and 13 for `z'`; the sampler **fails loudly**
  on any other width rather than substituting a nearby distribution.
- Entries are 32-bit cumulative values, so the sampling itself is integer-only.
- Truncation at 8 sigma leaves a tail of **2^-49.5**, far below the ~2^-16.8
  statistical distance that motivated the change.

**The mask parameters did not move.** `experiments/mask_calibration.py` reproduces
`T = 1700`, `s = 2665.5`, `beta = 244,992` and `T' = 1072`, `s' = 1673`, `beta' = 96,512`
exactly as before, because the calibration measures response norms at a fixed width and
the sampler changes the *shape* of the mask, not its standard deviation.

A test compares `from_uniform(width, uniform, sign)` across both languages over 420
points — the boundaries, the centre, and 128 spread values. It is exact, not
statistical, because the mapping is a pure function of integers in both.
