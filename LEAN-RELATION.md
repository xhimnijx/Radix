# The lean relation - soundness note, cost model, and decision record

**Status:** decision-grade analysis, not a proof. **Revised 2026-11-08** after the
Rust suite finally executed and corrected two inputs.
**Question:** the transaction relation proves in-circuit that each output's ML-KEM
ciphertext is a real encapsulation and that its AES-GCM ciphertext authenticates.
Does any safety property require that? And is the smaller circuit enough?

**Answers:**

1. **No.** Supply integrity, double-spend resistance, recipient detection and tamper
   resistance do not depend on in-circuit KEM or AEAD. The constraints buy third-party
   ciphertext auditability, which no consensus rule consumes.
2. **Removing them is necessary but not sufficient.** Lean cuts 5,500 of 14,173
   columns (39 %), and still predicts 8.5 GiB at production blowup against a 4 GiB
   gate.
3. **A single monolithic AIR cannot meet the phone budget in any configuration we can
   price.** The phone ceiling is about 1,020 columns at 4,096 rows; the smallest
   relation (path-only) is 5,043.

Reproduce: `python -m experiments.lean_relation_sizing`.

---

## Part A - soundness note: which property forces in-circuit KEM/AEAD?

### A1. Supply integrity and double-spend resistance

A note's value is fixed by `cm = H_note-commit(p, U64(v), rho, r)`. The relation
proves, from the spender's witness, that `cm` opens to `(p, v, rho, r)`, that
`p = H_note-owner(pk_s, K)` for the witness `K`, and that
`sum(v_in) = sum(v_out) + fee` holds with bounded limbs. Consensus enforces global
uniqueness of `cm` and `nf = H_nullifier(s, K, rho)`.

None of those steps reads `ct_kem`, the AES key, the nonce, or `C`, beyond
`leaf = H_note-leaf(cm, ct_kem, nonce, C)` being committed. Arbitrary bytes there
change `leaf` but cannot change a value, open `cm` twice, or produce a new `nf`.
**Supply safety is independent of the KEM/AEAD constraints.**

### A2. Recipient detection

The recipient decapsulates `ct_kem`, derives `K_enc`, decrypts `C`, recomputes
`cm' = H_note-commit(p', U64(v'), rho', r')`, and compares with `cm`. Any mismatch
means the output is not credited. Detection is complete **without** the circuit, and
it also catches a ciphertext encapsulated to a key the recipient does not hold.

What the circuit adds is that a *third party* could check consistency without the
recipient's key. No consensus rule consumes that.

### A3. Tamper resistance

`leaf` commits to `(cm, ct_kem, nonce, C)` and membership is proven against it, so
any mutation fails membership. That is why the recipient can trust the bytes they
decrypted.

### A4. Burn resistance - already absent

A payer can burn value by encapsulating to a key whose secret they discard. Proving
encapsulation does not prevent it, because neither the circuit nor consensus can
prove anyone controls `pk_v` (no proof of possession; review section 2.H6).

### A5. What is lost, and what must be written down

| Lost property | Consequence | Mitigation |
|---|---|---|
| Public verifiability that an output is well-formed for *some* key | Auditors cannot check ciphertext/commitment consistency without the recipient's key | Make recipient recomputation normative |
| Public authenticity of the 16-byte GCM tag | A payer can publish a tag that authenticates nothing | **Already true today**: RDXL constrains only bytes 0-139 and leaves 140-155 unconstrained (review 2.H14) |
| A guarantee a note is spendable by someone | Publicly valid outputs may be unspendable | Already true via destroyed keys; document the burn path |

### A6. Obligations before this becomes a versioned relation change

1. Define a **note-usability predicate** and prove: spend soundness needs only `cm`,
   balance and uniqueness; detection completeness for honest senders; detection
   soundness (value/owner are the committed ones).
2. Keep **`cm` globally unique**, so one commitment cannot carry two ciphertexts.
3. Keep the honest-construction obligation in the wallet (encrypt the same values it
   committed to). That is sender correctness, not a consensus rule.
4. Bound the griefing surface: a hostile output costs one decapsulation per scan.

**Conclusion of Part A:** the KEM/AEAD constraints are not required for safety. They
are an auditability feature. Removing them is a legitimate, versioned change provided
A6 is written and reviewed.

---

## Part B - cost model (corrected)

Two inputs in the first version of this note were wrong. Both were corrected only
after the Rust suite could finally run (`STATUS.md`, `MEASUREMENTS.md`):

- **Width is 14,173, not 14,477/15,629.** `cargo run -- rdxl-resource-report`
  printed `8192x14173` after the key-schedule revert. The old figure had never been
  executed because the crate did not compile.
- **The path witness is 1,024 bits, not 8,192.** The current node is the 2,937-column
  Keccak state; the sibling digest is 512 bit-sliced columns. Packing siblings into
  16-bit limbs saves 480 columns, not about 7,800. The earlier "packing is the lever"
  conclusion was therefore wrong and is withdrawn.

| Profile | Width | LDE @blowup 2 | Peak @4x (blowup 3) | Desktop @9.5x | Phone @4x |
|---|---:|---:|---:|---|---|
| R-fat (RDXL64P1 today) | 14,173 | 3.46 GiB | 27.7 GiB | 16x over | 28x over |
| R-lean (no KDF/AEAD) | 8,673 | 1.06 GiB | 8.5 GiB | 5.0x over | 8.5x over |
| R-lean + packed sibling | 8,193 | 1.00 GiB | 8.0 GiB | 4.8x over | 8.0x over |
| R-lean + packed + algebraic hash (counterfactual) | 5,284 | 0.65 GiB | 5.2 GiB | 3.1x over | 5.2x over |
| RDXZ64P1 path-only floor | 5,043 | 0.62 GiB | 4.9 GiB | 2.9x over | 4.9x over |

Peak = LDE x 4.0 (measured single proof). Planning column uses 9.5x (measured
multi-proof test). Production blowup 3 doubles the LDE rows relative to the test
blowup 2.

Width ceilings at production blowup, single-proof 4x:

| Cap | rows=4,096 | rows=2,048 | rows=1,024 |
|---|---:|---:|---:|
| Desktop 4 GiB | 4,092 | 8,188 | 16,380 |
| Phone 1 GiB | 1,020 | 2,044 | 4,092 |

What this says:

- The measured floor (2.49 GiB at blowup 2) fits the desktop gate **only at the test
  blowup**. At production parameters the same circuit is 4.9 GiB.
- Lean removes the largest removable bank (5,500 columns) and still cannot fit
  desktop at production: 8.5 GiB.
- Packing saves 480 columns, about 5 % of lean. It is not the lever.
- The dominant width is **Keccak (2,937) plus the KDF/AEAD banks (5,500) plus the
  bit-sliced note/leaf banks**. Replacing Keccak with a 300-column algebraic
  permutation is the biggest single lever available inside a monolithic AIR - and
  even that lands at 5.2 GiB.
- **Phone is out of reach** for any single-AIR configuration: 1,020 columns at 4,096
  rows is not achievable while proving a note opening plus a leaf hash.

---

## Part C - decision record

**D-M3-1.** In-circuit KEM/AEAD is removed from the *safety* relation and retained
only as an optional, separately versioned auditability extension. Requires the A6
argument and new vectors.

**D-M3-2.** The **monolithic AIR route is NO-GO for desktop at production
parameters**, and NO-GO for phone in every configuration priced. This is measured
(floor 2.49 GiB at blowup 2) and modelled (4.9 GiB at blowup 3), not inferred.

**D-M3-3.** ~~Implement R-lean + packed path and measure.~~ **Withdrawn.** Packing
saves 480 columns; the hypothesis behind this milestone was based on a mistaken
composition of the trace. Replacement: implement R-lean + algebraic in-circuit hash
only as a *priced experiment* (5.2 GiB predicted), not as a path to phone.

**D-M3-4.** Phone-class proving requires an architecture change, not an optimisation:
recursive aggregation of small AIRs, or a different proof family entirely (lattice
linkable ring signatures). See `ARCHITECTURE-DECISION.md` D-ADR-2.

**D-M3-5.** If a split/recursive design is pursued, the pass rule is: measured
single-proof peak <= 1 GiB on phone-class hardware with production FRI parameters.
Everything else is a laptop-only result and must be described as such.

---

## Part D - what would falsify this analysis

- A measured single-proof peak materially below 4x LDE would improve every row
  proportionally; it would not change the ordering, because the width ceilings are
  the binding constraint.
- A monolithic AIR whose *total* width is under ~1,020 columns at 4,096 rows would
  falsify D-M3-4. No combination of the changes priced here gets close.
- If production FRI can be run at blowup 2 with an acceptable soundness argument, all
  memory figures halve. That would make desktop plausible (lean 4.2 GiB, floor
  2.5 GiB) but still leave phone at ~4x its cap. Treat this as a research question
  for the review, not an assumption.
