# The lean relation - soundness note, cost model, and decision record

**Status:** decision-grade analysis, not a proof. **Date:** 2026-11-08.
**Question:** the transaction relation currently proves in-circuit that each output's
ML-KEM ciphertext is a real encapsulation and that its AES-GCM ciphertext
authenticates. Does any safety property require that? And if it does not, is the
resulting smaller circuit enough to fit the project's own device budget?

**Answers, in one line each:**

1. **No.** Supply integrity, double-spend resistance, and recipient detection do
   not depend on in-circuit KEM or AEAD. The constraints buy third-party
   ciphertext auditability, which no consensus rule consumes.
2. **Not by itself.** Removing them cuts trace width 35 % and predicts about
   11.8 GiB peak, still 2.9x over the 4 GiB desktop gate.
3. The quantified path to desktop fit is **also packing the depth-64 path witness**
   (bit-sliced 8,192 columns -> 384 limb columns): predicted 2.4 GiB, which fits
   desktop at every multiplier we tested, and still misses mobile by 2.4x.

Reproduce: `python -m experiments.lean_relation_sizing`.

---

## Part A - soundness note: which property forces in-circuit KEM/AEAD?

The claim under examination is that the *consensus* relation does not need to
constrain ML-KEM encapsulation or AES-GCM. It is argued property by property. All
symbols follow `Radix-Gate-A-Cryptographic-Review.md` section 4.

### A1. Supply integrity and double-spend resistance

A note's value is fixed by its public commitment
`cm = H_note-commit(p, U64(v), rho, r)`. The relation proves, from the spender's
witness, that `cm` opens to `(p, v, rho, r)`, that `p = H_note-owner(pk_s, K)` for
the witness `K`, and that the integer identity `sum(v_in) = sum(v_out) + fee` holds
with bounded limbs. Consensus separately enforces global uniqueness of `cm` and
`nf = H_nullifier(s, K, rho)`.

None of those steps reads `ct_kem`, the AES key, the nonce, or `C` (beyond
`leaf = H_note-leaf(cm, ct_kem, nonce, C)` being committed). Replacing `ct_kem` and
`C` by arbitrary bytes changes `leaf` but cannot change a value, create a second
opening of `cm`, or produce a new `nf`. **Supply safety is independent of the
KEM/AEAD constraints.**

### A2. Recipient detection (the property people assume needs the circuit)

The recipient's scan procedure is:

1. `K' = ML-KEM.Decaps(sk_v, ct_kem)`;
2. `p' = H_note-owner(pk_s, K')`, `K_enc' = KDF(K', ct_kem, cm)`;
3. decrypt `C` under `K_enc'` with AAD `U8(1)||cm||ct_kem`;
4. recompute `cm' = H_note-commit(p', U64(v'), rho', r')` and compare with `cm`.

Steps 1-4 are executed **by the recipient**, from public bytes and their own secret.
If the payer's ciphertext encodes a different value, owner, `rho`, or `r` than `cm`,
then `cm' != cm` and the output is not credited. The recipient therefore detects
every inconsistency the in-circuit constraints would have prevented, and one more:
a ciphertext that is a valid encapsulation but to a key the recipient does not hold.

**Detection is local and complete without the circuit.** What the circuit adds is
that a *third party* (an auditor, a node, a light client) could check the same thing
without the recipient's key. No consensus rule consumes that check.

### A3. Tamper resistance

`leaf` commits to `(cm, ct_kem, nonce, C)`, and membership is proven against it. Any
mutation of `C`, `ct_kem`, or `nonce` changes `leaf` and fails membership. This is
exactly why the recipient can trust the bytes they decrypted: they recompute `leaf`
from the published output record and check it is in the tree.

### A4. Burn resistance - already absent

A payer can burn value today by encapsulating to a valid `pk_v` whose secret they
discard, or by paying a random canonical key. Proving encapsulation in-circuit does
not prevent this, because neither the circuit nor consensus can prove that anyone
controls `pk_v` (there is no proof of possession - see the review, section 2.H6). So
the constraint does not deliver "no accidental burn"; it cannot.

### A5. What is actually lost, and what must be written down

| Lost property | Consequence | Mitigation |
|---|---|---|
| Public verifiability that an output is well-formed for *some* key | An auditor cannot check ciphertext/commitment consistency without the recipient's key | Make recipient-side recomputation normative; document that payee assurance is recipient-local |
| Public authenticity of the 16-byte GCM tag | A payer can publish a tag that authenticates nothing | **Already true today**: the RDXL relation constrains only ciphertext bytes 0-139 and leaves 140-155 unconstrained (review section 2.H14) |
| A guarantee that a note is *spendable by someone* | Publicly valid outputs may be unspendable | Already true via destroyed keys; add a wallet warning and document the burn path |

### A6. Residual obligations before this becomes a versioned relation change

1. State a formal **note-usability predicate**: an output is usable by a party iff
   that party's scan succeeds. Prove (i) *spend soundness* needs only `cm`, the
   balance relation, and consensus uniqueness; (ii) *detection completeness*: if the
   payer follows the honest construction, the recipient's scan accepts; (iii)
   *detection soundness*: if the scan accepts, the note's value and owner are the
   committed ones (immediate from commitment binding).
2. Keep the requirement that **`cm` is globally unique**, so one commitment cannot
   carry two ciphertexts; otherwise a payer could publish two "notes" for one
   commitment with conflicting encryptions.
3. Keep the honest-construction obligation in the wallet: the wallet must encrypt
   the same `(value, rho, r)` it committed to. That is now a *correctness* property
   of the sender, not a consensus rule.
4. Bound the griefing surface: a hostile output costs the recipient one KEM
   decapsulation per scan. Unavoidable without a scan filter.

**Conclusion of Part A:** the KEM/AEAD constraints are not required for safety. They
are an auditability feature. Removing them is a legitimate, versioned relation
change *provided* A6 is written and reviewed - not a silent optimisation.

---

## Part B - cost model

Inputs and sources are in `experiments/lean_relation_sizing.py`. The model uses the
project's own dimension arithmetic (2x randomized rows, blowup 2, +4 ZK codewords,
4-byte BabyBear) and converts the LDE floor to a predicted peak with a **9.5x
multiplier** derived from the two published focused runs:

- `RDXI64P1`: LDE 871,440,128 B, measured peak 7,911.7 MiB -> 9.52x
- `RDXJ64P1`: LDE 985,006,080 B, measured peak 9,518.0 MiB -> 10.13x

Both were test-process peaks (trace + proof + harness), so 9.5x is conservative for
a single isolated proving call.

| Profile | Rows | Width | LDE | Predicted peak | Desktop 4 GiB | Mobile 1 GiB |
|---|---:|---:|---:|---:|---|---|
| R-fat (current RDXL64P1) | 8,192 | 15,629 | 3.82 GiB | 36.3 GiB | 9.1x over | 36x over |
| R-lean (no KDF/AEAD) | 4,096 | 10,129 | 1.24 GiB | 11.8 GiB | 2.9x over | 11.8x over |
| **R-lean + packed path** | 4,096 | **2,065** | 0.25 GiB | **2.4 GiB** | **FITS (0.6x)** | 2.4x over |
| RDXZ64P1 path-only floor | 4,096 | 5,043 | 0.62 GiB | 5.9 GiB | 1.5x over | 5.9x over |

Sensitivity to the multiplier (predicted peak, GiB):

| Profile | 5.0x | 7.5x | 9.5x | 12.0x |
|---|---:|---:|---:|---:|
| R-fat | 19.1 | 28.6 | 36.3 | 45.8 |
| R-lean | 6.2 | 9.3 | 11.8 | 14.8 |
| R-lean + packed | 1.3 | 1.9 | 2.4 | 3.0 |
| Path-only floor | 3.1 | 4.6 | 5.9 | 7.4 |

Two results matter more than the rest:

- **The path-only floor already exceeds the desktop budget.** The smallest proof
  the harness has ever measured - depth-64 membership and nothing else - predicts
  5.9 GiB, 1.5x the gate. So "remove features until it fits" cannot work: the
  *representation* of the path is itself the problem.
- **The width ceiling is brutal.** At 4,096 rows the desktop gate allows width
  <= 3,445 and the mobile gate <= 858. R-lean is 10,129.

Where the width actually goes (post-revert RDXL): Keccak AIR about 2,937, path
current + sibling bit witnesses 8,192, absorb buffers about 1,088-1,152, AES/KDF
banks 5,500, balance/leaf/stage columns the remainder. **The 8,192 path-bit columns
dominate.**

### Why packing the path is the lever

The path is witnessed bit-sliced because the Keccak frame is bit-indexed: 4,096
current-node bits plus 4,096 sibling bits, carried across all 8,192 rows so the
transition constraints can hold them. Representing each 64-byte digest as 32 x 16-bit
limbs (384 columns for both digests, plus 64 direction bits) and expanding to bits
only inside the active permutation rows removes about 7,800 columns. It changes no
cryptography and no proof system; it is a witness-layout refactor plus a
column-lifetime audit.

**Caveat:** the packed estimate is an *estimate*. It assumes the transition
constraints can be expressed over limbs (they can: direction bits index limbs, and
bit extraction is a 16-way decomposition reused inside the Keccak rows) without
adding those columns back. It must be implemented and measured before it is believed.

---

## Part C - decision record

**D-M3-1.** The in-circuit KEM/AEAD constraints are removed from the *safety*
relation and retained only as an optional, separately versioned auditability
extension. Rationale: Part A. Consequence: a new relation version (`RDXM`), new
vectors, and a written A6 argument before it is used for anything.

**D-M3-2.** The monolithic-AIR route is **NO-GO for desktop as currently
structured**. Even the lean relation is 2.9x over the gate, and the smallest measured
profile is 1.5x over. This closes the "shave rows and hope" plan.

**D-M3-3.** The next implementation target is **R-lean + packed path**, with a
pre-registered pass rule: predicted peak <= 4 GiB *and* a measured single-proof peak
<= 4 GiB on the reference laptop class. Predicted 2.4 GiB makes the measurement
worth doing.

**D-M3-4.** **Mobile remains out of reach** (needs width <= 858 at 4,096 rows, or
1,024 rows at width <= 3,445). No combination of packing and lean gets there. Mobile
self-custody requires a different hash (algebraic, about 10-20x fewer columns) or
recursive aggregation / a zkVM. Do not promise a phone wallet on this architecture.

**D-M3-5.** If the packed measurement fails, the fallback order is: (1) split AIRs +
recursive aggregation, (2) zkVM with a Keccak/ML-KEM precompile, (3) algebraic hash
for tree/commitment/nullifier. Each is a multi-month change and each must be
re-costed with this model before implementation.

---

## Part D - what would falsify this analysis

- A measured single-proof peak far below the 9.5x multiplier (for example the 5x
  column): R-lean would then be about 6.2 GiB - still over, so D-M3-2 holds; the
  packed profile would be about 1.3 GiB, strengthening D-M3-3.
- Evidence that the path bit columns can be eliminated without adding them back
  elsewhere: strengthens D-M3-3.
- A production FRI configuration (more queries, larger blowup) *increases* both
  proof size and prover work; the model's blowup-2 test profile is therefore
  optimistic. This is another reason to treat 2.4 GiB as a floor, not a promise.
