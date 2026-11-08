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
2. **Not by itself.** Removing them cuts trace width 35 % and predicts 4.9 GiB
   (single-proof ratio) to 11.8 GiB (conservative) - still over the 4 GiB desktop
   gate in both cases.
3. The quantified path to desktop fit is **also packing the depth-64 path witness**
   (bit-sliced 8,192 columns -> 384 limb columns): predicted 1.0-2.4 GiB, which fits
   desktop across the measured range and lands at the mobile cap in the optimistic
   case only.

**Measured on this host (2026-11-08):** a single focused path-only proof peaks at
2.49 GiB for a 0.62 GiB LDE (**4.04x**); a composed multi-proof test peaks at
8.61 GiB for a 0.92 GiB LDE (**9.39x**). See `MEASUREMENTS.md`.

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
4-byte BabyBear) and converts the LDE floor to a peak with two **measured**
multipliers (see `MEASUREMENTS.md`):

- **4.04x** - one focused proof, `RDXZ64P1`, 2.49 GiB peak for 0.62 GiB LDE. This
  is what a wallet does: prove one transaction.
- **9.39x** - a composed test that builds several proofs in one process, `RDXK64P1`,
  8.61 GiB for 0.92 GiB LDE. This is the regime the project's own published ~9.5 GiB
  figures came from.

The conservative 9.5x is used for planning; the single-proof 4.0x is reported
alongside it because it is the operationally relevant number.

| Profile | Rows | Width | LDE | Peak @4x | Peak @9.5x | Desktop 4 GiB | Mobile 1 GiB |
|---|---:|---:|---:|---:|---:|---|---|
| R-fat (current RDXL64P1) | 8,192 | 15,629 | 3.82 GiB | 15.3 GiB | 36.3 GiB | 3.8x over | 15x over |
| R-lean (no KDF/AEAD) | 4,096 | 10,129 | 1.24 GiB | 4.9 GiB | 11.8 GiB | 1.2x over | 4.9x over |
| **R-lean + packed path** | 4,096 | **2,065** | 0.25 GiB | **1.0 GiB** | **2.4 GiB** | **FITS** | at cap / 2.4x over |
| RDXZ64P1 path-only floor | 4,096 | 5,043 | 0.62 GiB | 2.5 GiB | 5.9 GiB | fits at 4x | 2.5x over |

Sensitivity to the multiplier (predicted peak, GiB):

| Profile | 4.0x | 5.0x | 7.5x | 9.5x | 12.0x |
|---|---:|---:|---:|---:|---:|
| R-fat | 15.3 | 19.1 | 28.6 | 36.3 | 45.8 |
| R-lean | 4.9 | 6.2 | 9.3 | 11.8 | 14.8 |
| R-lean + packed | 1.0 | 1.3 | 1.9 | 2.4 | 3.0 |
| Path-only floor | 2.5 | 3.1 | 4.6 | 5.9 | 7.4 |

Two results matter more than the rest:

- **The measured floor fits, but barely.** The path-only proof measured **2.49 GiB
  and 17.9 s** on this laptop. It fits the 4 GiB gate with about 1.5 GiB of headroom
  - which the note, nullifier, output, balance and KEM relations must all share.
  The model's 5.9 GiB for this profile at 9.5x describes a multi-proof test process,
  not a wallet.
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

**D-M3-2.** The **R-fat** monolithic relation is **NO-GO for desktop**: 15.3 GiB at
the measured single-proof ratio and 36.3 GiB conservative, against a 4 GiB gate.
Dropping KEM/AEAD alone (**R-lean**) is marginal - 4.9 GiB at 4x - so it is
necessary but not sufficient. One earlier draft of this note claimed even the
path-only floor exceeded desktop; the measurement disproved that (2.49 GiB), and
the correction is recorded here rather than quietly dropped.

**D-M3-3.** The next implementation target is **R-lean + packed path**, with a
pre-registered pass rule: predicted peak <= 4 GiB *and* a measured single-proof peak
<= 4 GiB on the reference laptop class. Predicted **1.0-2.4 GiB** makes the
measurement the obvious next step.

**D-M3-4.** **Mobile is not established.** The packed profile lands at 1.0 GiB at
the single-proof ratio - exactly the cap, with no room for a production FRI
configuration (128 queries, blowup 3, which increases both proof size and prover
work) or for the wallet's own allocations. It needs either a 16,384-query-class
engineering budget or a different hash/recursion. Do not promise a phone wallet
until it is measured with production parameters.

**D-M3-5.** If the packed measurement fails, the fallback order is: (1) split AIRs +
recursive aggregation, (2) zkVM with a Keccak/ML-KEM precompile, (3) algebraic hash
for tree/commitment/nullifier. Each is a multi-month change and each must be
re-costed with this model before implementation.

---

## Part D - what would falsify this analysis

- **Already observed:** the single-proof ratio measured 4.04x, not 9.5x. That moved
  R-lean from 11.8 GiB to 4.9 GiB (still over the gate) and the packed profile to
  1.0 GiB, strengthening D-M3-3 without changing D-M3-2. The model now reports both.
- A packed-path build that adds the limb columns back elsewhere (for example if the
  Keccak frame forces per-bit expansion across all rows) would erase the gain. This
  is the single assumption the next milestone must test.
- A production FRI configuration (more queries, larger blowup) *increases* both
  proof size and prover work; the model's blowup-2 test profile is therefore
  optimistic. This is another reason to treat the packed estimate as a floor, not a
  promise, and to re-measure with production parameters.
