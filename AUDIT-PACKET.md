# Independent review packet

This is what an independent cryptographer, consensus engineer, or security auditor
receives. It states exactly what is being asserted, what is **not** being asserted,
and which artifact answers which question. The launch gate accepts a signature only
over the parameter hash printed here, so the review attaches to exact bytes.

Generate the current packet state:

```powershell
python -m examples.launch_gate_check
python -m pytest -q
cd proof_harness; cargo check --locked --all-targets
```

---

## 1. Claims offered for review

| ID | Claim | Status today | Evidence to inspect |
|---|---|---|---|
| A1 | Canonical encodings are unambiguous and reject non-canonical input | Supported for the tested corpus | `radix_core/encoding.py`, `wire.py`, `tests/test_wire.py`, `tests/test_adversarial_parsing.py` |
| A2 | Candidate-A hash formulas match the specification and a second implementation | Partially: one Rust SHAKE vector per formula, plus Python KATs | `Radix-Gate-A-Cryptographic-Review.md` §3.1, `tests/test_crypto_formulas.py`, `proof_harness/src/*.rs` |
| A3 | The 1-in/1-out relation proves path membership, note opening, nullifier, balance, and statement binding with a common witness | Component evidence only; never executed end-to-end | `proof_harness/TRANSACTION-PROOF-PROTOTYPE-SCOPE.md`, `depth64_path_opening.rs` (`RDXL64P1`) |
| A4 | Amount conservation is exact integer arithmetic, not field-modular | Argued and statically reviewed; prover never runs | `TRANSACTION-PROOF-PROTOTYPE-SCOPE.md` §"Output balance AIR review" |
| A5 | Anchor and block transitions are deterministic and atomic | Supported in the in-memory model; not a node | `radix_core/rules.py`, `state.py`, `tests/test_state.py` |
| A6 | Wallet note creation/recovery is correct for honest providers | Supported and integration-tested | `tests/test_real_wallet_flow.py`, `tests/test_wallet_scan_containment.py` |
| A7 | The launch gate cannot be opened without signed attestations over the exact parameters | Supported | `radix_core/launch.py`, `tests/test_launch_gate.py` |

## 2. Claims **not** offered — do not assume them

- That the construction is secure, private, or post-quantum safe end to end.
- That a complete transaction proof exists, or that `RDXL64P1` runs.
- That the shipped FRI parameters provide any particular soundness level (they are
  a 2-query test configuration; the gate refuses them for mainnet).
- That recipient key privacy holds (it does not; it is an open P0 blocker).
- That the wallet can be recovered from a seed (it cannot; there is no derivation).
- That the node can sync, mine, or validate a real chain (none of that exists).

## 3. Artifacts, in reading order

1. `Radix-Workspace-Review.md` — third-party-style assessment of the workspace as
   found, including the defects fixed since.
2. `SECURITY-NOTES.md` — every remediated defect with impact and regression test.
3. `Radix-Gate-A-Cryptographic-Review.md` — relation definitions, encodings,
   security games (definitions only), leakage profile.
4. `Radix-Protocol-Draft.md` — protocol, consensus outline, monetary hypothesis.
5. `Radix-Gate-1-Feasibility-Log.md` — decision log and open blockers.
6. `TRANSACTION-PROOF-PROTOTYPE-SCOPE.md` — what the harness does and does not prove,
   with measured numbers.
7. `Radix-Candidate-A-Mathematical-Exposition.md` — the mathematical narrative.
8. `PLAN.md` / `STATUS.md` — what is being claimed now, and what is missing.

## 4. Review scopes and what each signature asserts

The gate requires all five scopes. A reviewer signs only the scopes they actually
examined; the manifest may carry more than five attestations.

| Scope | The reviewer is asserting |
|---|---|
| `soundness` | The relation is knowledge-sound under the stated assumptions, or the specific gaps are listed and judged fixable. |
| `zero-knowledge` | The proof system's hiding is established for this circuit, or the specific leakage is listed. |
| `qrom` | The Fiat–Shamir transform and FRI parameters meet the target in a stated quantum model, with the arithmetic shown. |
| `consensus` | The state transition, uniqueness sets, anchors, and resource caps are deterministic, bounded, and correctly implemented for the claimed network. |
| `recipient-privacy` | The discovery construction prevents candidate-key testing and output linkability for the stated adversary, or the claim is narrowed explicitly. |

## 5. The exact bytes that get signed

```python
from radix_core.launch import MAINNET_PARAMETERS, AuditManifest, REQUIRED_MAINNET_SCOPES

print(MAINNET_PARAMETERS.canonical_bytes().hex())
print(MAINNET_PARAMETERS.parameters_hash().hex())
print(MAINNET_PARAMETERS)
```

`parameters_hash` is SHAKE256 over `Frame("radix/launch-parameters/v1", …)`. The
manifest payload is `Frame("radix/audit-manifest/v1", [parameters_hash,
issued_at, *scopes])`. Attestations are Ed25519 signatures over that payload.
Verification recomputes both from the parameters and the manifest fields; nothing
is trusted from the manifest except the attestations themselves.

## 6. Known limitations a reviewer should weigh explicitly

| # | Limitation | Consequence |
|---|---|---|
| 1 | No complete transaction proof; ML-KEM and GHASH are not in any AIR | No end-to-end soundness claim; the 16-byte GCM tag is unconstrained where CTR is proved |
| 2 | Shipped FRI config is `new_testing_zk` (2 queries, blowup 2) | Test-only; mainnet gate refuses it |
| 3 | Proving is fail-closed and never measured end to end | Proving time and peak RSS unknown |
| 4 | Recipient key privacy unsolved | Charter P-03 unmet |
| 5 | Quadratic block validation (`validate_integrity` per block, full clones) | Cannot replay a real chain |
| 6 | Static-audit tests grep Rust source text | They check formatting, not behaviour; Rust-side mutated-witness tests are the honest control |
| 7 | No seed/mnemonic recovery, no human address format | Not usable by a non-technical holder |
| 8 | No node, P2P, PoW, mempool, or block wire format | Cannot be a network, only a library |

## 7. How to record a review

Produce, and keep with the launch record:

1. Reviewer name, affiliation, and the scope(s) examined.
2. The exact `parameters_hash` reviewed.
3. Findings, severities, and whether each was resolved, accepted, or open.
4. The Ed25519 public key and the fingerprint used in the attestation.
5. A statement of independence (not an author, vendor, or paid implementer).

A signature is a statement about the bytes above, not a general endorsement of the
project.
