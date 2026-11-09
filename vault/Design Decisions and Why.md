---
title: Design Decisions and Why
tags: [design, rationale]
---

# Design decisions and why

The choices that shape the project, each with the alternative and the reason.

## 1. Implement SMILE rather than invent a protocol

**Alternative:** design a new lattice ring signature.
**Reason:** inventing cryptography is how people lose money. SMILE is published,
reviewed, and has a parameter table; the value this project adds is a *faithful
implementation*, a tag extension, and a verified port — not a new scheme.

## 2. Choose an irreducible-quartic modulus

**Alternative:** the split modulus with a full NTT (faster in Python).
**Reason:** at the split modulus the extraction's `c − c̃` invertibility fails with
probability `~2^-24.4`, capping soundness at ~24 bits, and `v(v−1)=0` leaves arbitrary
128-bit idempotents so the "one-hot index" conclusion is meaningless. Both problems
disappear in the field regime. See [[The NTT and the Quartic Decomposition]].

**Cost accepted:** no 128-point NTT, so multiplication uses the quartic CRT.

## 3. Prove the tag inside the existing proof

**Alternative:** a separate sigma protocol for the tag.
**Reason:** the separate proof was **forgeable** — a reviewer showed it bound only a
derived row. The same-witness extension makes the tag part of the relation already being
proved, so there is no second proof to attack. See [[Linkable Tags]].

## 4. Gaussian masks with `Rej1`, and an ℓ₂ bound

**Alternative:** a uniform `2^20` mask with an infinity-norm check (the original code).
**Reason:** with an infinity bound the *response* bound becomes the security parameter,
putting the core at ~`2^50`. The ℓ₂ bound with a calibrated `β` is what the paper
actually specifies. See [[Norms and Why They Matter]].

## 5. Verify by cross-implementation, not by inspection

**Alternative:** trust that the port matches because it was translated carefully.
**Reason:** three bugs survived careful translation — the arity formula, a sign, and
`g`'s prefix. Two implementations accepting each other's proofs is evidence that
inspection is not. See [[How the Port Was Verified]].

## 6. Accounts rather than notes in the wallet

**Alternative:** one keypair per wallet with many notes.
**Reason:** forced by the tag being a function of the *key*. One keypair, one tag, one
spend. Change must go to another account. See [[The Wallet and Its Accounts]].

## 7. Subprocess rather than FFI for the Rust backend

**Alternative:** bind Rust into Python with `pyo3`.
**Reason:** no crates available offline, and the boundary is one call per proof. ~40 ms
of process start against ~500 ms of computation. See [[The Rust Backend Seam]].

## 8. No encrypted keystore in the testnet

**Alternative:** encrypt the faucet seed with a password.
**Reason:** the faucet seed is a **public constant** in the source. Encrypting it would
imply a security property the harness does not have. The honest thing is to say so.
See [[Status and Honest Limitations]].

## 9. Keep the withdrawn tag code, with a failing test

**Alternative:** delete `tag.py`.
**Reason:** the forgery is part of the record. `experiments/tag_forgery_repro.py`
reproduces it and a strict `xfail` guards it. Deleting it would make the project look
like it never had the bug.

## 10. Record retractions in place

**Alternative:** quietly correct wrong numbers in the review record.
**Reason:** a wrong number in an audit record should be seen to be wrong. Three reviewer
claims were retracted and are still visible in `REVIEW-FINDINGS.md`.
