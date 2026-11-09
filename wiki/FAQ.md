# FAQ

**Is this a cryptocurrency?**
No. No value, no network, no consensus, not audited. The mainnet gate is closed by
design.

**Is it quantum-resistant?**
The security rests on module-SIS and module-LWE, which have no known efficient quantum
attack. But see the next question.

**Is it 128-bit secure?**
Unknown, and therefore not claimed. No lattice estimator has been run against the
parameters. This is the single most important open item.

**How is this different from Monero?**
Same privacy goal, different mathematics: Monero uses elliptic curves (broken by Shor),
Radix uses lattices. The ring-signature-plus-tag structure is deliberately similar.

**Why is a proof 32 KB?**
Lattice objects are large. A public key is 2 KB rather than 32 bytes, so everything
scales up. That is the price of post-quantum security.

**Why does a send take two minutes?**
The Python reference is slow and unoptimised. The Rust prover is 496 ms measured.
See the [fast backend](Getting-Started#use-the-fast-backend).

**Why can a wallet only spend each account once?**
Because the tag is a function of the key. A production wallet gives every output its own
key (one-time addressing); that is not built yet.

**Why does the wallet have four accounts?**
Because it starts with one funded account, and change has to go to a *different* key —
the first account's tag is burned by spending it.

**Can I trust the tests?**
They include cross-implementation checks: Rust proofs verify in Python and vice versa.
Two implementations cannot agree by accident on a 32 KB object.

**What is the biggest known gap?**
Amounts are visible and unproven, so a malicious spender could lie about their value.
That is documented in `vault/Transactions Outputs and Spends.md`.

**Has it been reviewed?**
Twice, informally. Four real defects were found and fixed; the record is in
`REVIEW-FINDINGS.md`, including claims the reviewers retracted against themselves.
