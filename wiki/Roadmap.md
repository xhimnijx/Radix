# Roadmap: what mainnet would require

The proof is the part this project got right. Mainnet needs four more layers, and the
order matters because an early layer can invalidate a later one.

## Phase 0 — close the cryptography (months)

| Task | Why it blocks |
|---|---|
| **Lattice estimator run** | The only thing between "proofs verify" and "parameters are secure" |
| Discrete Gaussian sampler | The mask is continuous-then-rounded |
| Restate Theorem B.1 for the irreducible modulus | The paper's analysis assumes the split case |
| Composition proof for the tag extension | Argued, not proved |
| Third review, then a paid audit | Two informal reviews found four defects |

## Phase 1 — complete the transaction model

Amount commitments, range proofs, conservation, **one-time addressing** (a real research
problem in the lattice setting), decoy selection. This is where design risk remains.

## Phase 2 — consensus and networking

Consensus choice, peer-to-peer, reorg handling, fee market, sync strategy — and an
answer to chain growth, since spent outputs cannot be pruned.

## Phase 3 — security engineering

Batch verification (110 ms per proof is a DoS vector), constant-time review, fuzzing,
encrypted keystore, reproducible builds, signed releases.

## Phase 4 — operations

Multiple audits, bug bounty, public testnet then stagenet, a frozen launch manifest
signed by several parties, incident response, and legal review.

## Sizing

A credible mainnet is roughly **one cryptographer plus two or three engineers for
18–24 months**, plus audit budget. The two places a design can still fail are lattice
range proofs and one-time addressing.
