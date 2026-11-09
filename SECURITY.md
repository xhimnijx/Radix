# Security policy

## Is this production software?

**No.** Radix is a research prototype. It holds no value, has no network, and makes no
security claim. If you find a vulnerability, that is still worth reporting — the
cryptography is intended to be correct, and a defect in it is a defect in research.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Instead:

1. Open a private security advisory:
   <https://github.com/xhimnijx/Radix/security/advisories/new>
2. Or email the maintainer listed in `CITATION.cff`.

Include what you did, what happened, and what you expected. A failing test case or a
short script is worth more than a description.

## Scope

In scope — a defect that breaks a claim the project actually makes:

- the proof does not verify, or a forged proof verifies;
- the same note can be spent twice despite the tag;
- the ring signature leaks the signer's index;
- the Rust and Python implementations disagree;
- a panic or crash on malformed input (decoder, verifier, envelope parser, HTTP API).

Out of scope — claims the project explicitly does not make (see
[`vault/What This Is Not.md`](vault/What%20This%20Is%20Not.md)):

- "the parameters are not 128-bit" — this is already stated in `STATUS.md`;
- amounts are visible and unproven — this is a documented B2 gap;
- the faucet seed is public, so anyone can spend the testnet's units;
- the testnet has no consensus, no peers, and no economic layer;
- anything requiring deployment of value, which the launch gate prevents.

## What we will do

Acknowledge within a week, tell you whether it is in scope, and record the outcome in
`REVIEW-FINDINGS.md` — including if the finding is against the maintainer. This project
keeps a record of the defects reviewers found, retractions included; a new finding goes
in the same place.

## Known-and-documented issues

Before reporting, check:

- `STATUS.md` — the current known state;
- `REVIEW-FINDINGS.md` — the review record;
- `vault/Status and Honest Limitations.md` — the open items.

Four real defects were found in review and are fixed:
the tag was forgeable, the masking was unsound, the challenge-difference soundness was
~24 bits, and the extracted index was not slot-constant. All four have regression tests.
