# Radix: initial protocol research and design direction

**Status:** research brief, not a protocol specification. The cryptographic choices below are research hypotheses, not audited recommendations. This review covers Monero's architecture, the practical quantum threat, ledger growth, and a ranked path for Radix.

## Executive recommendation

Do not start by cloning Monero and swapping ECC for a standardized post-quantum signature. Monero's privacy is a coordinated system: stealth outputs, anonymous linkable spends, hidden values, range proofs, wallet scanning, and consensus state all depend on one another. Shor-capable quantum computers threaten important ECC components; ML-DSA, SLH-DSA, and ML-KEM are not drop-in replacements for Monero's privacy primitives.

For an initial Radix design, prioritize **(1) a formal privacy and threat model, (2) crypto-agile versioned protocol, (3) a prototype of a post-quantum private spend system using transparent hash-based zero-knowledge proofs (likely STARK-family) and PQ-safe commitments/nullifiers, and (4) explicit data-availability and pruning rules**. Benchmark end-to-end transactions and verify the cryptographic constructions with independent experts before selecting them. Use ordinary ML-DSA only where ordinary public signatures are acceptable; it does not give ring anonymity. Avoid promising “quantum-proof” or fixed tiny chain size.

The key storage fact: pruning reduces what each node must keep; accumulators and succinct proofs shift validation costs. None can make transaction history disappear for everyone while preserving permissionless recovery and data availability. Design a network with small validating nodes plus independent archive/data-availability providers, and be honest about what each class of node can do.

## How Monero works (simplified, with mathematical sketch)

### Keys and stealth outputs

A standard Monero account has separate spend and view secrets. In a simplified Edwards-curve model, let the recipient secrets be spend scalar `a` and view scalar `b`, with public points `A=aG` and `B=bG`. A sender chooses fresh random `r`, publishes transaction public key `R=rG`, and derives a shared secret point `D=8rA=8aR`. For output index `i`, the sender computes `x=Hs(D || i) mod ℓ` and creates one-time output public key `P=xG+B`. The recipient computes the same shared point using `b` and `R`, scans candidate outputs, and can spend the output with one-time secret `x+b`. (Subaddresses and current implementation details add derivation rules; this is the conceptual scheme.) This makes every on-chain destination a fresh one-time key rather than the published address. The private view key lets a wallet scan incoming output data; the spend key authorizes spending. A view-only wallet does not necessarily know all outgoing activity and cannot always establish the complete balance.

### Hidden spends, linkability and double-spend prevention

A spend includes a ring of candidate output keys, one of which is the actual input. A linkable ring signature proves knowledge of the secret for one member without exposing which one. Monero's key image is conceptually `I=x·Hp(P)` for output secret `x` and public key `P`; the same spend produces the same image. Consensus rejects an already-seen image, preventing double-spends without identifying the spent ring member. Monero currently uses CLSAG, and current rings contain 16 members including the real output. A ring of size 16 is not a guarantee of 1/16 anonymity: decoy selection, reused or identifiable outputs, transaction timing, network metadata, wallet behavior and outside information all affect effective privacy.

### Amount confidentiality and supply correctness

RingCT hides amounts using Pedersen commitments. Simplified form: `C=vH+γG`, where `v` is the amount and `γ` a blinding factor. A transaction proves, without revealing values, that input commitments balance output commitments and fees; it also supplies range proofs that committed amounts lie in the allowed range. This prevents hidden-value inflation and modular wraparound. Monero uses CLSAG for ring spends and Bulletproofs+ for aggregated range proofs; these are distinct proof roles. These constructions rely on elliptic-curve discrete-log assumptions and are not quantum resistant against a sufficiently capable Shor machine.

### Mining, issuance, and consensus

Monero uses proof-of-work with RandomX, designed to be CPU/memory intensive to reduce specialized-hardware advantage; this is a decentralization objective, not a guarantee that mining is perfectly egalitarian or ASIC-proof forever. Miners assemble transactions, search for a block hash satisfying the difficulty target, and broadcast candidate blocks; validating nodes independently check proof-of-work, difficulty, transaction rules, reward and chain selection. Solo mining avoids pool custody; conventional pools concentrate coordination, while P2Pool is a decentralized alternative.

Monero targets roughly two-minute blocks, adjusts difficulty, and has a decaying subsidy followed by a permanent tail emission (nominally 0.6 XMR per block before the block-weight penalty), plus fees. Coinbase outputs mature before spending. A dynamic block-weight mechanism permits expansion but penalizes reward when block weight exceeds its recent median: for median `M` and weight `B` where `M < B < 2M`, the reward multiplier is `(2M−B)B/M²`; above `2M` blocks are invalid. This provides capacity elasticity while making large blocks costly to miners. Any Radix issuance and block-capacity mechanism should be stated as a long-term security-budget choice, not just an initial tokenomics number.

### Wallets and nodes

A wallet derives keys, scans output announcements with its view capability, identifies its one-time outputs, tracks key images/spent state, selects inputs, creates decoys/proofs/outputs and broadcasts transactions. A local full node validates the consensus rules and avoids revealing wallet queries to a third party. A remote node can expose network address, timing and wallet queries, and can censor or deny service; wallets retain their private keys but rely on that node for data and availability. Nodes validate independently rather than trusting a miner's claim that a block is valid.

Monero's pruning can save about two-thirds of disk on an individual node by retaining a random 1/8 of certain pruneable ring-signature data. It does not stop aggregate chain growth or provide every historical byte from every pruned node. Pruning is useful, but is not a cure for permanent storage growth.

## Quantum threat: what must change

Shor's algorithm threatens elliptic-curve discrete logarithms. In Monero-like systems that affects spend authorization, Diffie–Hellman-style stealth derivation, linkable ring signatures/key images and Pedersen commitment binding. Simply replacing key signatures leaves amounts, stealth and anonymous spending exposed. NIST-standardized primitives are useful components, not a whole private-coin protocol:

- **ML-DSA (FIPS 204):** standardized lattice signature for ordinary signatures; not a ring signature or anonymous one-out-of-many spend proof. Per-input signature size is material.
- **SLH-DSA (FIPS 205):** stateless hash-based signatures with conservative hash assumptions, but very large signatures; more plausible for infrequent governance/checkpoint keys than everyday spends.
- **ML-KEM (FIPS 203):** key encapsulation, not a signature or stealth-address scheme. It could support encrypted communications, but Radix still needs a private payment/scan-key construction.
- **Lattice ring proofs and hash-based commitments:** candidate research directions, not drop-in standards. Must establish quantum-secure anonymity, soundness, linkability/nullifier uniqueness and range/balance correctness together.
- **STARK-family proofs:** transparent, hash-based proof systems offer a plausible post-quantum direction, including recursive validity proofs. A STARK does not automatically provide privacy: the circuit must be zero knowledge and prove hidden ownership, no double-spend, amount range and balance. It does not provide the transaction data or wallet history. Performance and proof bytes are construction- and circuit-dependent.

Grover gives a generic quadratic speedup against brute-force search, not Shor's exponential break of public-key discrete log. Hash choices and parameters need explicit quantum security analysis; do not use a blanket “double all hashes” rule. Long-lived keys, historical outputs and migration policy need analysis, since moving after exposure may be too late for data that can be attacked retrospectively.

## Ranked ideas for Radix

Scores are relative priorities (impact, practicality, risk), not guarantees.

| Rank | Idea | Why / tradeoff | Priority |
|---|---|---|---|
| 1 | **Formal threat model + crypto-agility from genesis** | Define adversaries (quantum, network, node, miner, wallet compromise), privacy goals and migration paths. Version transaction and proof formats; avoid hardwiring one primitive. Governance/upgrade complexity remains. | Essential now |
| 2 | **Post-quantum private-spend proof prototype** | Research a transparent ZK proof that proves ownership of one hidden member of a committed output set, emits a unique PQ-safe nullifier, and proves balance/range validity. STARK/hash-based families are promising, but large proof and prover costs are likely. No off-the-shelf Monero equivalent. | First technical R&D |
| 3 | **Specify data availability and node tiers** | Small validators, wallet servers and archives have different storage duties. Replication, erasure coding, discovery and retention incentives must be designed, not assumed. Historic data availability remains a dependency. | Essential now |
| 4 | **Pruning + independent archives** | Lowest-risk disk reduction and practical launch baseline. Improves individual node accessibility but does not arrest total chain growth or guarantee that old history is served. | Near-term |
| 5 | **PQ-safe output accumulator / stateless validation** | Commitments to active outputs and membership witnesses can cut local state. In private currencies, design must preserve plausible decoys, scan/recovery, nullifier history and anonymity; witness bandwidth and serving are shifted costs. | Medium-term research |
| 6 | **Recursive validity proofs for batches/history** | Can make validation of many transitions succinct. Requires a fully correct consensus circuit, expensive proving operations, careful upgrades and a separate data-availability layer. Circuit bug can invalidate the chain. | Long-term |
| 7 | **Protocol-level privacy defaults and metadata defenses** | Constant formats, uniform fees/outputs where feasible, robust decoy construction, private transaction broadcast and wallet scanning protections limit user error/metadata leakage. Network-level privacy remains hard. | High, staged |
| 8 | **Decentralized mining/pool design and durable issuance** | Evaluate RandomX-like PoW versus alternatives, concentration and energy costs; use stable long-term security incentives. ASIC resistance is never absolute and mining alone does not make private transactions secure. | High, parallel |
| 9 | **Client-side validation for optional assets** | Can keep application-specific data off the base chain, but users must retain/receive histories and assets may be stranded. Not a substitute for globally fungible private base money. | Optional feature |
| 10 | **Ordinary ML-DSA-only spending** | A tractable PQ baseline for transparent or non-private transactions, but it sacrifices Monero-like signer ambiguity unless augmented with a separate PQ privacy proof; signatures also increase ledger bytes. | Only as interim/fallback |

## Implementation roadmap

1. **Write the spec before the coin:** asset/supply model; transaction lifecycle; privacy goals; threat model; finality/reorg rules; fee and anti-DoS rules; wallet recovery; node roles; data retention and historical verification assumptions.
2. **Establish a research team and review process:** cryptographers, protocol engineers, privacy/network researchers, wallet implementers. Maintain a public assumptions ledger and threat model. Fund independent review; publish reproducible benchmarks and attack analyses.
3. **Build a non-consensus prototype:** compare candidate hash commitments, PQ spend/nullifier proofs, range/balance proofs and wallet scanning. Measure transaction bytes, prover CPU/RAM/time, verifier time, block bandwidth, initial sync and wallet recovery across ordinary hardware.
4. **Model chain growth:** at several transaction rates, calculate bytes/day and years-to-disk targets, separately for full archive, pruned node, accumulator state, proof/witness relay and wallet. State what data exists somewhere and who serves it.
5. **Test privacy adversarially:** decoy-set attacks, timing/amount/fee fingerprints, remote-node query leakage, P2P broadcast correlation, key compromise, mempool behavior, wallet restore and light-client eclipse attacks.
6. **Prototype testnet and audits:** fuzz consensus/parser/circuit code; formalize proof statements; independent cryptographic review; public testnet with adversarial miners and node operators; no monetary launch until serious findings are resolved.
7. **Launch only with migration rules:** specify cryptographic agility, deprecation thresholds, emergency fork process, old-key/output migration and what happens if quantum capability arrives before voluntary migration.

## Source guide

- Monero [stealth addresses](https://www.getmonero.org/resources/moneropedia/stealthaddress.html), [ring signatures](https://www.getmonero.org/resources/moneropedia/ringsignatures.html), [RingCT](https://www.getmonero.org/resources/moneropedia/ringCT.html), [view key](https://www.getmonero.org/resources/moneropedia/viewkey.html), [pruning](https://www.getmonero.org/resources/moneropedia/pruning.html), [RandomX](https://www.getmonero.org/resources/moneropedia/randomx.html), [mining](https://www.getmonero.org/get-started/mining/), [tail emission](https://www.getmonero.org/resources/moneropedia/tail-emission.html), and [Monero Research Lab papers](https://www.getmonero.org/resources/research-lab/).
- Cryptography: Noether, [Ring Signature Confidential Transactions for Monero](https://eprint.iacr.org/2015/1098); [Bulletproofs+](https://eprint.iacr.org/2020/735); [Triptych](https://eprint.iacr.org/2020/018); [CLSAG](https://eprint.iacr.org/2019/654). Paper status, exact version and implementation correspondence should be checked during a formal specification review.
- Ledger scaling: [Monero pruning announcement](https://www.getmonero.org/2019/02/01/pruning.html); Dryja, [Utreexo](https://eprint.iacr.org/2019/611); [Bitcoin Optech Utreexo](https://bitcoinops.org/en/topics/utreexo/) and [client-side validation](https://bitcoinops.org/en/topics/client-side-validation/).
- Post-quantum standards: NIST [ML-KEM / FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [ML-DSA / FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), [SLH-DSA / FIPS 205](https://csrc.nist.gov/pubs/fips/205/final); Ben-Sasson et al., [Scalable, Transparent, and Post-Quantum Secure Computational Integrity](https://eprint.iacr.org/2018/046).

**Citation caveat:** this first-pass review used primary project pages, standards pages and papers directly; broad web search was unavailable in this session. Moving source-code branches and paper revisions should be pinned and verified before turning this brief into a consensus specification. This is technical research, not investment, legal, or cryptographic-audit advice.
