# Radix: roadmap from research idea to a permissionless cryptocurrency

**Purpose:** turn the selected Candidate-A direction into a staged, evidence-gated project that could eventually let the public run nodes, use self-custody wallets, send and receive the asset, and mine blocks without approval from a central operator.

**Status:** a plan, not a launch decision. Candidate A is not proven secure, Gate A is not passed, no production STARK is selected, no mining or monetary policy is final, and no mainnet parameters are approved. Calendar estimates below are planning ranges only; cryptographic redesign or failed gates can stop or restart the schedule.

## 1. Executive recommendation

Proceed with **Candidate A as a non-value research track**, not as a mainnet commitment. Its proposed core is a confidential-note system, a depth-64 global append-only Merkle tree, deterministic nullifiers, and a transparent zero-knowledge proof for membership, output construction, and bounded integer balance. The present design also proposes ML-KEM-768 and AES-256-GCM and would require proving substantial KEM, encryption, and hash computations inside the proof system. That cost—and whether the complete proof can be made secure—is unknown.

In parallel, specify the public chain and mining objectives, but do not let provisional choices harden into consensus merely because code has been written. The protocol draft's upstream RandomX/120-second PoW direction and tail-emission schedule are hypotheses for study, not selected launch parameters. Do not call RandomX ASIC-proof, quantum-proof, or perfectly egalitarian.

**Non-negotiable rule:** there is no value-bearing mainnet until the exact privacy construction, proof system, consensus transition, money creation, wallet recovery, and data-availability model pass their gates and receive independent review. If Candidate A fails its feasibility or security gate, redesign it or stop; do not silently weaken privacy or swap in classical cryptography while retaining stronger marketing claims.

## 2. What “anyone can access, mine, and own” must mean

The phrase needs testable product requirements. It cannot mean guaranteed equal rewards, guaranteed profits, legal availability in every jurisdiction, or immunity to network surveillance.

### Access

- Anyone can download source code and reproducible releases, join the peer-to-peer network, create a wallet, receive and send the asset, and run a validating node without a whitelist, account, or central API.
- A new user can obtain and verify chain state without trusting a miner, wallet vendor, explorer, or project-operated checkpoint. If checkpoints or snapshots are introduced for performance, their trust assumptions must be explicit and optional verification from genesis remains possible, or a separately reviewed trust-minimized proof path is provided.
- Historical note ciphertexts and proof data remain available from independent archives; validity proofs do not reconstruct data that was withheld.
- The protocol may be permissionless while exchanges, hosted wallets, mining pools, or other services remain subject to local law. Do not promise universal legal access.

### Mining

- Interpret “mine” as **permissionless proof-of-work mining** unless governance explicitly chooses another consensus model. Anyone can run the reference miner; no registration or approval is needed.
- Measure whether ordinary hardware can participate, but never promise that every miner will be equally profitable or that specialist hardware will never emerge. Publish hardware, energy, pool, and hashrate-concentration data.
- Support solo mining and investigate decentralized pool coordination. Avoid making a centralized pool, project server, or hosted miner necessary to participate.
- Validators independently check proof validity, state transition, issuance, difficulty, and chainwork. Mining does not grant permission to bypass transaction rules.

### Ownership

- “Own” means control of the required private keys and the ability to construct a valid spend under consensus. It is not a statement of legal title, guaranteed market value, or guaranteed recoverability after key loss.
- The wallet must support independently generated non-custodial keys, understandable backups, restore-on-new-device, optional view-only access, and clear separation of spend authority from viewing/scanning capability.
- No custodian, issuer, or administrator can freeze, confiscate, or create balances outside the published consensus rules. Emergency upgrades must be transparent and versioned; they cannot be hidden powers.

## 3. Architecture to carry forward—and to challenge

The current source set is the [Candidate-A mathematical exposition](<Radix-Candidate-A-Mathematical-Exposition.md>), the [Gate A review](<Radix-Gate-A-Cryptographic-Review.md>), the [protocol draft](<Radix-Protocol-Draft.md>), and the [research brief](<Radix-Research.md>). Treat the exposition as an explanation of a proposed relation, not as an implementation specification.

### Candidate-A hypotheses

- Notes commit to hidden amount and opening; public outputs carry a KEM ciphertext and authenticated encrypted recovery payload.
- New output leaves append to the global binary tree. A spend proves membership at a public root without revealing the leaf index and publishes a deterministic nullifier.
- The proof must demonstrate commitment openings, KEM/output consistency, AEAD/output consistency, tree membership, canonical ranges, and integer conservation.
- The value balance is over integers. Range and carry/limb constraints are required; a field-modular equation alone is not adequate.
- Full nodes separately check branch-relative anchors, nullifier non-membership, commitment uniqueness, and atomic state updates.

### Known blockers to decide before implementation hardens

1. **No selected end-to-end proof system.** The proposed STARK knobs are benchmarks, not a security parameter set. The exact AIR/circuit, transcript, masking, FRI variant, binding, extraction, soundness, zero knowledge, and QROM analysis are absent.
2. **Potentially prohibitive proof cost.** Proving ML-KEM, AES-GCM, SHAKE-based hashes, and tree paths may make transactions too slow, large, or memory-intensive for normal users.
3. **Recipient-key privacy and wallet scanning.** ML-KEM IND-CCA security does not by itself give recipient key privacy. The per-output KEM ciphertext size and scanning work are substantial. Test whether observers with candidate keys can identify outputs.
4. **Published length leakage.** The current experimental-v1 ciphertext reveals exact memo length: `|C|=156+|memo|`. The Gate 1 log proposes a fixed 652-byte plaintext and 668-byte ciphertext for a successor privacy profile; the format/version and vectors remain to be implemented and reviewed.
5. **Fork context — specification decision recorded.** The statement has no candidate-parent/fork identifier; the transcript binds the chain/version/anchor/root statement only. Consensus `AnchorOK` checks the root on the exact candidate parent's ancestry, and branch-relative nullifier state determines replay acceptance. This is intentionally not a fork-specific transcript; implementation/tests must preserve that rule.
6. **Monetary arithmetic incomplete.** The maximum block transfer count and fee bound are not fixed, so the mint proof's aggregate fee total needs a defined finite width and canonical serialization.
7. **Recipient address control.** The payer-supplied output spend component can be arbitrary. Define key validation, proof-of-possession or user-facing invalid-address protections, and failure recovery.
8. **Supply invariant.** Specify genesis/migration issuance and prove every accepted output is created by a valid transfer or mint transition.

Candidate B may remain a research comparator or explicit redesign option. It is not a ready-made fallback; it needs its own complete commitment, amount/range proof, global cross-context nullifier, recipient discovery, encoding, and security analysis. Do not swap proof families without a versioned design review.

## 4. Program structure and accountable workstreams

Run these tracks in parallel where dependencies permit, but make their results meet at common design gates.

| Workstream | Accountable expertise | Principal outputs |
|---|---|---|
| Cryptography and protocol | Independent ZK/STARK specialists, post-quantum cryptographers, protocol designer | Threat model, formal relations, exact primitive profile, proof-system choice, security arguments, migration design |
| Consensus and economics | Distributed-systems/PoW engineer, economist, independent simulation reviewers | Deterministic state machine, PoW and retarget rules, chain selection, issuance model, fee/weight bounds, adversarial simulations |
| Implementation and testing | Systems engineers, security engineer, test/verification engineer | Reference implementation, differential vectors, fuzzers, model checks, reproducible builds, safe release process |
| Wallet and privacy | Wallet engineers, UX/accessibility, privacy researcher | Seed/key format, scanning, restore, signing/proving flow, relay privacy, usability and error handling |
| Network and data availability | P2P engineers, node operators, archive/community operators | Peer protocol, bootstrap, anti-eclipse measures, archival retention, pruning, sync and availability monitoring |
| Legal, operations, governance | Counsel in relevant jurisdictions, incident lead, independent community representatives | Legal analysis, launch charter, upgrade process, disclosures, incident response, funding transparency |

No individual or project-controlled signing key should be able to unilaterally change balances, bypass proof checks, or silently activate a consensus change. Define how releases and emergency changes are reviewed, reproduced, announced, activated, and rolled back before a public testnet.

### Indicative schedule and resourcing

These are planning bands for a staffed project, not promised delivery dates. Workstreams can overlap, but later milestones depend on exact, reviewed designs:

| Work | Indicative effort | Dependency / caveat |
|---|---:|---|
| Charter, threat model, requirements | 1–2 months | Start immediately; legal and privacy claims may change scope. |
| Candidate-A formalization and feasibility | 6–18+ months | Highest uncertainty; may fail or require a new design. |
| Consensus/economic design and simulations | 3–6 months | Can run beside cryptographic research; must be revised if transaction costs change. |
| Production implementation and private devnet | 6–12 months | Begins only after relation and protocol interfaces stabilize; significant redesign resets work. |
| Public testnet and adversarial soak | 6–12+ months | Re-start affected soak after critical consensus/proof changes; require independent operators. |
| Independent audits, remediation, launch decision | 3–9+ months | Can partly overlap testnet; findings may reopen earlier gates. |

For a successful design, **roughly 2–4 years or longer from a properly staffed start** is a planning envelope, not a forecast; the design may never meet its gates. Reserve sustained funding for independent cryptographers, consensus and wallet engineering, external audits, public testnet grants, bug bounty, legal advice, archive infrastructure, release security, and post-launch maintenance. The people who design a critical proof or consensus rule must not be its only reviewers or approvers. Do not fund launch-critical work on an assumption of future token price or pre-sale proceeds.

## 5. Gated roadmap

Phases can overlap, but a later gate cannot be declared passed by schedule alone. Each gate produces public artifacts and has a stop condition.

### Gate 0 — Charter, requirements, and threat model

**Status (2026-10-31):** Owner approved the charter in conversation; approval is recorded in [Radix-Gate-0-Charter.md](<Radix-Gate-0-Charter.md>). The owner-approval portion is complete. Qualified legal review remains open, so Gate 0 is not fully closed; this does not block non-value Gate 1 research. No legal opinion or launch authorization is implied.

**Purpose:** make the intended coin and its threat model explicit before more cryptographic engineering.

**Work**
- Define users and adversaries: passive chain observer, quantum-capable attacker, malicious recipient, wallet malware, dishonest miner, majority-hashpower coalition, censored/eclipsed node, compromised build/release, and hostile archive.
- Define privacy goals separately: amount confidentiality, spend anonymity, recipient privacy, unlinkability, network privacy, wallet-scan privacy, and what each leaks. Do not collapse them into “private.”
- Write the meaning of “post-quantum” per layer, assumptions, acceptable residual risks, and emergency migration policy.
- Decide whether permissionless PoW is a firm requirement; define participation/accessibility objectives without promising ASIC resistance or profitability.
- Set a non-custodial distribution policy: no hidden premine or privileged issuance; if any initial allocation is proposed, disclose recipient, amount, vesting, purpose, and effect on supply before code/genesis.
- Obtain legal advice for the project, protocol distribution, public communications, privacy claims, open-source releases, and any foundation/company/fundraising structure.

**Exit artifacts:** signed-off requirements, explicit non-goals, attacker model, claims/assumptions table, initial distribution principles, and written kill criteria. Publicly state that prototype tokens have no promised value. The charter and owner approval are recorded in [Radix-Gate-0-Charter.md](<Radix-Gate-0-Charter.md>); the remaining Gate 0 action is qualified counsel's review of intended activities/jurisdictions before public launch, distribution or value-bearing activity.

### Gate 1 — Formal protocol and Candidate-A cryptographic feasibility

**Purpose:** convert the relation into an exact construction and determine whether it is worth building further.

**Work**
- Complete all byte encodings, tags, field order, malformed-input behavior, key validation, nonce rules, proof public inputs, output lengths, and consensus-visible state transitions.
- Compare and pin a prototype STARK/FRI implementation candidate. Define AIR/circuit constraints for hashing, KEM, AEAD, tree membership, openings, U64 ranges, 69-bit balance, and carries. Specify the Fiat–Shamir transcript; the current fork-context decision is that the proof binds chain/version/anchor/root, while consensus `AnchorOK` supplies branch applicability, not a candidate-fork ID.
- Model security games for completeness, knowledge soundness/extraction, zero knowledge, commitment binding/hiding, nullifier pseudorandomness, recipient discovery/key privacy, and chosen-ciphertext/forgery behavior. Account for QROM, multi-target use, composition, grinding, and all public leakage.
- Model the accepted-tree invariant, branch-relative anchor validation, nullifier and commitment uniqueness, reorganization behavior, mint issuance, and genesis/migration state as a deterministic transition system.
- Design independent cryptographer reviews early enough to affect the architecture. An AI or internal desk review is not a substitute.

**Benchmarks:** build a non-value prototype and publish reproducible measurements for proof creation time, peak RAM, proof size, verifier time, output bytes, wallet scan throughput, full-node validation throughput, and initial sync on clearly stated low-, mid-, and high-spec commodity hardware. Test worst-case input/output counts and malformed-proof DoS costs. Compare end-to-end privacy designs, not isolated primitive or paper headline sizes.

**Exit criteria:** reviewers can state exactly what is proved and under what assumptions; implementation and relation agree; security parameters have a reproducible analysis; and measured proof/wallet costs meet thresholds set *before* the results are known. Implement and test the fixed-length memo format, resolve recipient key privacy, and freeze block-fee/resource bounds. The fork-context choice is recorded in the Gate 1 feasibility log: no fork ID in the proof statement; branch applicability is consensus-side. If any critical criterion fails, redesign, select a separately reviewed alternative, or stop. No mainnet approval at this gate.

**Progress (2026-10-31):** Candidate A remains a non-value feasibility baseline; Gate 1 is not passed. The public-statement/fork-context contradiction is resolved at the specification level. The workspace now has an executable Python reference package for strict framing and experimental-v1 wire codecs, SHAKE256 formulas, variable-v1 and separately unactivated fixed-padding memo payloads, pinned `cryptography==50.0.2` ML-KEM-768 keygen/encapsulation/decapsulation and AES-256-GCM concrete adapters with the specified v1 KDF/AAD composition, wallet key generation, canonical 12-bit ML-KEM public encoding and keypair consistency checks, encrypted Scrypt/AES-GCM keyfile save/restore, address serialization, and real-provider note creation/recovery/scanning, a bounded legacy wallet scan-chunk helper with caller-asserted positions plus an authenticated-output scan helper and cursor method that check each output index/leaf against a caller-trusted root, optionally enforce a leaf-count bound for that same checkpoint, lock the cursor to legacy or authenticated mode on its first successful scan, pin an authenticated cursor to its root/count pair, and reject later mode/checkpoint changes, advance only on success, and expose immutable cursor snapshots for caller-managed persistence (restoring local state does not authenticate its checkpoint; root/count authentication and range/source completeness remain external), explicit experimental-v1 memo-length leakage (fixed padding remains unactivated), and a bounded process-local and SQLite-persistent key/nonce reuse guard (WAL/FULL, committed before encryption; old-database rollback remains undetectable), a `secrets`-backed entropy boundary for note material, the sparse depth-64 output tree with reserved empty-leaf rejection, exact integer balance/branch-relative anchors, and an atomic ordered transfer-plus-mint state transition with mandatory injected proof/mint verifier callbacks, detached pre-callback transfer/mint records and selected-ancestry snapshots, plus a mint-total range check against the 1–16 nonzero U64 output limits; uniqueness maps require genesis replay because the header authenticates only the output-tree root; and an exact integer evaluator and cumulative-supply function for the draft's illustrative tail-emission proposal. The transition never mutates its input state on failure; subsidy, aggregate-fee cap, transfer-count cap, and proof relations remain caller-supplied rather than frozen consensus parameters, and the emission proposal is not selected or wired into consensus. One hundred two pytest tests pass, including isolated transfer/mint, selected-ancestry, and full wallet scan-chunk snapshots against callback mutation and integer-only provisional subsidy and cumulative-emission vectors (tail at epoch 9,693 / height 6,978,960; still policy-only), ML-KEM key-generation shape checks and spend/KEM wallet-key assembly, bounded wallet scan chunks with auth-failure skipping, absolute-position tracking and fail-closed malformed/provider behavior, deterministic fake-provider note creation followed by recovery of the retained opening and nullifier, invalid-input/entropy failure checks before KEM use, entropy-source contract/failure tests, adversarial crypto-provider checks for derived KDF/AAD and note recovery (nullifier derivation, auth rejection, backend failure, commitment mismatch, and callback-time mutation of caller-owned records), atomic process-local AES-GCM key/nonce reservation (duplicate, failed-encryption burn, capacity exhaustion, and concurrent calls), parent-state/header-root binding, Merkle node-map integrity, malformed and mutated header-field rejection, output-leaf binding, defensive ledger snapshots, a read-only public leaf count, non-empty mint shape, exact tuple-vector enforcement, direct output-field validation resistant to shadowed methods, and canonical transfer normalization before verifier callbacks. Both prior standalone Gate 1/reference-vector scripts pass; new codecs also round-trip the frozen experimental-v1 fixture bytes exactly. This is model evidence only: no concrete KEM/AEAD backend, STARK/FRI, complete wallet, persistent node, PoW, or full network exists; only a note-recovery primitive is present. A pinned Plonky3 prototype benchmark candidate and Winterfell control have been identified, but no library has been built or benchmarked and no proof system is selected. Recipient privacy, end-to-end ZK/QROM security, proof cost, complete wire/profile choices, and monetary/resource rules remain open; independent reviews are not a prerequisite for continuing this non-value implementation track, but no security or launch claim is supported without evidence. See [Radix-Gate-1-Feasibility-Log.md](<Radix-Gate-1-Feasibility-Log.md>) and the [reference-core README](<README.md>).

### Gate 2 — Consensus, PoW, and monetary-policy freeze candidate

**Purpose:** prove that the public ledger has deterministic, bounded rules and a credible security budget.

**Work**
- Specify header serialization, chain/network ID, timestamp rules, proof-of-work hash/seed schedule, target comparison, difficulty retarget, cumulative-work fork choice, target clamps, integer arithmetic, coinbase maturity, anchor age, and activation/version behavior.
- Benchmark the provisional upstream RandomX candidate unchanged. Pin an upstream version only for experiments; verify reference vectors, test seed changes/reorg boundaries, initialization cost, memory requirements, verification cost, low-end CPU participation, energy use, pool concentration, and ASIC/FPGA risks. Compare alternatives openly. Never describe one candidate as guaranteed ASIC-proof.
- Simulate hashrate additions/exits, pool capture, selfish mining, timestamp manipulation, time-warp, long-range histories, majority/reorg attacks, eclipse conditions, and transaction censorship. Publish model code and assumptions.
- Select and justify issuance: hard cap versus tail emission, initial subsidy, epoch schedule, fee treatment, coinbase maturity, genesis allocation, and exact rounding. The current 120-second/10 RAD/tail proposal is not selected.
- Bound per-block transactions, aggregate fees, subsidy, mint outputs, proof work, serialized bytes, and validator resource use with checked wide arithmetic. Define supply invariant and publish long-horizon simulations under low-fee and high-fee scenarios.
- Define upgrade governance: explicit versions/activation, review period, testnet signal, failure recovery, no silent cryptographic changes.

**Exit criteria:** independent implementation of consensus test vectors produces identical results; state machine has no unbounded or ambiguous arithmetic; chain selection is deterministic; issuance has a proved/checked bound and supply account; resource caps and attack models are published. Mining remains provisional until end-to-end testnet data.

### Gate 3 — Reference implementation and private development network

**Purpose:** implement a vertical slice without monetary value.

**Components**
- Canonical serialization library plus independent parser and test vectors.
- Consensus state machine with tree, nullifier map, commitment uniqueness, fee accounting, mint transition, reorg handling, and deterministic chainwork.
- Prover/verifier using only the selected audited candidate construction; no handwaved “proof stub” accepted in performance or security claims.
- P2P full node, miner/reference miner, archive mode, pruning experiment, wallet/key derivation, note scanning, transaction builder, recovery/import, and local testing tools.
- Deterministic build pipeline, dependency/SBOM inventory, code signing/release-key governance, secure update process, and crash/telemetry privacy policy.

**Tests**
- Unit and differential tests; property-based and coverage-guided parser/circuit fuzzing; malformed KEM keys, ciphertexts, proofs, ranges, lengths, and ordering; integer overflow/underflow and duplicate tests.
- Model-check concurrent spends, ordering, orphaned branches, stale/future anchors, root collisions/equality cases, reorgs, reward accounting, and checkpoint/snapshot flows.
- Cross-implementation vectors for proof verification, state roots, mining headers, and wallet recovery. Any disagreement is a consensus blocker.
- Side-channel, memory-safety, dependency, build-reproducibility, and secret-handling review.

**Exit criteria:** independent clean-room nodes reach the same state from genesis and adversarial block sequences; wallets recover across supported platforms; no central server is required for ordinary use; no unresolved critical correctness issue. No transferable real-value coins.

### Gate 4 — Public testnet and adversarial operations

**Purpose:** expose the protocol and operations to untrusted users and hostile conditions.

**Duration:** keep the public testnet active long enough to cover software upgrades, significant reorgs, hash-rate shocks, spam, wallet restores, and multiple independent operator groups; use evidence-based duration rather than a ceremonial date.

**Program**
- Publish testnet source, parameters, binaries, miner/node/wallet documentation, reproducible builds, explorer APIs, archive interfaces, known limitations, and a vulnerability reporting channel.
- Recruit independent miners, solo miners, pools, full nodes, low-bandwidth/pruned nodes, archives, wallets, and researchers. Ensure mining does not require a project-operated pool or approval.
- Run adversarial exercises: proof spam, large public output sets, nullifier races, key-scanning attacks, reorgs across anchors, withheld ciphertext data, archive failures, eclipse/sybil/partition, extreme block load, mining concentration, difficulty lag, and upgrade rollback.
- Measure actual node storage/bandwidth, bootstrap time, wallet scan time, proving costs, relay delays, mining hardware distribution, and archive redundancy. Publish regular dashboards and raw datasets.
- Operate a bug bounty whose scope includes protocol, circuit, consensus, wallets, P2P, build infrastructure, and key management. Patch through public releases; restart affected soak periods after consensus-critical changes.

**Exit criteria:** multiple independent teams can reproduce the network; no unresolved critical/high vulnerability; consensus and supply invariants survive adversarial testing; data recovery and availability work without a single operator; user accessibility tests pass against predeclared metrics. A quiet testnet is not sufficient.

### Gate 5 — Independent review and mainnet decision

**Required before a value-bearing launch**
- At least two independent cryptographic reviews of the exact pinned proof construction, relation/AIR, reductions, transcript, QROM and composition analysis; one reviewer must not be a vendor or author of the implementation being reviewed.
- Independent consensus/economic review of PoW, difficulty, reorg/fork choice, issuance, supply invariant, bounds, and attack simulations.
- Independent implementation audits of node, wallet, miner, parser, networking, cryptographic code, reproducible builds, and upgrade mechanisms.
- Public review window, remediation evidence, retest of every critical/high issue, and a funded incident-response plan. No unresolved consensus-critical bug or unexplained divergence.
- Reproducible release artifacts, pinned parameters and dependencies, published privacy/leakage table, security assumptions, threat model, node requirements, wallet recovery instructions, and limitations.
- A mainnet readiness vote/decision under a predeclared governance process. Record dissent and residual risk; do not allow marketing or exchange readiness to override a failed security gate.

If the proof is too slow or its security proof incomplete, **do not launch it with real value**. Continue testnet research, change the design and restart affected gates, or terminate the effort. Do not switch to a weaker proof while keeping the same claims.

### Gate 6 — Fair, permissionless launch

**Launch checklist**
- Publish the final source, consensus parameters, genesis block/hash, initial state, exact mining start time, release binaries, checksums, reproducible build instructions, and independent audit reports well before mining begins.
- No secret pre-mining, private genesis allocation, privileged block validation, hidden admin key, or special founder difficulty window. If the policy allows any premine/treasury, make it explicit and independently verifiable before genesis.
- Run genesis generation transparently with independent observers; have multiple unaffiliated operators verify the same genesis and first blocks.
- Enable independent full nodes, archives, solo miners and decentralized-pool alternatives. Publish safe bootstrap paths and let users verify from genesis. Project-operated infrastructure may help but cannot be the only path.
- Start with conservative transaction/block resource limits derived from benchmarks; monitor congestion and proof-verification costs. Any limit change uses the public upgrade rules.
- Explain confirmation risk, probabilistic finality, privacy leakage, backups, wrong-address risks, and lack of guaranteed market value in user-facing material.

Launch is not the end of review. Pause deposits/transactions or activate a predesigned emergency procedure if a consensus-breaking proof, inflation bug, key compromise, or serious chain split is discovered. Emergency authority, thresholds, and safe recovery must be documented before launch.

### Gate 7 — Long-term operation and decentralization

- Keep protocol maintenance, audits, release engineering, bug bounty, and independent test infrastructure funded transparently.
- Track miner/pool concentration, node and archive diversity, peer connectivity, bandwidth/storage growth, wallet scan cost, proof failures, censorship, reorg depth, and software-version concentration.
- Maintain at least two independent compatible implementations or a tested independent verification implementation where feasible; preserve canonical test vectors and a public conformance suite.
- Review issuance and security budget against measured fees and hashrate. Do not change monetary policy reactively without a public simulation and explicit upgrade process.
- Publish yearly threat-model and privacy reviews, including quantum-progress and cryptanalytic changes. If assumptions weaken, activate a previously designed migration; do not improvise wallet migration after an exploit.
- Keep archives and wallet recovery usable for users returning years later. Test restoration from paper/seed backup on clean devices.
- Support merchants, explorers, wallets, and exchange integration without making any one custodian necessary. Market volatility and adoption are not engineering acceptance criteria.

## 6. Proposed evaluation thresholds: define before measuring

Do not cherry-pick benchmarks after seeing results. Before Gate 1 prototypes are benchmarked, publish a table of minimum and target requirements for:

- wallet proof-generation time, peak RAM, failure rate, and device battery/thermal impact;
- node proof-verification time, worst-case block validation time, RAM, storage, sync bandwidth, and initial-sync duration;
- transaction and proof size, outputs per byte, KEM scan throughput, and restore-from-backup time;
- minimum supported miner hardware, memory/CPU needs, validator cost, energy estimates, and pool/miner concentration;
- annual chain growth, archive cost, data replication, block propagation and reorg behavior;
- privacy tests under chain-only and network-observer models, including memo length and recipient key testing;
- fee/weight policy, monetary supply bounds, and worst-case DoS cost per unit of attacker spend.

For each metric, publish the hardware, software version, configuration, sample size, median and tail percentiles, and reproducible scripts. If criteria are revised after results, explain why and rerun comparisons. Public access includes low-bandwidth and modest-device users; measure it rather than asserting it.

## 7. Immediate 30/60/90-day plan

### First 30 days
1. Freeze feature scope and publish the definitions of access, mining, ownership, privacy, and post-quantum claims.
2. Turn open blockers above into a decision register with owner, evidence needed, deadline, and stop condition.
3. Commission independent scoping from a ZK/STARK cryptographer and a PoW/consensus engineer; this is not yet a full audit.
4. Write the Candidate-A security games, privacy/leakage matrix, exact proof public inputs, and consensus-state transition diagram.
5. Set pre-benchmark hardware profiles and usability/performance targets; do not tune target thresholds after seeing results.
6. Decide whether the project has enough funding and expert capacity to pursue the next research gate; otherwise pause before code creates sunk-cost pressure.

### By day 60
1. Produce a draft exact transaction/AIR interface, frame and key-validation spec, fork-context decision, mint-fee bound proposal, and genesis/supply invariant.
2. Build or refine a tiny non-value reference model for tree membership, nullifiers, output parsing, integer balance, anchor validation, and reorg behavior.
3. Specify the RandomX study and alternative-comparison methodology, including benchmark machines, test vectors, difficulty simulations, and pool-concentration measures.
4. Publish the preliminary legal/governance structure and transparent funding/distribution policy.
5. Start the KEM/AES/hash-in-circuit prototype only after the exact relation and instrumentation plan are agreed.

### By day 90
1. Deliver the first reproducible feasibility measurements for the complete Candidate-A proof workload, not a hash-only microbenchmark.
2. Deliver a written independent cryptographic scoping memo identifying proof-system selection needs and fatal design concerns.
3. Deliver consensus simulations for hashrate shocks, timestamp attacks, retargets, cumulative work, reorgs, and provisional issuance.
4. Decide explicitly: proceed to Gate 1 completion, redesign the output/discovery/proof architecture, investigate Candidate B as a separate reviewed protocol, or stop. Do not issue a “mainnet soon” promise based on a testnet prototype.

## 8. Principal risks and stop conditions

| Risk | Why it can stop the project | Required response |
|---|---|---|
| Candidate-A proof too expensive | Wallets cannot spend promptly or full nodes cannot validate within accessible resource limits. | Redesign the relation/output construction or stop; never silently centralize proving or validation without revising the access promise. |
| No defensible soundness/ZK/QROM argument | A bug may enable counterfeit value, theft, or spend linkage. | No value-bearing launch; commission review, repair, and restart the relevant gates. |
| KEM recipient testing or address linkability | Public ciphertexts may expose recipients and damage the stated privacy model. | Define key privacy/scanning threat model; change discovery/encapsulation and prove/test the new relation. |
| PoW centralizes or is easy to attack | A small coalition can censor, reorg, or destabilize the chain. | Compare algorithms and economics; change chain design before launch or stop. “ASIC-resistant” is not an acceptance argument. |
| Data unavailable or chain growth excessive | Users cannot restore notes, new nodes cannot sync, and privacy can fail through remote scanning. | Reduce data cost with reviewed design changes, fund independent archives, or revise the access target transparently. |
| Supply/fee width or state transition ambiguous | Overflow, duplicate state, or mint bugs can inflate supply. | Freeze bounds and formalize checked transitions before public value. |
| Governance or key compromise | A release authority can become a de facto central administrator. | Minimize authority, use reproducible builds and multi-party public process; disclose remaining trust. |
| Legal or operational constraints | A technically open protocol may still create legal risks for developers or services. | Obtain jurisdiction-specific counsel; do not promise global legal availability. |

## 9. Definition of “ready”

The project is ready to consider a public, value-bearing launch only when all of these are true:

- Any person can inspect, build, run, and independently verify the software and chain rules without an account or project server.
- Any person can create a self-custody wallet and recover it from the documented backup; the privacy and key-ownership semantics have been reviewed and tested.
- Any person can mine through public software and independently validate the chain; mining distribution and resource costs are measured and honestly disclosed.
- The exact proof relation, circuit, transcript, security assumptions, and end-to-end security bounds are pinned, publicly reviewed, and no longer benchmark-only.
- Supply, fees, issuance, nullifier/commitment state, anchors, reorgs, and fork choice are deterministic, bounded, cross-implemented, and tested.
- Data needed for wallet recovery is durably available from multiple independent sources; fresh nodes can verify state under the published trust model.
- Independent reviews and public testnet have found and resolved critical issues; launch binaries are reproducible and incident response is ready.
- Residual risks are published in plain language, and no claim is made of guaranteed anonymity, guaranteed equal mining, guaranteed returns, or “quantum-proof” security.

If one item is missing, the honest status is “research/testnet,” not “secure cryptocurrency.”

## 10. Decision requested before executing the roadmap

This plan assumes **permissionless PoW is a requirement** because the goal explicitly includes mining, with upstream RandomX only as a candidate to test—not a final choice. Before Gate 2, the project should confirm that preference, approve the distribution/funding principles, and resource independent cryptographic and consensus expertise. Nothing else in this plan commits the project to the experimental monetary parameters or proof knobs in the current research documents.
