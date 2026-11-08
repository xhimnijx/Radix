# Radix Gate 0 — project charter, requirements, and threat model

**Version:** 1.0-draft  
**Prepared:** 2026-10-31  
**Status:** Owner approval of this research charter was given in conversation on 2026-10-31. Qualified legal review remains outstanding; this is not legal advice, a security certification, or a launch authorization. Approval authorizes continued research under these principles, not binding project, legal, or economic commitments.  
**Project name:** “Radix” is a temporary codename only. “Radix” and “XRD” are already associated with an existing crypto project; do not use them as a launch brand/ticker without legal and ecosystem-confusion review.

## 1. Charter and intended outcome

The project is a research effort to determine whether a **permissionless, self-custodial, privacy-preserving cryptocurrency** can be built with defensible post-quantum assumptions. The user’s stated intent is broad public access, the ability to mine, and individual ownership/control. This charter translates that intent into testable requirements without promising equal mining rewards, profit, anonymity in every setting, legal availability everywhere, or quantum-proof security.

The immediate outcome is **a non-value research/test network**, if and only if the cryptographic, consensus, implementation, and legal gates later permit one. A public, transferable, value-bearing mainnet is outside the present authorization. No prototype balance or token has promised value.

### 1.1 Core product requirements

| ID | Requirement | Acceptance evidence required before launch |
|---|---|---|
| P-01 | Permissionless participation: no protocol whitelist, required account, issuer, or central API to create keys, validate, receive, or construct a spend. | Clean-room node and wallet setup from public source; protocol tests show no hidden allowlist or issuer authority. |
| P-02 | Self-custody: spend authority is held by the user; no operator can freeze or seize notes or create balances outside consensus. | Threat-model review, key custody review, and state-transition tests; no privileged mint/freeze key in code or genesis. |
| P-03 | Privacy by default is the target, with amount confidentiality, spend unlinkability, and recipient privacy separately specified. | Public leakage table; cryptographic definitions and attacks for each property; independent review. No generic “anonymous” claim. |
| P-04 | Post-quantum design objective for transaction authorization, recipient discovery, commitments/nullifiers, and proof system. | Every layer has explicit assumptions, parameters, quantum-model analysis and composition review. No ECC fallback under a PQ label. |
| P-05 | Public verifiability: independent nodes validate issuance, proofs and state transitions without trusting a project checkpoint or hosted verifier. | Deterministic consensus vectors; independent implementation; bootstrap path with genesis verification or a separately reviewed trust-minimized proof path. |
| P-06 | Permissionless PoW mining is the working requirement because mining is part of the stated goal. | Anyone can run a reference miner without project approval; solo mining tested. Hardware fairness/profitability is not guaranteed. Exact PoW remains a later gate. |
| P-07 | Historical data required for wallet recovery and verification has a documented availability/retention model. | Archive protocol and independent operators; restore/scan tests; documented effects of pruning and unavailable data. |
| P-08 | Open and accountable protocol changes. No silent cryptographic changes or unilateral administrative balance powers. | Public versioned specifications, activation/review process, reproducible releases and incident procedures. Governance mechanics remain a later decision. |
| P-09 | Conservative, transparent distribution. Proposed default: zero premine, zero founder/insider allocation, zero treasury allocation, and no presale/ICO. Initial distribution only through a publicly specified consensus issuance schedule, if later approved. | Genesis and supply audit; exact issuance, recipients and any exception disclosed before implementation/genesis. This proposed default requires owner ratification. |
| P-10 | No investment or return promise. | Public materials state no guaranteed value, profitability, privacy against all observers, finality, or legal status. |

### 1.2 Explicit non-goals and limits

The project does not promise:

- equal mining rewards, ASIC resistance, profit, or resistance to all forms of specialized hardware;
- protection against compromised endpoints, malicious wallet software, coercion, key theft/loss, or a user voluntarily revealing their keys;
- network-layer anonymity against global traffic observation, timing/IP correlation, eclipse, partition, or an adversary controlling a wallet's peers;
- that every recipient can be hidden if the chosen discovery protocol leaks keys, ciphertext-recipient links, or scan behavior;
- deterministic finality under pure PoW; confirmations are probabilistic and reorg risk depends on hash power and network conditions;
- legal availability in every jurisdiction or legal conclusions without qualified counsel;
- that standardized components (e.g., ML-KEM) make the composed payment, proof, wallet, or consensus system secure.

## 2. User and operating assumptions

### Intended users

1. Individuals holding their own keys and using local or independently operated wallets/nodes.
2. Independent validators, archival nodes, miners and wallet developers, without project permission.
3. Researchers and auditors able to reproduce protocol results and challenge assumptions.

Hosted wallets, mining pools, exchanges, custodians, explorers and project-run infrastructure may exist as optional services; they must not be required for ordinary protocol use. Optional services can introduce their own legal, privacy and availability risks.

### Access and ownership policy

- Key creation and use do not require identity registration or a central service.
- A user can receive and spend without a project operator's approval.
- Losing all spend secrets may be irreversible; a recovery phrase is not a backdoor. Any view-only capability must not silently grant spend authority.
- No protocol admin key may pause, confiscate, freeze, or mint outside publicly activated consensus rules.
- The distribution plan defaults to no privileged initial balances. Any requested exception requires explicit public disclosure, owner approval, supply analysis, vesting/lockup details where relevant, and legal review before genesis.

## 3. Threat model

### 3.1 Adversary capabilities to assume

| Adversary | Capabilities included in the design/review | Important limitation |
|---|---|---|
| Passive chain observer | Records all blocks, outputs, proofs, nullifiers, amounts/fees that are public, and timing forever; combines public information across years. | Cryptographic privacy does not erase public metadata or future key compromise. |
| Active transaction adversary | Creates malformed, adaptive, duplicate, conflicting, and strategically timed transactions; probes wallet scanning and recipient discovery. | Parser, proof, relay and scan code need separate DoS and privacy tests. |
| Dishonest miner / pool | Censors, reorders and delays transactions; mines competing blocks; attempts reorgs and reward/fee manipulation. | Under PoW, sufficiently dominant hash power can reorganize history; proofs do not provide finality. |
| Hash-power coalition | Can temporarily or persistently exceed the honest mining share, including through rented/specialized hardware. | No honest-majority guarantee is unconditional. Consensus threat assumptions and attack-cost measurements must be published. |
| Network adversary | Sybil peers, eclipse, partition, delay, observe IP/timing, control a peer or relay, or withhold blocks/transactions. | Network anonymity and availability require separate design; P2P alone does not provide them. |
| Malicious/compromised wallet | Exfiltrates keys, lies about recipient/amount, creates distinguishable transactions, or leaks scans and broadcasts. | Users must be warned that wallet and endpoint compromise defeats protocol-level protections. |
| Malicious archive/provider | Withholds or alters old ciphertexts/proofs, selectively serves data, or correlates scans. | Integrity checks do not guarantee historical data availability. Need multiple independent archives and recovery tests. |
| Quantum-capable cryptanalyst | Applies known quantum algorithms to public chain data, keys, hashes, signatures, commitments, KEMs, and proof transcripts; may retain ciphertexts now for future analysis. | “Post-quantum” is an engineering objective relative to stated assumptions, not a guarantee against future algorithms or implementation failures. |
| Implementation/supply-chain attacker | Exploits dependencies, compiler/build pipeline, release keys, side channels, unsafe parsers or compromised binaries. | Mathematical security does not compensate for compromised implementations or releases. |
| Economic attacker | Spams proofs/outputs, exploits fee and resource rules, concentrates mining, or attacks availability incentives. | A relay fee floor alone does not prevent spam; consensus and local policy must be separated and bounded. |

### 3.2 Security and network assumptions

- PoW study assumes chain safety/liveness only under explicit honest-hashpower, network-delay, propagation and eclipse-resistance conditions. The familiar “less than half adversarial hash power” shorthand is not by itself a sufficient security theorem.
- Pure PoW gives probabilistic confirmation, not deterministic finality. Wallets must communicate confirmation depth and changing risk; do not define a universal safe confirmation count.
- Nodes and wallets use canonical parsers, bounded allocations and cheap checks before expensive cryptography. All proof verification and KEM/scan work is an adversarial resource surface.
- Users protect secrets and obtain software/builds through a channel whose integrity they can evaluate. No protocol guarantees safety if wallet binaries are malicious.
- Data availability is an explicit assumption: a valid commitment/proof does not recreate historical ciphertext bytes that archives withhold.

## 4. Privacy requirements and permitted claims

Privacy properties are distinct and must not be collapsed into “private.” The current architecture candidates and literature are unreviewed; no property below is yet certified.

| Property | Desired result | Known leakage / current status |
|---|---|---|
| Amount confidentiality | Hide note amounts and sender balance links while publicly enforcing range and conservation. | Fees, resource size, transaction timing and possible amount side channels may remain public. Proof relation and range bounds are not yet audited. |
| Spend anonymity / unlinkability | Hide which valid prior note was consumed; prevent linking a spend to an output except through a valid spend secret. | Small eligible set, timing, amount/fee patterns, wallet behavior, implementation side channels, and a ring design's decoy set can reduce anonymity. Candidate A/B proof is not complete. |
| Recipient privacy | Hide which address/user receives an output and avoid linkability across payments. | A KEM ciphertext is not automatically key-private; scanning or view keys may identify outputs. Candidate scan protocol is unresolved. |
| Sender/network-origin privacy | Avoid exposing the originating IP or first broadcaster through transaction propagation. | Not guaranteed by the ledger. Requires separate relay/transport work; global observers and compromised peers may correlate traffic. |
| Wallet-scan privacy | Do not reveal viewing key or scan results to remote services by default. | Local scanning is the default target, but naïve scans can be slow; optional remote scanning leaks information unless separately protected. |
| Memo/content confidentiality | Encrypt optional memo/content to the intended recipient. | Length, output count, timing and ciphertext are visible unless padded/obfuscated; padding policy is unresolved. |
| Supply integrity | No hidden inflation; validators can check all created value despite hidden amounts. | Depends on sound proof and mint relation, exact integer/carry limits, fee accounting and consensus correctness. |

### Approved public-claims posture for research phase

**May say, with context:** “researching a privacy-preserving, post-quantum-oriented cryptocurrency”; “Candidate A/B are unvalidated research designs”; “the prototype is non-value and not audited”; “privacy does not hide network metadata.”

**Must not say or imply:** “quantum-proof,” “untraceable,” “fully anonymous,” “ASIC-proof,” “guaranteed secure,” “final after N blocks,” “guaranteed equal mining,” “risk-free,” “investment,” or “legally available everywhere.” Do not describe a component's security level as the end-to-end coin's security level.

## 5. Post-quantum objective and residual-risk policy

### Objective

For any value-bearing release, require a target of at least **128-bit estimated security against the best known classical and quantum attack** for each critical security property, after accounting for concrete parameters, multi-target use, protocol composition, transcript/Fiat–Shamir effects and implementation constraints. This is a design target, not a certification. A candidate that cannot provide a defensible estimate must not be marketed as meeting it.

The review must separately analyze:

1. Key encapsulation and recipient discovery, including ciphertext/key privacy and multi-user attacks.
2. Spend authorization, one-time key/tag binding, nullifier pseudorandomness and cross-context double-spend resistance.
3. Commitment binding/hiding and hash preimage/collision security under quantum queries.
4. Proof completeness, knowledge soundness/extraction and zero knowledge in the applicable quantum model (including the QROM where Fiat–Shamir is used).
5. Amount range, integer conservation, tree/state-transition and mint-proof composition.
6. Consensus PoW against quantum search and practical hardware effects, without assuming a hash function alone makes the mining game fair.

NIST-standardized ML-KEM/ML-DSA/SLH-DSA are useful components where appropriate, but standardization of a component does not standardize anonymous credentials, ring signatures, stealth addresses, STARK composition, or a cryptocurrency. Exact current standards/errata must be pinned before implementation. If the PQ objective conflicts with feasible resource limits, pause and redesign; do not silently substitute classical cryptography.

## 6. Permissionless mining and monetary policy principles

### Working requirement

Permissionless PoW is the working consensus requirement because the stated product includes mining. This commits the research program to test PoW and solo mining—not to RandomX, a 120-second cadence, a particular target algorithm, tail emission, or any specific reward. Upstream RandomX may be benchmarked unchanged as one candidate, but no “ASIC-resistant” or “egalitarian” promise is authorized.

### Distribution / issuance default proposed for ratification

- No hidden premine, founder allocation, insider allocation, treasury mint, presale, or issuer-controlled balance.
- The proposed genesis balance is zero; any later subsidy must be generated only by the disclosed consensus mint transition after independent supply accounting and owner approval.
- Mining issuance, if adopted, is transparent and identical under published rules. Orphaned block rewards do not become spendable unless consensus explicitly defines otherwise.
- Any future allocation exception must be disclosed with recipient, amount, purpose, vesting, governance and supply effects before code/genesis; no retroactive undisclosed exception.
- Development funding should be sought through separately disclosed grants/donations/contracts, not assumed token value or an undisclosed protocol allocation.

These are conservative proposed principles based on the stated goal of public ownership. They are not considered accepted until the owner records approval.

## 7. Governance, legal, and operational boundaries

- Research artifacts may be published as open-source documentation/code after license and safety review. A public non-value testnet, test coins or public token distribution still requires a separate risk/legal review and clear no-value messaging.
- No legal jurisdiction, entity, foundation, fundraising plan, service provider or launch location has been specified. Obtain qualified counsel in relevant jurisdictions before public fundraising, token distribution, exchange listings, commercial launch, or claims about privacy/legal status. No legal opinion has been obtained for this charter.
- Trademark, domain, ticker and confusion review is required before adopting “Radix” or “XRD.” Continue using it only as an internal codename pending that review.
- Governance must not let one person/entity silently change consensus or balances. Exact upgrade thresholds, activation mechanisms, emergency response and rollback require later public design and independent review.
- No monetary value, exchange listing, investment return, or guaranteed utility is promised for any prototype.

## 8. Kill / pause / redesign criteria

Stop the current design or keep it research-only if any of these holds:

1. Independent experts cannot state a credible security argument for ownership, nullifier uniqueness, private membership and hidden-amount conservation under the selected assumptions.
2. A required layer lacks a defensible ≥128-bit estimated classical/quantum security margin after parameter selection and composition, or a new attack materially weakens it.
3. Recipient discovery/key privacy cannot be demonstrated or metadata leakage invalidates the stated privacy goals.
4. Proof generation, proof size, wallet scanning, verification or chain growth exceed predeclared commodity-device/resource limits, or create a practical validation/scan DoS vector that cannot be bounded.
5. Consensus permits hidden inflation, duplicate spends, ambiguous state transitions, unbounded arithmetic, or inconsistent independent implementations.
6. Practical permissionless mining requires a trusted operator, or adversarial simulation shows intolerable capture/reorg risk without a credible mitigation. Do not address this by making unjustified ASIC-resistance claims.
7. Security depends on users trusting a central party, secret setup, issuer mint key, unreviewed checkpoint, or unavailable archive without an explicit redesign and approval.
8. Independent review finds critical/high-severity issues that are unresolved, or the project cannot fund independent review, incident response and public-testnet operations.
9. Qualified counsel identifies a material unresolved risk for the intended jurisdictions/activities, or the project cannot communicate legal and privacy limitations honestly.
10. The project must market the coin as more secure, private, quantum-resistant, final, fair, or valuable than evidence supports.

A failed gate means pause, redesign, narrow the claims, or stop. It does not authorize a quiet classical fallback or public token launch.

## 9. Owner decision register and Stage 0 exit

| Decision | Proposed default for this research plan | Status |
|---|---|---|
| Product intent | Permissionless, self-custodial, privacy-preserving currency research | Inferred from user's stated goal; owner confirmation/sign-off required. |
| Mining | Permissionless PoW research requirement; no algorithm selected | Inferred from stated wish that people mine; Gate 2 must decide final consensus. |
| Privacy | Amount/spend/recipient privacy as separate targets; no network-anonymity guarantee | Proposed; requires owner acceptance of leakage/non-goals. |
| PQ target | At least 128-bit estimated classical and quantum security for critical properties, subject to review | Proposed engineering target; no candidate currently shown to meet it end-to-end. |
| Initial distribution | Zero premine/insider/treasury allocation; transparent mining issuance only if approved | Recommended default; owner ratification required. |
| Monetary schedule | No schedule approved; current numbers are experiments only | Deferred to Gate 2. |
| Brand | “Radix” internal codename; no XRD ticker use | Pending trademark/ecosystem-confusion review. |
| Legal jurisdictions/entity/funding | None selected | Counsel and owner decisions required; no legal advice obtained. |
| Prototype token | No promised value; no value-bearing mainnet authorized | Current research constraint. |
| Governance/upgrade rules | Public, versioned, non-unilateral changes; exact mechanism deferred | Principle proposed, mechanism deferred. |

### Stage 0 artifacts now prepared

This document supplies a proposed charter, testable requirements, attacker model, privacy/leakage boundaries, PQ objective, distribution principles, public-claims policy, and kill criteria. The related research, protocol, and Gate A documents are not substitutes for owner approval or legal advice.

### Stage 0 status: owner-approved; legal review pending

The owner approved the charter and decision register in conversation on 2026-10-31. This records authorization to continue research under these principles; it is not a cryptographic signature or authority to make binding legal/economic commitments. Qualified counsel still needs to review relevant jurisdictions and intended activities. Therefore the owner-approval portion of Gate 0 is complete; the legal-review exit item remains open. No downstream technical gate is passed by this document.

**Owner approval record (recorded from conversation):**

- [x] I accept the product intent and non-goals in §§1–2.
- [x] I accept the privacy limits and prohibited claims in §4.
- [x] I accept the proposed PQ security target and acknowledge that no current candidate has demonstrated it end-to-end.
- [x] I accept the zero-premine/zero-insider/zero-treasury proposed default in §6, or attach a fully disclosed alternative.
- [x] I accept permissionless PoW as a research requirement, not a final algorithm/launch decision.
- [x] I accept that prototype tokens have no promised value and that no mainnet is authorized.
- [x] I understand qualified legal review is still required and this document is not legal advice.

Owner/signatory: Maxim Gil  Date: 31/10/2026
