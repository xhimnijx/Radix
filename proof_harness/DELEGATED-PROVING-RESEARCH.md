# Research note: delegating Radix transaction proving

**Status:** feasibility study only; no prover service or consensus change is implemented.

## Bottom line

Outsourcing proof generation is a real cryptographic direction, not a free privacy-preserving optimization. A client can hand a complete witness to a miner and have that miner prove, but this directly gives the miner the spend secrets/openings and breaks the intended privacy boundary. A privacy-preserving outsourcing protocol or secure multiparty computation (MPC) could in principle let workers share computation without any one worker learning the witness. I found relevant academic work on privacy-preserving outsourced proof generation, but it targets trusted-setup zk-SNARKs; it is not evidence that this custom, hash-based Radix RDXL proof can be securely or efficiently outsourced.

**Recommendation:** do not send complete Radix witnesses to miners and do not advertise miner proving as anonymous or quantum-safe. A concrete threshold/MPC design proposal now exists in [`THRESHOLD-MPC-PROVER-DESIGN.md`](THRESHOLD-MPC-PROVER-DESIGN.md); it is a specification artifact, not an implemented or security-proven protocol. A complete local wallet prover is also not implemented here; once it exists and meets the resource budget, local proving is the privacy-preserving default. If a future protected-outsource design succeeds, workers could be paid, but their role and any fee share must be consensus-defined and independent of transaction validity.

## What the literature establishes (and does not)

- Nakamura, Miyamae, and Morinaga, [“A Privacy-preserving Outsourcing Scheme for Zero-knowledge Proof Generation”](https://doi.org/10.2197/ipsjjip.30.151), proposes a privacy-preserving worker for proof generation and reports applicability to **zk-SNARKs with a trusted setup**. Its abstract says the worker's computational and memory load is almost the same as the prover's. This establishes that protected single-worker outsourcing has been studied; it does **not** establish compatibility with Radix's transparent STARK, post-quantum security, safe worker/miner behavior, or lower resource requirements. The accessible abstract does not provide enough detail to transplant its protocol here.
- Lindell's [MPC survey](https://eprint.iacr.org/2020/300) describes MPC's goal as computing over private inputs while revealing only the output. This is the right general model for a set of workers jointly evaluating a prover, but MPC is a protocol family, not a drop-in switch: the security model, corruption threshold, malicious behavior, dropout, communication, and cryptographic assumptions all matter.
- [ZKBoo](https://eprint.iacr.org/2016/163) is a useful example of “MPC-in-the-head” zero knowledge. It is **not** a distributed miner-proving service; using MPC as a technique inside a proof and splitting a live prover among untrusted workers are distinct constructions.
- The original [STARK computational-integrity paper](https://eprint.iacr.org/2018/046) describes a transparent, hash-based STARK design as post-quantum secure under its assumptions. That is not a post-quantum security proof for this repository's custom RDXL profile or for a proposed MPC wrapper.
- NIST [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) standardizes ML-KEM and says its security is believed to hold against quantum adversaries, based on Module-LWE. That property does not automatically carry to the whole transaction, STARK, MPC, network, or wallet.

## Candidate architectures

### 1. Directly pay one miner to prove (reject for privacy)

The wallet sends the witness and statement to a miner; the miner returns a proof. This is the simplest workload transfer, but a miner that receives the full note opening can learn spend authority and link the spend to the submitted transaction. Transport encryption protects only the connection, not the miner endpoint. A later proof does not undo disclosure. Payments, worker identity, request timing, source IP, and retries add correlation signals.

### 2. Privacy-preserving single-worker outsourcing (not yet a Radix candidate)

A special protocol could blind/transform a witness and let one worker do nearly all proving work without learning the secret, with the wallet validating the response. The cited outsourcing paper shows this line of research exists, but its stated target is trusted-setup zk-SNARKs. RDXL is a different transparent STARK-style construction, so adapting such a protocol would require a new security reduction and a concrete implementation. It must also prevent a worker from substituting malformed data, learning secrets through repeated/adaptive queries, or withholding results.

### 3. Threshold/MPC proving (plausible research direction; high uncertainty)

The wallet could secret-share witness material among independently operated workers, and they could jointly execute a malicious-secure prover so the final proof is publicly verifiable while fewer than a defined threshold of workers learn nothing about the witness. The design must specify at least:

- exactly which values are shared (including the input KEM shared secret, note opening, spend secret, path/witness data, and prover randomness), versus public statement fields;
- an explicit collusion threshold and active/malicious security, including cheating, abort, selective failure, replay, and adaptive-query handling;
- a post-quantum security basis for **every** MPC primitive (no unreviewed reliance on classical DH, pairing, or discrete-log assumptions), plus a quantum-aware analysis of the proof transcript;
- how private field/arithmetic work, hashing, commitments, FFT/LDE, FRI, and transcript challenges are distributed without opening witness-dependent intermediate values;
- authenticated worker selection, message integrity, denial-of-service recovery, and a way for the client to reject invalid output locally;
- metadata protections (anonymous submission/relay, batching or delay policy, no stable worker-user correlation) and a stated network adversary model.

A threshold only protects against a bounded colluding set. If enough workers collude, or the wallet endpoint is compromised, privacy is lost. Zero-knowledge of the final public proof does not by itself protect the witness from the entities that ran the prover.

## Resource and fee implications for this repository

Current RDXL static dimensions are `8,192 × 14,477` trace, `16,384 × 14,481` randomized matrix, and `65,536 × 14,481` LDE after overlaying key-schedule S-box input, output, and witness columns with the corresponding CTR-block bank on mutually exclusive rows. The LDE payload alone is estimated at `3,796,107,264 B` (`3.536 GiB`); the hypothetical randomized-matrix-plus-LDE overlap is `4.419 GiB` (`4,745,134,080 B`), still above the conservative `4 GiB` desktop per-process cap. These are payload estimates, not measured peak RSS or time. Prior GNU measurements for smaller profiles were about `5,875 MiB` (RDXS) and `9,518 MiB` (RDXJ), not RDXL or mobile measurements. Moving the same prover to one miner transfers the burden; it does not lower the burden. MPC may reduce each worker's private memory, but adds communication, storage, synchronization, and cryptographic overhead; no scaling factor or fit to the `≤1 GiB` mobile app / `≤4 GiB` desktop proof-process budgets has been established.

A fee-funded market is possible as a **consensus design**, not just a wallet setting: transaction fees could explicitly split into a prover bounty and the ordinary block fee, payable only after inclusion and proof verification. Rules must say how a worker's claim is bound to the transaction without making it front-runnable, and handle failed/withheld work, duplicate jobs, invalid submissions, worker collusion, fee sniping, and Sybil identities. Payment can reward service but cannot create witness privacy or proof soundness. A visible worker payout address can itself add linkability; concealing it requires further payment machinery and analysis. Any such fee split changes protocol economics and requires a separate specification and adversarial analysis.

## “100% anonymous and quantum safe” is not a supportable guarantee

No design can honestly promise absolute anonymity against every endpoint compromise, worker coalition, traffic-analysis capability, or future attack. A defensible target would be a precise threat model: for example, no coalition of fewer than `t` workers learns the spend witness from protocol messages, while public observers learn only the transaction's explicitly public fields and unavoidable network metadata is separately mitigated. Public nullifiers, roots, fees, output ciphertext sizes, timing, and IP/relay patterns can still leak correlations.

Likewise, “post-quantum” is conditional on concrete assumptions and security reductions. Even if the selected STARK is hash-based and ML-KEM is used, the repository still lacks a complete proof of ML-KEM decapsulation in the input relation, output KEM encapsulation/recipient ownership, AES-GCM/GHASH correctness, complete consensus validity, and a security analysis of the concrete STARK parameters. A proposed MPC protocol would add more primitives and assumptions. We must not label the system quantum-safe or fully anonymous before these gaps are resolved and independently analyzed.

## Decision gate before executable integration

The initial proposal in [`THRESHOLD-MPC-PROVER-DESIGN.md`](THRESHOLD-MPC-PROVER-DESIGN.md) specifies a provisional `n=4, t=1` threat model, data classes, stage mapping, and network/metadata controls. It does **not** select or implement the exact active VSS/multiplication protocol, prove adaptive-security properties, establish the underlying STARK's quantum security, or show resource feasibility. Do not code a production-facing MPC prover or benchmark proof-heavy workloads until those gaps are closed; first quantify operation count, bandwidth, per-worker peak RAM, and wall-clock against the existing budgets. Any implementation must preserve soundness and zero-knowledge parameters. Current harness remains a research prototype, not a production proving service, verifier, wallet, or consensus implementation.
