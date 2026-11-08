# Threshold/MPC transaction proving: concrete design proposal

**Status: design only. No MPC prover, secret-sharing code, network service, worker protocol, or security claim has been implemented.** This proposal is intentionally not wired into Candidate A. It selects a provisional threat model and dataflow so the unresolved engineering and security work is concrete; it is not a proof of security or an approval to deploy.

## 1. Candidate threat model

- **Workers:** four independently operated workers, `n = 4`.
- **Corruption threshold:** at most `t = 1` worker is statically malicious or colluding during one proof session. The privacy target is information-theoretic secrecy of Shamir shares from any one worker. Two colluding workers can reconstruct degree-one shared values; privacy is explicitly lost at that point.
- **Active security:** use an honest-majority, actively secure finite-field MPC design with verifiable sharing and authenticated messages, with **abort** as the allowed failure outcome. A malicious worker may cause denial of service; it must not make honest workers accept inconsistent shares or release a different valid proof. This proposal does not promise fairness or guaranteed output delivery.
- **Network model:** synchronous rounds with authenticated private point-to-point channels and authenticated broadcast; an adversary may observe, modify, replay, delay, reorder, or drop network traffic. It may control one worker and its network. A global observer may correlate endpoints, timing, and volume; the metadata measures below reduce, but do not eliminate, that risk.
- **Endpoint and adaptive compromise:** a compromised wallet endpoint reveals its witness. The candidate assumes a static corruption set within a session. Mobile/adaptive corruption of different workers over time is not covered until proactive share refresh, erasure, and adaptive-security proofs are specified. Adaptive *protocol queries* are handled by making a job one-shot: one fixed circuit version and canonical statement per session; no general witness-dependent computation oracle; no reuse of a witness sharing after abort; a retry creates fresh shares and fresh randomness. Workers return only a proof or an indistinguishable abort class, never intermediate predicates or stage-specific witness errors.
- **Result:** if these assumptions hold and the underlying proof is sound and zero knowledge, fewer than two colluding workers learn no information from their shares beyond the public inputs and permitted output. This is conditional, not “100% anonymous.”

The `n=4,t=1` choice is a research starting point for an honest-majority protocol, not a selected production parameter. A concrete VSS, multiplication, broadcast, and output protocol must be chosen and proven to meet this model before coding.

## 2. Inputs: what is public and what is shared

The job is bound to one exact canonical `TransactionStatementV1`, one source-chain record, and one proof-circuit/profile identifier. No worker may substitute another statement or AIR.

### Public to workers

- Every byte of the canonical transaction statement: chain ID, version, anchor height, output root, fee, nullifier, and the output's commitment, ML-KEM ciphertext, nonce, ciphertext, and leaf.
- The source output record and leaf, source commitment, anchored root, circuit/profile hash, public parameters, and protocol version. These are treated as public chain-state data in this prototype.
- Fiat–Shamir challenges and transcript messages only after the protocol has committed to the required hiding values. Challenges are public transcript state, not witness shares.
- The eventual serialized proof is public. Workers and the wallet verify it against the exact canonical statement; a proof for a different statement is never accepted.

### Secret-shared among all four workers

The wallet (or trusted local input adapter) creates fresh degree-one Shamir shares over the pinned BabyBear field for each field element/byte encoding below. No worker receives a complete witness:

- 64-byte spend secret;
- input ML-KEM shared secret (32 bytes), input note value, `rho`, and note randomness; derived input owner, nullifier intermediates, and all private hash/KDF/AES state;
- output note opening: owner (64 bytes), value, `rho` (64 bytes), randomness (64 bytes), and the independent output KEM shared secret (32 bytes);
- depth-64 Merkle sibling/path witness and path index, plus all trace rows and witness-dependent AIR values derived from them;
- all prover-only randomness: PCS/MMCS hiding randomness, randomized trace/codeword masks, FRI/prover randomness, and any fresh circuit randomness. It is generated as a jointly contributed shared value; no one worker or the wallet alone chooses the final mask. Fresh randomness and fresh shares are required per job and retry.

Canonical byte/field encodings are validated before sharing. The public statement and source record are not secret-shared as a substitute for authenticating them; their exact bytes and profile hash are bound into the job. The current RDXL prototype does not prove ML-KEM decapsulation/encapsulation or output-owner derivation, so sharing these secrets does not fix those AIR gaps.

Wallet-side preprocessing is itself within a trusted local boundary: the current KEM/AEAD provider callbacks receive raw decapsulation-key bytes/per-output ciphertexts, shared secrets, plaintext, and authentication outcomes. They must not be remote or logging adapters. If any such operation is delegated, it must run on shared values under a specified, proven MPC circuit; a full key or secret must never be disclosed to one worker. This design does not implement or validate those circuits, so MPC aggregation alone does not cure provider leakage.

## 3. Candidate distributed prover dataflow

This is the intended mapping, not an implemented API:

1. **Input sharing and checks:** the wallet sends one share of each private field to each authenticated worker in an authenticated session. Workers reject stale session IDs, mismatched statement/profile hashes, malformed encodings, duplicate sequence numbers, and out-of-order messages. VSS/consistency checks prevent a malicious dealer or worker from silently giving inconsistent shares. The precise VSS and broadcast protocol is still an implementation blocker.
2. **Trace and AIR work:** witness-dependent trace construction stays shared. Field additions and other linear maps are performed locally on each share. Nonlinear field products use the active MPC multiplication protocol (including its preprocessing, sacrifice/consistency checks, and abort behavior). Bit decomposition, SHAKE/SHA3, AES, Keccak, and Poseidon operations must be represented as explicit secure circuits over the pinned field; no private input or witness-dependent intermediate may be opened for convenience.
3. **FFT/LDE and FRI:** FFTs and other linear transforms can be applied locally to each Shamir share. Pointwise products, constraint evaluations, and other nonlinear stages remain in MPC. FRI folding uses public challenges with secret-shared values; only values required by the final public proof may be opened. Protocol code must preserve the existing hiding masks and prove that every opened query is permitted by the ZK PCS.
4. **Merkle/hash commitments:** Merkle leaves and internal hash computations over shared witness-dependent values run inside MPC. Workers reveal only the prescribed commitment digest, not the hash preimages or intermediate states. Public roots/challenges are transcript outputs by design. Hash-output leakage and quantum query/grinding bounds need a proof for the exact transcript and PCS; the fact that a hash is applied does not itself establish hiding.
5. **Adaptive transcript:** all workers derive identical challenges from the canonical public transcript using domain separation for profile, statement, session, and round. They do not open data in response to an uncommitted or worker-selected challenge. Any mismatch, invalid share, or timeout aborts the session; no partial trace, share, or intermediate proof object is returned.
6. **Output and local rejection:** the client receives only a bounded proof envelope. It checks the exact expected statement bytes and profile, then runs the ordinary full verifier locally and rejects on any parse, binding, or verification failure before broadcasting. This local verifier must be shown to fit the target wallet budget; it is not yet established for production.

The proof protocol must not reduce soundness, ZK masking, query counts, or challenge security to make MPC cheaper. Final-proof zero knowledge alone does not protect input shares from the workers; that protection has to come from the MPC protocol.

## 4. Malice, abort, replay, and query controls

- Bind each job to `H(domain || profile_hash || canonical_statement || source_checkpoint || fresh_job_nonce || worker_set || expiry)`. This identifier is one-time and is not a stable wallet identifier. Workers authenticate each message with the session transcript hash, sender identity, monotonically increasing sequence number, and round number.
- Require active verifiable sharing and consistency checks before a share influences a multiplication or commitment. A worker may be excluded only when the selected protocol yields verifiable evidence that meets its exclusion rule; otherwise honest workers abort rather than attempt an unsafe repair. No VSS, evidence format, or exclusion protocol is selected here, so this proposal currently permits abort but does not establish safe worker exclusion.
- Any worker may abort. The client sees one generic failure class; it does not receive a secret-dependent diagnosis. Retrying requires reshare of the entire witness with fresh polynomials, fresh prover randomness, a new nonce, and a new session. The same worker set must not see a reusable share or an adaptive oracle on the same witness.
- A proof is accepted only after local verification against the exact statement and chain context. Invalid/withheld work is unpaid. Replay protection is separate from proof verification: a valid proof for an old statement cannot satisfy a new job because the statement bytes and profile are bound.
- This does not prevent a global observer from correlating repeated client retries. The wallet should rate-limit retries and avoid reporting fine-grained MPC failures.

## 5. Post-quantum basis and open transcript issue

- **MPC privacy/correctness core:** Shamir sharing, finite-field arithmetic, and an information-theoretic honest-majority MPC/VSS protocol can avoid classical Diffie–Hellman, pairings, and discrete-log assumptions. This is only a candidate basis; the exact actively secure protocol and its adaptive security theorem have not been selected or reviewed. Authenticated broadcast and private channels are still required.
- **Network authentication/confidentiality candidate:** use authenticated worker identities with ML-DSA-65 signatures and fresh per-session ML-KEM-768 key establishment, then AES-256-GCM for channel protection, with key rotation/erasure and strict nonce discipline. This adds lattice and symmetric assumptions; it does not make workers anonymous. NIST describes ML-KEM and ML-DSA as believed secure against quantum adversaries, while both current FIPS pages list potential-update/errata notes ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)). Implementations must track the current standards and errata.
- **Transcript/commitments:** the exact RDXL proof transcript, Fiat–Shamir transform, PCS hash, field size, query parameters, grinding cost, and ZK masks require a quantum-aware (including QROM) soundness and zero-knowledge analysis. The current Rust harness uses a testing-ZK FRI configuration and its concrete profile has not been established as production-secure or quantum-safe. Do not infer security from the general STARK literature or from choosing ML-KEM for the transport.
- Avoid adding a discrete-log-based commitment, classical-DH transport, or undocumented MPC dependency. Any new primitive needs an explicit standard, parameter set, implementation, security reduction, side-channel analysis, and dependency audit.

## 6. Metadata and worker selection policy candidate

Workers are selected from an independently operated, authenticated registry with pinned ML-DSA identity keys and a transparent change log. The wallet should submit via a separately operated batching/anonymous-relay layer, use padded fixed-size protocol messages, one-time job identifiers and ephemeral channel keys, and never reuse a worker-user pseudonym. A candidate release policy is a batch of at least 16 jobs or a fixed 15-minute batch window with cover traffic; this has not been costed and is not implemented. Worker selection must be independent of wallet identity, and no single operator should control two of the four worker slots under the stated privacy threshold.

The stated network adversary sees packet timing, sizes, and ingress/egress links and may control one worker; batching, padding, relay separation, and cover traffic aim to reduce correlation. They do not hide the public transaction, its nullifier, timing on-chain, or a compromised endpoint, and they do not protect against a global observer correlating enough metadata. No absolute anonymity claim is supportable.

## 7. Resource reality and implementation gate

The current RDXL LDE payload alone is estimated at `3,796,107,264 B` (`3.536 GiB`); after the disjoint-row S-box input/output/witness overlays, a hypothetical randomized-matrix/LDE overlap is `4,745,134,080 B` (`4.419 GiB`). These are payload estimates, not peak RSS. Shamir sharing across four workers **does not automatically divide per-worker matrix memory**: each worker normally holds a full-size share of each matrix. Row/column partitioning could alter this but requires a different distributed FFT/FRI design and more communication. The current RDXL prover has a preflight refusal under the smaller 1-GiB mobile / 4-GiB desktop cross-target process budget; without target-specific runtime policy it uses the smaller cap, and an MPC wrapper cannot remove that gate by assertion. No MPC bandwidth, CPU, RSS, proof-time, or verification-time measurements exist, and no proof-heavy test was run for this design.

Before any executable MPC code is eligible, the project must:

1. Pin an actively secure, aborting four-party protocol (VSS, multiplication/preprocessing, authenticated broadcast, randomness generation, and session recovery) with a concrete adaptive/static corruption theorem and no classical hardness assumptions in its core.
2. Analyze and, if required, replace the current testing-only STARK/PCS transcript with production parameters and a quantum-aware security argument, without weakening zero knowledge or soundness.
3. Define a full secret-share API for all listed witness values, prove circuit equivalence to the canonical local AIR, and demonstrate that no witness-dependent intermediate is opened.
4. Produce operation-count, communication, per-worker peak-RSS, CPU, and latency estimates for every prover stage against the existing budgets before running a heavy test.
5. Implement authenticated worker/session handling, replay and abort controls, anonymous relay/batching, and a local verifier path; independently audit the implementation and test malicious-worker and selective-failure cases.

**Decision:** this proposal is the implementation boundary for now. Do not integrate workers, accept third-party witness shares, expose a network endpoint, or advertise threshold privacy until all gates above pass. Existing local proving and verifier code remain unchanged.

## References

- Yehuda Lindell, [Secure Multiparty Computation (MPC)](https://eprint.iacr.org/2020/300), survey of MPC functionality and security models.
- NIST, [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final).
- Repository-specific limits and proof gaps: [`TRANSACTION-PROOF-PROTOTYPE-SCOPE.md`](TRANSACTION-PROOF-PROTOTYPE-SCOPE.md), [`DELEGATED-PROVING-RESEARCH.md`](DELEGATED-PROVING-RESEARCH.md), and [`src/depth64_path_opening.rs`](src/depth64_path_opening.rs).
