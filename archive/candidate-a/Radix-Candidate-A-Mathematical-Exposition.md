# A Mathematical Exposition of Candidate A

## A global Merkle tree and transparent proof system for confidential transfers

**Working paper for mathematical discussion**  
**Status:** explanatory account of an experimental protocol candidate; not a security proof or implementation specification

### Abstract

Candidate A is a proposal for confidential transfers in which each payment creates a committed note, notes are appended to a global hash tree, and a spender proves in zero knowledge that the notes being spent belong to a sufficiently old tree snapshot. A transaction also proves that its public nullifiers are correctly derived from those notes, that its new output records are internally consistent, and that the sum of the hidden input values equals the sum of the hidden output values plus the public fee.

This paper gives a mathematical account of those objects and the relation a proposed transparent zero-knowledge proof would need to establish. It explains how hash commitments, Merkle authentication paths, key encapsulation and authenticated encryption fit together, and why value conservation must be an integer statement rather than merely a congruence in a proof field. It then describes how a STARK could prove the relation, while distinguishing the abstract proof goal from the still-unselected proof construction. The candidate has a useful formal outline, but no complete proof-system parameters, demonstrated implementation, end-to-end security theorem, or production readiness. The text is intended to make the mathematics inspectable—not to assert that the construction is secure.

**Keywords:** confidential transactions; Merkle tree; zero-knowledge proof; STARK; FRI; integer constraints; post-quantum cryptography

---

## 1. Scope and mathematical model

A cryptocurrency transaction has two logically separate jobs:

1. **Cryptographic validation:** establish that the sender knows secret data opening valid prior notes, that the values balance, and that the outputs were formed according to the protocol, without disclosing the hidden values or which tree entries were spent.
2. **Consensus state transition:** ensure that no note is spent twice, append valid outputs, and agree on one history of blocks and tree roots.

A proof of the first kind does not by itself solve the second. In particular, a proof cannot stop a block producer from presenting two individually valid transactions that spend the same note; the consensus state machine must reject the second use of the same nullifier.

This exposition follows the experimental Candidate-A relation in the [Gate A review](<Radix-Gate-A-Cryptographic-Review.md>) and the [protocol draft](<Radix-Protocol-Draft.md>). It does not choose a STARK library or assert a security level. All numerical settings below are research/benchmark settings unless explicitly identified as a wire-format or primitive profile.

### 1.1 Notation

- A byte string is an element of \(\{0,1\}^*\); \(\mathsf{U8},\mathsf{U16},\mathsf{U32}\) are the analogous 1-, 2-, and 4-byte little-endian encodings. A bit string has length measured in bits, and a byte string has length measured in bytes.
- \(\mathsf{U64}(v)\) denotes the unique 8-byte little-endian encoding of an integer \(v\in\{0,\ldots,2^{64}-1\}\).
- \(\mathsf{Bytes}(x)=\mathsf{U32}(|x|)\mathbin\Vert x\), where \(|x|\) is the byte length and \(\Vert\) denotes concatenation.
- \(H_t\) is a domain-separated SHAKE256 function with 64-byte output. Its input is the unambiguous canonical frame `Frame(t;x_1,…,x_n) = ASCII("RADIX") || U8(1) || U16(|t|) || ASCII(t) || U16(n) || Bytes(x_1) || … || Bytes(x_n)`; all tags and field order are prescribed by the versioned protocol. A subscript on SHAKE256 denotes the requested output length in bits. Short names used below map as follows: `H_spend-pk` to `radix/spend-pk/v1`, `H_note-owner` to `radix/one-time/v1`, `H_note` to `radix/note/v1`, `H_leaf` to `radix/leaf/v1`, `H_nullifier` to `radix/nullifier/v1`, and `H_tree-node` to `radix/tree-node/v1`.
- \(\mathbb{F}_p\) denotes a finite field with \(p\) elements. A proof circuit may do arithmetic in this field, but the financial balance statement is over the ordinary integers \(\mathbb{Z}\).
- \(\lambda\) is a security parameter. A “quantum polynomial-time” adversary is an efficient attacker allowed quantum computation; this matters for claims about post-quantum security.

### 1.2 Experimental profile

The current profile uses SHAKE256 for domain-separated hashes, ML-KEM-768 for recipient key encapsulation, AES-256-GCM for note-payload encryption, 64-byte random note secrets/openings, 64-byte hash outputs, 64-level output-tree paths, and at most 16 inputs and 16 outputs per transfer. Amounts and fees are unsigned 64-bit integers. The output-tree root and transaction fields are public; note amounts and ownership openings are intended to be hidden by the proof and encrypted payload.

These choices identify candidate primitives and encodings, not a complete security theorem. In particular, “512-bit hash output” is an output length, not a claim of 512-bit security for the composed system.

---

## 2. Notes: hiding an amount while preserving a spending witness

A note is a record of value that can later be spent. Candidate A uses a hash commitment to bind the record, a KEM-derived secret to let the recipient recover it, and an authenticated ciphertext to store its recovery data on-chain.

### 2.1 Spend and viewing keys

Let \(s\in\{0,1\}^{512}\) be a spend secret. Define a 512-bit public spend component

\[
  pk_s = H_{\text{radix/spend-pk/v1}}(s).
\]

The recipient also has an ML-KEM-768 key pair \((pk_v,sk_v)\). The public address contains the chain identifier, \(pk_s\), and \(pk_v\). The spend secret \(s\) authorizes spending; the viewing secret \(sk_v\) permits trying to recover incoming notes. The two roles are deliberately distinct.

### 2.2 Commitment to a note

Let the note amount be \(v\in\{1,\ldots,2^{64}-1\}\). Let \(K\in\{0,1\}^{256}\) be a KEM shared secret, and let \(\rho,r\in\{0,1\}^{512}\) be independently sampled random strings. First derive an owner-related value

\[
  o = H_{\text{radix/one-time/v1}}(pk_s,K),
\]

then form the note commitment

\[
  cm = H_{\text{radix/note/v1}}(o,\mathsf{U64}(v),\rho,r).
\]

The commitment is a 512-bit string. Its intended role is **binding**: after publishing \(cm\), a spender should not be able to open it to a different owner component or amount without finding a hash collision. It is also intended to conceal the opening when \(\rho\) and \(r\) are fresh high-entropy values. This is computational hiding under a hash/XOF model, not perfect hiding and not an additive commitment.

In particular, commitments cannot be summed to check the transaction balance. The balance must be proved from the hidden values inside the zero-knowledge relation.

### 2.3 Recipient encapsulation and encrypted recovery data

For an output to a recipient with public viewing key \(pk_v\), the payer runs ML-KEM encapsulation:

\[
  (ct_{kem},K) = \mathsf{Encaps}(pk_v;\,\eta),
\]

where \(\eta\in\{0,1\}^{256}\) is the prescribed encapsulation randomness, \(ct_{kem}\) is 1,088 bytes, and \(K\) is 32 bytes. The wire profile fixes the exact standard algorithm and randomness encoding; it does not invent a new KEM.

The recovery plaintext is

\[
  P = \mathsf{U64}(v)\Vert\rho\Vert r\Vert\mathsf{Bytes}(memo),
\]

with \(|memo|\le512\) bytes. Derive a 256-bit symmetric key by framed hashing:

\[
  K_{enc} = \mathsf{SHAKE256}_{256}
    (\mathsf{Frame}(\texttt{radix/note-kdf/v1};K,ct_{kem},cm)).
\]

Then encrypt using AES-256-GCM with a fresh 12-byte nonce and associated data \(\mathsf{U8}(1)\Vert cm\Vert ct_{kem}\):

\[
 C = \mathsf{GCM.Enc}(K_{enc},nonce,P,\mathsf{AAD}).
\]

The ciphertext field \(C\) includes the 16-byte authentication tag. The associated data is authenticated but not encrypted. The recipient uses \(sk_v\) to decapsulate \(ct_{kem}\), re-derives \(K_{enc}\), decrypts \(C\), and checks that the recovered values recompute \(cm\).

This design makes the note self-contained enough to be scanned from public chain data. It also creates two explicit limitations. First, a KEM's confidentiality notion does not automatically imply **recipient key privacy**. An observer who holds candidate viewing keys may be able to decapsulate and test candidate note openings. Second, the AES-GCM ciphertext is not padded: since \(|P|=140+|memo|\),

\[
  |C|=|P|+16=156+|memo|.
\]

Thus the exact memo byte length is public from the ciphertext length. Candidate A hides memo contents, not memo length.

### 2.4 The public output leaf

An output's public leaf is

\[
  \ell = H_{\text{radix/leaf/v1}}(cm,ct_{kem},nonce,C).
\]

The public record therefore includes \(cm\), \(ct_{kem}\), \(nonce\), \(C\), and \(\ell\); it does not publish \(v,\rho,r,K\), or the address keys in clear text. The leaf hash binds the record fields together: changing any field changes the intended leaf value, subject to the collision resistance assumption for the hash.

---

## 3. The global append-only output tree

The ledger stores all output leaves in a binary Merkle tree of fixed depth \(D=64\). This gives \(2^{64}\) possible indices. A 64-bit index \(i\) selects one leaf; its binary digits determine whether the path goes left or right at each level.

Let \(E_0\) be the designated empty-leaf hash and recursively define the empty subtree values

\[
 E_{d+1}=H_{\text{radix/tree-node/v1}}(\mathsf{U8}(d),E_d,E_d),
 \qquad 0\le d<64.
\]

A nonempty leaf occupies its assigned index; unused leaves have value \(E_0\). The initial empty-tree root is \(E_{64}\). If a leaf \(\ell\) has index \(i\) and sibling hashes \(s_0,\ldots,s_{63}\), define \(z_0=\ell\), then

\[
 z_{d+1}=\begin{cases}
 H_{\text{radix/tree-node/v1}}(\mathsf{U8}(d),z_d,s_d),&\text{if bit }d\text{ of }i\text{ is }0,\\
 H_{\text{radix/tree-node/v1}}(\mathsf{U8}(d),s_d,z_d),&\text{if bit }d\text{ of }i\text{ is }1.
 \end{cases}
\]

The path authenticates membership under root \(z_{64}\). A path has exactly 64 sibling hashes; its orientation is derived from the index rather than supplied as a second, potentially inconsistent encoding.

The tree is **append-only**: new outputs occupy fresh indices, and previous leaves are not deleted or changed. This lets a spender prove membership with a logarithmic-size path rather than revealing a publicly selected ring of decoys. The cost of one membership witness is 64 sibling digests; in a circuit, each level also requires the corresponding node-hash computation.

A root is not just “the root at height \(a\)” in an unqualified global table. Forks can have different roots at the same height. For a candidate block \(B_h\) of height \(h\), with parent \(P\) and anchor height \(a\), the rule is:

1. Reject if \(a>h\), before doing subtraction.
2. Find the ancestor \(A=\mathsf{ancestor}(P,a)\) on this exact parent chain; reject if absent. Let \(\mathsf{State}_{post}(A)\) be the state after all accepted transactions in \(A\). Require the supplied root to equal the output-tree root in that state.
3. Compute \(d=h-a\) using checked subtraction and require \(d\ge60\) in this experimental policy.

This is a branch-relative anchor predicate. Reorganizations require transactions to be revalidated against their new candidate-parent ancestry. The 60-block delay is a provisional conservative rule, not a claim of deterministic finality.

---

## 4. Spending: a nullifier and a zero-knowledge relation

### 4.1 Deterministic nullifier

For a note with spend secret \(s\), KEM shared secret \(K\), and commitment randomness \(\rho\), define

\[
  nf = H_{\text{radix/nullifier/v1}}(s,K,\rho).
\]

The spender publishes \(nf\) but not its inputs. The mapping is deterministic, so the same note produces the same nullifier on every attempted spend. Consensus stores all previously used nullifiers and rejects a repeated value. The intended privacy argument is that the hash output is computationally unpredictable without the secret inputs; this needs its own multi-target and quantum analysis and does not follow from collision resistance alone.

### 4.2 Public statement and witness

For \(m\) inputs and \(q\) outputs, where \(1\le m,q\le16\), the public statement is conceptually

\[
 x_A=(chain\_id,tx\_version,anchor\_height,root_{out},fee,
       (nf_j)_{j=1}^{m},(out_k)_{k=1}^{q}).
\]

Each public output contains the commitment, KEM ciphertext, nonce, authenticated ciphertext, and leaf hash. All fields use fixed canonical encodings and prescribed order. The witness includes, for each input, its spend secret, amount opening, KEM secret, original public leaf data, tree index, and Merkle path. For each output it includes the recipient key material, encapsulation coins, amount/opening, memo, and AEAD nonce needed to recompute the public output. More explicitly, the witness has input components

\[
  w^{in}_j=(s_j,K_j,\rho_j,r_j,v_j,cm_j,ct_{kem,j},nonce_j,C_j,index_j,path_j)
\]

and output components

\[
  w^{out}_k=(pk_{s,k},pk_{v,k},K_k,\eta_k,\rho'_k,r'_k,v'_k,memo_k,aead\_nonce_k).
\]

The full witness is the ordered collection of these tuples, together with any tree-boundary witnesses required by the fixed append-only tree representation.

The relation \(R_A(x_A;w_A)\) is true exactly when all the following conditions hold.

1. **Canonical values.** Every encoding and range is valid. Each input and output amount lies in \(\{1,\ldots,2^{64}-1\}\); the fee is a canonical \(\mathsf{U64}\).
2. **Input ownership and membership.** For each input \(j\), recompute \(pk_{s,j}=H_{spend-pk}(s_j)\), its owner component \(o_j=H_{note-owner}(pk_{s,j},K_j)\), and its commitment \(cm_j=H_{note}(o_j,\mathsf{U64}(v_j),\rho_j,r_j)\). Recompute the historical leaf from its stored ciphertext data and prove, with its 64-level path, that it belongs to \(root_{out}\). For inclusion in candidate block `B_h`, consensus must separately check `AnchorOK(B_h,anchor_height,root_out)` against the exact parent-chain ancestor described in §3; this context-dependent rule is consensus-side unless the block context is explicitly included as a public proof input.
3. **Nullifier correctness.** For every input, recompute \(H_{nullifier}(s_j,K_j,\rho_j)\) and require exact equality with the corresponding public \(nf_j\). Duplicate nullifiers within a transaction are rejected.
4. **Output correctness.** For each output \(k\), use the hidden, well-formed ML-KEM public key and encapsulation coins to reproduce \((ct_{kem,k},K_k)\). Recompute the owner component, commitment, KDF key, AES-GCM ciphertext/tag, and output leaf. Every result must equal the matching public output field. Duplicate output commitments within a transaction are rejected; the block executor separately checks uniqueness against the global commitment set.
5. **Integer balance.** The hidden amounts satisfy
   \[
    \sum_{j=1}^{m}v_j=\sum_{k=1}^{q}v'_k+fee
   \]
   as an equality in \(\mathbb{Z}\), not merely in the proof field.
6. **Statement binding.** The proof is bound to the entire canonical public statement: chain/version, anchor, root, fee, ordered nullifiers, and ordered output records. Domain separation is intended to prevent accidental proof reuse across versions/chains, subject to the selected proof construction's actual binding and soundness guarantees. The serialized statement contains no parent/fork identifier, so it is not intrinsically fork-specific. Branch applicability is supplied by consensus `AnchorOK`. The protocol draft's mention of fork context in Fiat–Shamir challenges must either be specified as a verifier public context bound by the transcript, or be reduced to this consensus-side branch check.

This is a relation definition, not yet a machine-checked circuit. Precisely, `R_A` describes transaction content and witness consistency; candidate-block acceptance is a separate predicate. For a proof `π` and current state `S`, write

\[
  \mathsf{Accept}(B_h,x_A,\pi,S)=1
\]

only if \(\mathsf{Verify}(x_A,\pi)=1\), `AnchorOK(B_h,anchor_height,root_out)=1`, each nullifier is absent from the current map, each output commitment is globally unused, and the block executor applies the updates atomically. This keeps parent-chain context and global maps out of the ordinary transaction proof; a stateless design would need additional transition proofs. Its input side relies on an inductive ledger invariant: every historical leaf was appended only after a valid transfer-output or issuance relation was checked. The spend relation does not re-run that historical proof or decrypt the old ciphertext. The invariant is what ties the hidden `K` used in the spend opening to the KEM ciphertext in the authenticated historical leaf, subject to the binding and soundness assumptions. A proof that this relation holds means the prover knows a witness satisfying these equations; it does not mean that a recipient controls the output's private key. The payer-supplied output spend component may be arbitrary bytes, so a payment can intentionally or accidentally be made to an unspendable address.

### 4.3 Why balance is an integer equation

The range bounds are essential. Since \(m,q\le16\) and every amount is at most \(2^{64}-1\),

\[
 \sum_{j=1}^{m}v_j < 16\cdot2^{64}=2^{68},
 \qquad
 \sum_{k=1}^{q}v'_k+fee < 17\cdot2^{64}<2^{69}.
\]

A proof circuit commonly expresses arithmetic over a finite field. If it checked only

\[
 \sum_j v_j \equiv \sum_k v'_k+fee\pmod p,
\]

then the statement would only be a congruence. For example, two unequal integers can have the same residue modulo \(p\). The experimental Goldilocks field has modulus \(p=2^{64}-2^{32}+1\), which is far below the possible 69-bit totals, so modular equality alone is plainly insufficient.

Instead, the circuit must represent the bounded integers as limbs and constrain carries. For instance, write each amount in base \(2^{32}\):

\[
 v_j=v_{j,0}+2^{32}v_{j,1},\qquad 0\le v_{j,0},v_{j,1}<2^{32}.
\]

Add the limbs with explicit carry variables. If the running input and output totals are represented by low and high limbs, each limb equality and carry bound is separately constrained; the final high limb range ensures no unaccounted overflow. The exact constraint system must prove that the two integer totals are equal, not simply rely on a field equation that could wrap around. The maximum right-hand total needs fewer than 69 bits, hence three 32-bit limbs suffice for the final accumulator, with appropriate range checks on all limbs/carries.

A small pedagogical example is \(9+7=13+3\). In the protocol, the values are hidden and may be 64-bit; the proof demonstrates the same equation using range-constrained witness variables.

---

## 5. Consensus state and issuance

The transaction proof does not replace the block executor. A full validator must, in an atomic ordered transition:

1. verify the transaction proof and its public statement;
2. check that every public nullifier is absent from the current nullifier map, then insert it;
3. reject any output commitment already used and insert the new unique commitments;
4. append every verified output leaf and update the output-tree root; and
5. enforce fee, block, and consensus rules.

The nullifier map is separate from the output Merkle tree. The transfer proof shows that each published nullifier corresponds to a valid hidden input; the full node checks whether that nullifier has already been used. A stateless client would need an additional authenticated transition proof to establish those map updates. Candidate A's ordinary transaction relation does not by itself prove global non-membership in the nullifier set.

Issuance also requires a separate relation. For a block subsidy \(S_h\), and total valid public fees \(F_h\), a mint proof must show that all newly issued outputs are correctly constructed and that

\[
  \sum_k v'_k = S_h+F_h
\]

as an integer. The block executor separately checks the schedule for \(S_h\), recomputes \(F_h\), prevents excess mint transactions, and appends the outputs. The research draft has not yet fixed a maximum transfer count and fee bound per block, so a finite canonical width for \(F_h\) and its serialization is still required. Genesis and any migration issuance must be covered by an explicit initial-state rule. The intended supply invariant is inductive: every tree leaf must arise from a verified transfer output, a verified issuance output, or an explicitly authorized genesis/migration rule. Without that base case and transition invariant, transaction proofs alone cannot establish total supply correctness.

---

## 6. What a STARK would prove

A STARK (a transparent zero-knowledge proof based on an algebraic intermediate representation and low-degree testing; “transparent” means that no trusted setup is required) would take public data \(x_A\) and a private witness \(w_A\), and produce a proof \(\pi\) checked by a verifier. Its intended completeness property is

\[
 R_A(x_A;w_A)=1\quad\Longrightarrow\quad
 \mathsf{Verify}(x_A,\pi)=1
\]

for honestly generated proofs. Its soundness/knowledge property informally says that producing an accepted proof for a false statement should be computationally infeasible, with an extraction theorem showing that a successful prover effectively knows a valid witness. Its zero-knowledge property says the proof reveals no material information about the witness beyond what follows from the public statement and explicitly admitted leakage.

At a high level, the prover encodes a computation as a sequence of field elements (a **trace**) whose adjacent rows obey algebraic constraints. Those constraints are represented by low-degree polynomials. The prover commits to evaluations of the trace using a hash-based Merkle commitment. A verifier checks randomly selected locations, and a FRI (Fast Reed–Solomon Interactive Oracle Proof of Proximity)-style protocol tests whether the committed function is close to a low-degree polynomial. Random sampling makes it likely that a false computation violates at least one checked constraint. Fiat–Shamir hashing can turn verifier challenges into a noninteractive proof transcript, but its security must be analyzed in the appropriate random-oracle model, including the quantum random-oracle model (QROM) for quantum adversaries.

For Candidate A the trace would have to implement the actual relation: SHAKE-based hashes and tree authentication, 64-bit range constraints and carries, KEM encapsulation, AES-GCM encryption, and all public-field bindings. This is mathematically well-defined at the relation level, but potentially expensive. SHAKE, ML-KEM, and AES are not cheap field operations. No proving-time, verification-time, memory, or proof-size result is established here.

### 6.1 Benchmark knobs are not a proof parameter set

The current discussion proposes a Goldilocks field \(p=2^{64}-2^{32}+1\), trace domain at most \(2^{24}\), blowup factor 8, 128 FRI queries, 32 bits of transcript grinding, and 512-bit SHAKE outputs for external commitments. These are benchmark targets only. They do not determine a soundness error on their own. The exact FRI/DEEP variant, degree bounds, extension field, query sampling, masking needed for zero knowledge, commitment construction, transcript, grinding analysis, extraction theorem, and QROM accounting are all part of the proof-system definition.

In particular, “128 queries” does not imply “128-bit security.” A soundness analysis has to bound the probability that a false trace passes all checks, then include commitment binding, Fiat–Shamir, extraction, grinding, quantum queries, multi-target use, and composition with the hash, KEM, AEAD, and consensus assumptions. Until that complete calculation and a suitable simulator are specified, Candidate A has no justified end-to-end numeric security level.

---

## 7. Security claims: intended properties and assumptions

The mathematical objects above suggest security goals, but each goal depends on assumptions and a proof that has not yet been supplied.

| Intended property | Mathematical/cryptographic basis | Present limitation |
|---|---|---|
| Commitment binding | Finding two distinct openings to the same 512-bit hash should require a collision/second-preimage attack. | Depends on SHAKE framing, implementation correctness, and applicable quantum/multi-target bounds. |
| Commitment hiding | Fresh, high-entropy \(\rho,r\) make the hash commitment difficult to distinguish across candidate openings. | A plain hash is not unconditionally hiding; a full transcript-level hiding argument is absent. |
| Note confidentiality and integrity | ML-KEM shared secret, framed KDF, and AES-256-GCM with fresh nonce. | KEM IND-CCA does not imply recipient key privacy; nonce and composition requirements remain. |
| Spend unlinkability | Deterministic nullifiers should look unpredictable without note secrets; the proof should hide the membership witness. | Requires a nullifier pseudorandomness argument and a zero-knowledge/extraction-secure STARK. |
| No double spend | Stable nullifier plus consensus map that rejects duplicates. | Correct atomic state transition and reorganization behavior are necessary. |
| No inflation | Integer balance relation, explicit issuance relation, and inductive tree/supply invariant. | Genesis, migration, fee bounds, and complete consensus implementation still need exact rules. |
| Post-quantum security | Hash-based commitments/STARK components and ML-KEM-768 under its standard lattice assumptions. | Every primitive and their composition need separate analysis; “post-quantum” is not established by naming these components. |

The public leakage includes transaction sizes, input/output counts, fees, nullifiers, block timing, and network metadata. In particular, Candidate A reveals exact memo length through \(|C|=156+|memo|\). No padding, cover traffic, recipient-anonymous KEM, or global-network privacy is specified. A proof can hide a tree index; it cannot erase timing or byte lengths already published.

---

## 8. Research status and conclusions

Candidate A has a coherent mathematical direction: hash-committed notes are stored in an append-only global Merkle tree; a spender proves hidden note membership and opening, emits deterministic nullifiers, constructs valid encrypted outputs, and proves bounded integer conservation. The proof relation is substantially more explicit than a description that merely says “use a STARK.”

However, this is not yet a complete cryptographic protocol in the theorem-and-implementation sense. The following are still necessary before the mathematics could support a value-bearing deployment:

1. Specify and pin one exact zero-knowledge STARK/FRI construction, including all transcript/public-context (including whether a fork identifier is bound), masking, commitment, degree, and field-extension details.
2. Define the complete AIR or circuit, including SHAKE, ML-KEM, AES-GCM, Merkle paths, canonical parsing, ranges, and integer carries.
3. Prove or justify knowledge soundness, zero knowledge, QROM security, hash/KEM/AEAD composition, nullifier pseudorandomness, and a numeric total security bound.
4. Demonstrate that circuit constraints are equivalent to the consensus implementation; test fork-relative anchors, nullifier updates, commitment uniqueness, issuance, and reorganization behavior.
5. Benchmark the actual prover and verifier, especially the cost of proving ML-KEM and AES-GCM operations, and measure transaction and proof sizes.
6. Specify key validation, recipient scanning, address ownership/unspendable-address behavior, genesis and monetary policy, DoS limits, and all remaining canonical wire formats.

The current STARK knobs are therefore a research comparison profile, not mainnet parameters. The [Gate A review](<Radix-Gate-A-Cryptographic-Review.md>) records this candidate as not passed and recommends only isolated, non-value feasibility work. Nothing in this paper asserts that Candidate A is secure or that a production cryptocurrency can be built from it without changes.

---

## References and source documents

1. *Radix Gate A Cryptographic Review*, workspace research document; contains the current Candidate-A relation, encoding profile, threat model, and evidence ledger: [Radix-Gate-A-Cryptographic-Review.md](<Radix-Gate-A-Cryptographic-Review.md>).
2. *Radix Protocol Specification (Research Draft)*, workspace protocol document; contains the proposed note lifecycle, Candidate-A transaction relation, and provisional consensus behavior: [Radix-Protocol-Draft.md](<Radix-Protocol-Draft.md>).
3. FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (ML-KEM), as referenced by the workspace specification. Candidate A proposes the ML-KEM-768 parameter set; use the standard and its current errata for any implementation.

---

**Acknowledgment of status:** This exposition is AI-assisted and has not been reviewed by an independent cryptographer. It is explanatory mathematics and design documentation, not an audit, proof of security, implementation specification, or launch approval.
