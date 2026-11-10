# Header commitments: transaction root and state root

**Status:** design note for P0-3, 2026-11-10. Decisions taken: **binary Merkle tree with sorted
leaves** for the transaction root, and the **state root is enforced from the start**, not advisory.

## Why this exists

The block header committed to `str(len(transactions))`. Two blocks with completely different
spends and the same count hashed identically, so proof of work secured an ordering of block hashes
rather than a ledger: a miner could publish a block, then publish a different one with the same
hash and the same work, and every peer would treat it as the same block.

A transaction root fixes that. A state root goes further: it commits to *what the ledger contains*
after the block, so two nodes that applied the same blocks but hold different notes cannot agree on
a header. Without it, "the same chain" means "the same list of hashes", not "the same UTXO set".

## 1. Transaction root

**Construction.** Binary Merkle tree over the block's transactions.

1. For each transaction, canonicalise its payload to bytes (§3) and hash it: `leaf_i = SHA3-256(0x00 || payload_i)`.
2. **Sort the leaves by hash**, ascending, treating them as 32-byte unsigned big-endian integers.
3. Build the tree bottom-up in pairs: `parent = SHA3-256(0x01 || left || right)`.
4. An odd node at any level is **promoted unchanged** to the next level (it is not duplicated).
5. The root is the value at the top; a block with no transactions has the fixed empty root
   `SHA3-256(0x02)`.

**Why sorted.** The root must depend on the *set* of spends, not on the order a block producer
happened to place them. Two nodes that receive the same transactions in different orders must build
the same block (L-2 depends on this too). Sorting by leaf hash gives a canonical order without
requiring the producer to agree with anyone on anything else.

**Why promoted rather than duplicated.** Duplicating an odd node (Bitcoin's rule) admits a
second-preimage ambiguity: a tree with `[a, b, c]` and one with `[a, b, c, c]` can share a root. It
is a known, avoidable weakness and this is a new format, so it is avoided.

**Domain separation.** `0x00` for leaves, `0x01` for internal nodes, `0x02` for the empty root.
Without it a leaf hash can be reinterpreted as an internal node hash.

**Inclusion proof.** A path of `(sibling_hash, side)` pairs from a leaf to the root. The verifier
recomputes the root and compares it to the header. The proof also carries the leaf index so the
verifier knows the leaf's position in the canonical sorted order; a proof is only valid for the
block whose root it is given with.

**Cost.** `n` leaves and `log2(n)` hashes per proof. At 64 transactions in a block, a proof is
about 6 × 32 = 192 bytes.

## 2. State root

**What is committed.** Two sets, committed together so that neither can be changed alone:

- the **unspent notes**: `(output_id, note)` where `note = (key, value)`;
- the **spent tags**: the tag bytes that have been consumed.

**Construction.** A sorted-set Merkle tree, rebuilt from the current state on each block:

1. Canonicalise every unspent note to bytes (§3) and hash: `SHA3-256(0x03 || note_bytes || output_id)`.
2. Canonicalise every spent tag and hash: `SHA3-256(0x04 || tag_bytes)`.
3. Concatenate both leaf sets, **sort by hash**, and build the same binary Merkle tree as §1 with
   the same promotion rule and domain separator `0x05` for internal nodes.

**Why one tree over both sets.** A block that adds a note and a block that spends one must not
produce the same root. Committing both sets in one tree makes every change visible, and it avoids a
second tree whose interaction with the first would need its own argument.

**Enforcement.** `Chain.append` recomputes the root after applying the block and rejects the block
if it differs from the header's. This is the decision taken: the root is **consensus**, not
advisory. The consequence is that the encoding in §3 is now part of consensus, and any
non-determinism in it is a chain split rather than a cosmetic bug.

**Cost, stated plainly.** Rebuilding a sorted tree over the whole unspent set is `O(n log n)` per
block, which is wrong for a real ledger and acceptable only because this chain is small. S-1
replaces it with an indexed, incrementally-updated structure. The *commitment format* is designed to
survive that replacement: an incremental sparse Merkle tree over the same leaf hashes produces a
different root, so this is a format change when S-1 lands, not a drop-in. That is recorded here
rather than discovered later.

## 3. Canonical encoding

The root is only meaningful if every implementation produces the same bytes. The rules:

- **Fixed field order.** Every structure serialises its fields in one documented order; no
  "whatever the dict iterates as".
- **Little-endian** for integers, matching the rest of this codebase. Fixed widths: 8 bytes for
  height, nonce, timestamp, target and amounts; 4 bytes for counts.
- **No floats, ever.** A float in a committed structure is a cross-platform mismatch waiting to
  happen; the difficulty is stored as an integer target and stays that way.
- **No maps without sorting.** Any dict that reaches a commitment is converted to a sorted sequence
  of pairs first.
- **Length-prefixed variable-length fields.** A concatenation of two variable-length fields with no
  lengths is ambiguous: `("ab", "c")` and `("a", "bc")` produce the same bytes.
- **A version byte** at the front of every committed structure, so a format change is a visible
  change rather than a silent one.

## 4. Header layout

```
offset  size  field
0       8     version            u64, currently 1
8       8     height             u64
16      32    previous           block hash
48      32    anchor             chain anchor at mining time
80      8     nonce              u64
88      8     timestamp          u64, seconds
96      8     target             u64
104     var   coinbase           length-prefixed encoded key
...     32    transaction_root
...     32    state_root
```

The hash is `SHA3-256(header_bytes)` and the proof-of-work comparison is unchanged (first 8 bytes
of the hash below the target).

The version field is new. It costs 8 bytes and it makes a format change detectable rather than
producing an unexplained "the peer's chain does not validate" on every node after an upgrade.

## 5. What is deliberately not committed

- **The mempool.** Local, not consensus.
- **Peer state.** Not consensus.
- **The ring pool order.** The pool is derived from the note set, so committing it separately would
  duplicate state. S-4 wants ring references by key hash rather than position; until then the pool
  order *is* derivable from the same set, so it is not a second commitment.
- **Treasury and immature-reward bookkeeping** in the first version. They are consensus-relevant and
  should be added, but each one enlarges the leaf set and the argument for including it. Recorded as
  a follow-up rather than silently omitted.

## 6. Migration

This changes the block format. There is no upgrade path from the current chain and none is needed:
the testnet genesis is regenerated and old `chain.json` files do not decode. The version field
exists so that the *next* change does not have the same cost.

## 7. What must be true when P0-3 is done

- Two blocks with different transaction sets can never share a hash. *(Already true with the flat
  root; the Merkle tree keeps it and adds a proof.)*
- An inclusion proof for a transaction verifies against the block's transaction root, and a proof
  for a transaction not in the block does not.
- A block whose declared state root disagrees with the recomputed one is **rejected**, and a test
  demonstrates it by tampering with one note.
- Two nodes that apply the same blocks independently compute the same state root — the determinism
  test, which is the one that would catch a serialisation bug masquerading as a consensus failure.
