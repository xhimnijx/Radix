"""Non-production Gate 1 reference model for bounded balance and anchor/state rules.

This deliberately models consensus-side branch applicability separately from the
proof's public statement. The transaction proof binds chain/version/anchor/root;
AnchorOK resolves that root on the candidate parent's exact ancestry. A candidate
block/fork hash is not a proof input. It also models sequential transfer checks,
mint-last ordering, staged uniqueness sets, atomic rejection, and tree capacity.
This is specification-test code only: it is not a node, proof verifier, Merkle
implementation, or security argument.

Run with: python Radix-Gate-1-Reference-Model.py
"""
from dataclasses import dataclass

U64_MAX = (1 << 64) - 1
MIN_ANCHOR_AGE = 60


def anchor_ok(
    candidate_height: int,
    parent_post_roots: dict[int, bytes],
    anchor_height: int,
    supplied_root: bytes,
) -> bool:
    """Return whether root is the exact ancestor post-root and old enough.

    `parent_post_roots` represents only the candidate block parent's ancestry,
    keyed by ancestor height. It must not be a height-only global root cache.
    """
    if not isinstance(candidate_height, int) or not isinstance(anchor_height, int):
        return False
    if candidate_height < 0 or anchor_height < 0 or anchor_height > candidate_height:
        return False
    if candidate_height - anchor_height < MIN_ANCHOR_AGE:
        return False
    if len(supplied_root) != 64:
        return False
    ancestor_root = parent_post_roots.get(anchor_height)
    return ancestor_root is not None and ancestor_root == supplied_root


def balance_ok(inputs: list[int], outputs: list[int], fee: int) -> bool:
    """Check the experimental U64 value bounds and integer conservation."""
    if not 1 <= len(inputs) <= 16 or not 1 <= len(outputs) <= 16:
        return False
    if not isinstance(fee, int) or not 0 <= fee <= U64_MAX:
        return False
    if any(not isinstance(v, int) or not 1 <= v <= U64_MAX for v in inputs + outputs):
        return False
    # Python integers deliberately model the required bounded integer equation;
    # the proof circuit must separately constrain limbs/carries, not field-wrap.
    return sum(inputs) == sum(outputs) + fee


@dataclass(frozen=True)
class LedgerSets:
    nullifiers: frozenset[bytes] = frozenset()
    commitments: frozenset[bytes] = frozenset()


def apply_public_state_updates(
    state: LedgerSets,
    new_nullifiers: list[bytes],
    new_commitments: list[bytes],
    proof_valid: bool,
) -> LedgerSets | None:
    """Atomically apply already proof-checked public uniqueness updates.

    `None` means reject. The model checks duplicates both within a transaction
    and against prior state; a real implementation also verifies proof and
    typed record canonicality, fee, anchor, and append-only tree transitions.
    """
    if not proof_valid:
        return None
    if any(len(x) != 64 for x in new_nullifiers + new_commitments):
        return None
    if len(set(new_nullifiers)) != len(new_nullifiers):
        return None
    if len(set(new_commitments)) != len(new_commitments):
        return None
    if state.nullifiers.intersection(new_nullifiers):
        return None
    if state.commitments.intersection(new_commitments):
        return None
    return LedgerSets(
        state.nullifiers.union(new_nullifiers),
        state.commitments.union(new_commitments),
    )


MEMO_MAX = 512
NOTE_PLAINTEXT_LENGTH = 652
AEAD_TAG_LENGTH = 16


def encode_padded_note_plaintext(value: int, rho: bytes, randomness: bytes, memo: bytes) -> bytes:
    """Encode the proposed fixed-length successor payload (not AEAD itself)."""
    if not isinstance(value, int) or not 1 <= value <= U64_MAX:
        raise ValueError("note value must be a nonzero U64")
    if len(rho) != 64 or len(randomness) != 64:
        raise ValueError("note randomizers must each be 64 bytes")
    if len(memo) > MEMO_MAX:
        raise ValueError("memo exceeds 512 bytes")
    return (
        value.to_bytes(8, "little")
        + rho
        + randomness
        + len(memo).to_bytes(4, "little")
        + memo
        + bytes(MEMO_MAX - len(memo))
    )


def decode_padded_note_plaintext(data: bytes) -> tuple[int, bytes, bytes, bytes]:
    """Decode and enforce canonical zero padding for the proposed layout."""
    if len(data) != NOTE_PLAINTEXT_LENGTH:
        raise ValueError("note plaintext must be exactly 652 bytes")
    value = int.from_bytes(data[:8], "little")
    rho, randomness = data[8:72], data[72:136]
    memo_length = int.from_bytes(data[136:140], "little")
    if not 1 <= value <= U64_MAX or memo_length > MEMO_MAX:
        raise ValueError("noncanonical value or memo length")
    memo_end = 140 + memo_length
    memo = data[140:memo_end]
    if any(data[memo_end:]):
        raise ValueError("nonzero memo padding")
    return value, rho, randomness, memo


TREE_CAPACITY = 1 << 64


@dataclass(frozen=True)
class Transfer:
    nullifiers: tuple[bytes, ...]
    commitments: tuple[bytes, ...]
    leaves: tuple[bytes, ...]
    fee: int
    proof_valid: bool = True
    anchor_valid: bool = True


@dataclass(frozen=True)
class Mint:
    commitments: tuple[bytes, ...]
    leaves: tuple[bytes, ...]
    values: tuple[int, ...]
    proof_valid: bool = True


@dataclass(frozen=True)
class BlockModelState:
    ledger: LedgerSets = LedgerSets()
    leaf_count: int = 0
    appended_leaves: tuple[bytes, ...] = ()


def apply_block(
    state: BlockModelState,
    transfers: list[Transfer],
    mint: Mint,
    subsidy: int,
) -> BlockModelState | None:
    """Validate transfers in order, mint last, then atomically commit.

    Proof/anchor booleans stand in for external verification. Fee totals use
    Python exact integers here; a consensus transaction cap and finite canonical
    accumulator width are intentionally not selected by this model.
    """
    if not 0 <= state.leaf_count <= TREE_CAPACITY:
        return None
    nullifiers = set(state.ledger.nullifiers)
    commitments = set(state.ledger.commitments)
    leaf_count = state.leaf_count
    new_leaves: list[bytes] = []
    fee_total = 0

    def append_outputs(cms: tuple[bytes, ...], leaves: tuple[bytes, ...]) -> bool:
        nonlocal leaf_count
        if not 1 <= len(cms) <= 16 or len(cms) != len(leaves):
            return False
        if any(len(cm) != 64 for cm in cms) or any(not leaf for leaf in leaves):
            return False
        if len(set(cms)) != len(cms) or commitments.intersection(cms):
            return False
        for leaf in leaves:
            if leaf_count >= TREE_CAPACITY:
                return False
            new_leaves.append(leaf)
            leaf_count += 1
        commitments.update(cms)
        return True

    if not transfers:
        return None
    for tx in transfers:  # serialized transaction order; stage before next tx
        if not tx.proof_valid or not tx.anchor_valid or not 1 <= len(tx.nullifiers) <= 16:
            return None
        if not 0 <= tx.fee <= U64_MAX:
            return None
        if any(len(nf) != 64 for nf in tx.nullifiers):
            return None
        if len(set(tx.nullifiers)) != len(tx.nullifiers) or nullifiers.intersection(tx.nullifiers):
            return None
        if not append_outputs(tx.commitments, tx.leaves):
            return None
        nullifiers.update(tx.nullifiers)
        fee_total += tx.fee

    # Exactly one mint is logically processed after all ordinary transfers.
    if not mint.proof_valid or not 0 <= subsidy <= U64_MAX:
        return None
    if not 1 <= len(mint.values) <= 16 or any(not 1 <= v <= U64_MAX for v in mint.values):
        return None
    if len(mint.values) != len(mint.commitments):
        return None
    if sum(mint.values) != subsidy + fee_total:
        return None
    if not append_outputs(mint.commitments, mint.leaves):
        return None

    return BlockModelState(
        ledger=LedgerSets(frozenset(nullifiers), frozenset(commitments)),
        leaf_count=leaf_count,
        appended_leaves=tuple(new_leaves),
    )


def test_fixed_length_memo_payload() -> None:
    rho, randomness = b"r" * 64, b"s" * 64
    for memo in (b"", b"memo", b"contains\x00byte", b"\x00" * MEMO_MAX):
        encoded = encode_padded_note_plaintext(42, rho, randomness, memo)
        assert len(encoded) == NOTE_PLAINTEXT_LENGTH
        assert len(encoded) + AEAD_TAG_LENGTH == 668
        assert decode_padded_note_plaintext(encoded) == (42, rho, randomness, memo)
    try:
        encode_padded_note_plaintext(1, rho, randomness, b"x" * (MEMO_MAX + 1))
    except ValueError:
        pass
    else:
        raise AssertionError("overlong memo was accepted")
    canonical = encode_padded_note_plaintext(42, rho, randomness, b"x")
    nonzero_padding = canonical[:-1] + b"\x01"
    try:
        decode_padded_note_plaintext(nonzero_padding)
    except ValueError:
        pass
    else:
        raise AssertionError("nonzero memo padding was accepted")


def test_anchor_rules() -> None:
    root_a = b"A" * 64
    root_b = b"B" * 64
    chain_a = {height: bytes([height % 256]) * 64 for height in range(120)}
    chain_a[60] = root_a
    assert anchor_ok(120, chain_a, 60, root_a)  # exact age boundary, branch root
    assert not anchor_ok(119, chain_a, 60, root_a)  # age 59
    assert not anchor_ok(120, chain_a, 121, root_a)  # future anchor
    assert not anchor_ok(120, chain_a, 60, root_b)  # wrong/sibling-branch root
    assert not anchor_ok(120, chain_a, 120, root_a)  # too recent
    assert not anchor_ok(120, chain_a, 59, root_a)  # supplied root not at that height
    assert not anchor_ok(120, {h: r for h, r in chain_a.items() if h != 60}, 60, root_a)
    # A transaction is intentionally reusable on another branch only when that
    # branch has the same anchor post-root; later state/nullifier checks still
    # decide validity on each branch independently.
    chain_same_anchor_other_branch = dict(chain_a)
    chain_same_anchor_other_branch[60] = root_a
    assert anchor_ok(120, chain_same_anchor_other_branch, 60, root_a)


def test_integer_balance() -> None:
    assert balance_ok([9, 7], [13], 3)
    assert balance_ok([U64_MAX, U64_MAX], [U64_MAX, U64_MAX - 1], 1)
    assert not balance_ok([9, 7], [13], 2)
    assert not balance_ok([0], [0], 0)
    assert not balance_ok([U64_MAX + 1], [1], 0)
    assert not balance_ok([1] * 17, [17], 0)
    assert not balance_ok([17], [1] * 17, 0)
    assert not balance_ok([1], [1], U64_MAX + 1)


def test_atomic_uniqueness_updates() -> None:
    state = LedgerSets()
    n1, n2 = b"n" * 64, b"N" * 64
    c1, c2 = b"c" * 64, b"C" * 64
    updated = apply_public_state_updates(state, [n1], [c1], True)
    assert updated == LedgerSets(frozenset([n1]), frozenset([c1]))
    assert apply_public_state_updates(updated, [n1], [c2], True) is None
    assert apply_public_state_updates(updated, [n2], [c1], True) is None
    assert apply_public_state_updates(state, [n1, n1], [c2], True) is None
    assert apply_public_state_updates(state, [n2], [c2, c2], True) is None
    assert apply_public_state_updates(state, [n1], [c1], False) is None
    assert state == LedgerSets()  # rejection never mutates prior state


def test_ordered_atomic_block_transition() -> None:
    n1, n2 = b"1" * 64, b"2" * 64
    c1, c2, cmint = b"a" * 64, b"b" * 64, b"m" * 64
    tx1 = Transfer((n1,), (c1,), (b"leaf-1",), fee=2)
    tx2 = Transfer((n2,), (c2,), (b"leaf-2",), fee=1)
    mint = Mint((cmint,), (b"leaf-mint",), (8,))  # subsidy 5 + fees 3
    state = BlockModelState()
    result = apply_block(state, [tx1, tx2], mint, subsidy=5)
    assert result is not None
    assert result.appended_leaves == (b"leaf-1", b"leaf-2", b"leaf-mint")
    assert result.leaf_count == 3
    assert result.ledger.nullifiers == frozenset([n1, n2])
    assert result.ledger.commitments == frozenset([c1, c2, cmint])

    # Duplicate spends/commitments are checked against the staged overlay.
    assert apply_block(state, [tx1, Transfer((n1,), (c2,), (b"x",), 0)], mint, 5) is None
    assert apply_block(state, [tx1, Transfer((n2,), (c1,), (b"x",), 0)], mint, 5) is None
    assert apply_block(state, [tx1, tx2], Mint((c2,), (b"mint",), (8,)), 5) is None
    assert apply_block(state, [tx1, tx2], Mint((cmint,), (b"mint",), (7,)), 5) is None
    assert apply_block(state, [Transfer((n1,), (c1,), (b"x",), 2, proof_valid=False)], mint, 5) is None
    assert state == BlockModelState()  # rejected attempts leave parent state untouched

    almost_full = BlockModelState(leaf_count=TREE_CAPACITY - 1)
    # The transfer consumes the final leaf slot; the logically-later mint cannot overflow.
    assert apply_block(almost_full, [tx1], Mint((cmint,), (b"mint",), (7,)), 5) is None
    fills_tree = BlockModelState(leaf_count=TREE_CAPACITY - 2)
    full = apply_block(fills_tree, [tx1], Mint((cmint,), (b"mint",), (7,)), 5)
    assert full is not None and full.leaf_count == TREE_CAPACITY


if __name__ == "__main__":
    test_fixed_length_memo_payload()
    test_anchor_rules()
    test_integer_balance()
    test_atomic_uniqueness_updates()
    test_ordered_atomic_block_transition()
    print("All Gate 1 reference-model tests passed.")
