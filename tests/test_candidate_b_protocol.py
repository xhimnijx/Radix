"""Tests for the Candidate-B protocol prototype (notes, rings, spends, ledger)."""

import pytest

from radix_core.candidate_b import lsag, protocol
from radix_core.candidate_b.protocol import (
    LedgerState,
    NoteRecord,
    ProtocolError,
    RingInput,
    RingMember,
    Transaction,
    apply_block,
    build_spend,
    generate_note_keypair,
)

HEIGHT = 100
VALUE = 10


def _fixture(count: int = 8, value: int = VALUE) -> tuple[LedgerState, list]:
    keys = [generate_note_keypair() for _ in range(count)]
    notes = tuple(
        NoteRecord(verification_key=key.verification_key, value=value) for key in keys
    )
    return LedgerState.from_notes(notes, height=HEIGHT), keys


def _outputs(recipient_key, count: int = 1, value: int = 10) -> tuple[NoteRecord, ...]:
    return tuple(
        NoteRecord(verification_key=generate_note_keypair().verification_key, value=value)
        for _ in range(count)
    )


def test_genesis_fixture_roots_notes_and_indexes_by_value():
    state, keys = _fixture(4)
    assert state.note_count == 4
    assert state.candidates(VALUE) == (0, 1, 2, 3)
    assert state.candidates(VALUE + 1) == ()
    assert state.note(0).verification_key == keys[0].verification_key
    assert state.height == HEIGHT


def test_spend_verifies_and_commits_atomically():
    state, keys = _fixture()
    outputs = _outputs(keys[0], 2, 4)
    transaction = build_spend(keys[3], state, 3, outputs, fee=2, ring_size=4)

    protocol.validate_transaction(state, transaction)
    next_state = apply_block(state, HEIGHT + 1, (transaction,))

    assert next_state.height == HEIGHT + 1
    assert next_state.note_count == state.note_count + 2
    assert len(next_state.tags) == 1
    assert next_state.root != state.root
    assert next_state.total_value == state.total_value - 2  # fee is burned in this model


def test_double_spend_is_rejected_after_the_tag_is_recorded():
    state, keys = _fixture()
    transaction = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=3)
    next_state = apply_block(state, HEIGHT + 1, (transaction,))

    # Replaying the identical transaction is rejected earlier still (its root no
    # longer matches). The interesting case is a *new* transaction spending the
    # same note against the new root: same note => same tag.
    replay = build_spend(
        keys[0], next_state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=3
    )
    with pytest.raises(ProtocolError, match="double spend"):
        apply_block(next_state, HEIGHT + 2, (replay,))


def test_a_spend_cannot_be_replayed_in_the_same_block_twice():
    state, keys = _fixture()
    transaction = build_spend(keys[1], state, 1, _outputs(keys[1], 1, 8), fee=2, ring_size=3)

    with pytest.raises(ProtocolError, match="duplicate tag"):
        apply_block(state, HEIGHT + 1, (transaction, transaction))


def test_balance_and_fee_are_enforced():
    state, keys = _fixture()
    outputs = _outputs(keys[2], 1, 9)  # 10 input, 9 output, fee 0 -> unbalanced
    transaction = build_spend(keys[2], state, 2, outputs, fee=0, ring_size=2)
    with pytest.raises(ProtocolError, match="input total"):
        protocol.validate_transaction(state, transaction)


def test_wrong_owner_cannot_build_a_spend():
    state, keys = _fixture()
    with pytest.raises(ProtocolError, match="does not own"):
        build_spend(keys[0], state, 5, _outputs(keys[0], 1, 8), fee=2, ring_size=3)


def test_ring_members_must_share_a_value():
    state, keys = _fixture()
    transaction = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=3)
    ring = list(transaction.inputs[0].ring)
    mixed = NoteRecord(verification_key=generate_note_keypair().verification_key, value=VALUE + 1)
    ring[-1] = RingMember(index=ring[-1].index, record=mixed)
    broken = Transaction(
        anchor_height=transaction.anchor_height,
        root=transaction.root,
        outputs=transaction.outputs,
        fee=transaction.fee,
        inputs=(
            RingInput(
                ring=tuple(ring),
                paths=transaction.inputs[0].paths,
                signature=transaction.inputs[0].signature,
            ),
        ),
    )
    with pytest.raises(ProtocolError, match="share one value"):
        protocol.validate_transaction(state, broken)


def test_tampering_with_the_message_breaks_the_signature():
    state, keys = _fixture()
    transaction = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=3)

    # Same ring/signature, different fee => different canonical message.
    tampered = Transaction(
        anchor_height=transaction.anchor_height,
        root=transaction.root,
        outputs=transaction.outputs,
        fee=transaction.fee + 1,
        inputs=transaction.inputs,
    )
    with pytest.raises(ProtocolError, match="signature"):
        protocol.validate_transaction(state, tampered)


def test_ring_order_is_part_of_the_signed_message():
    state, keys = _fixture()
    transaction = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=3)
    ring_input = transaction.inputs[0]
    reordered = RingInput(
        ring=tuple(reversed(ring_input.ring)),
        paths=tuple(reversed(ring_input.paths)),
        signature=ring_input.signature,
    )
    broken = Transaction(
        anchor_height=transaction.anchor_height,
        root=transaction.root,
        outputs=transaction.outputs,
        fee=transaction.fee,
        inputs=(reordered,),
    )
    with pytest.raises(ProtocolError, match="ascending|signature"):
        protocol.validate_transaction(state, broken)


def test_reusing_an_output_key_is_rejected():
    state, keys = _fixture()
    reused = (NoteRecord(verification_key=keys[0].verification_key, value=8),)
    transaction = build_spend(keys[1], state, 1, reused, fee=2, ring_size=2)
    with pytest.raises(ProtocolError, match="output key has already been used"):
        protocol.validate_transaction(state, transaction)


def test_anchor_height_and_root_are_checked():
    state, keys = _fixture()
    transaction = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=2)

    stale_anchor = Transaction(
        anchor_height=HEIGHT - 1,
        root=transaction.root,
        outputs=transaction.outputs,
        fee=transaction.fee,
        inputs=transaction.inputs,
    )
    with pytest.raises(ProtocolError, match="current block height"):
        protocol.validate_transaction(state, stale_anchor)

    wrong_root = Transaction(
        anchor_height=transaction.anchor_height,
        root=b"\x11" * 64,
        outputs=transaction.outputs,
        fee=transaction.fee,
        inputs=transaction.inputs,
    )
    with pytest.raises(ProtocolError, match="root"):
        protocol.validate_transaction(state, wrong_root)


def test_a_rejected_block_leaves_the_previous_state_untouched():
    state, keys = _fixture()
    good = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=2)
    bad = Transaction(
        anchor_height=good.anchor_height,
        root=good.root,
        outputs=good.outputs,
        fee=good.fee + 5,
        inputs=good.inputs,
    )
    with pytest.raises(ProtocolError):
        apply_block(state, HEIGHT + 1, (good, bad))
    assert state.height == HEIGHT
    assert state.note_count == 8
    assert state.tags == frozenset()


def test_not_enough_decoys_is_rejected():
    state, keys = _fixture(count=2)
    with pytest.raises(ProtocolError, match="not enough equal-value notes"):
        build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=4)


def test_ring_signature_links_across_different_rings():
    state, keys = _fixture()
    first = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=2)
    second = build_spend(keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=4)
    assert first.inputs[0].tag_bytes() == second.inputs[0].tag_bytes()


def test_signature_size_is_linear_in_ring_size():
    state, keys = _fixture()
    sizes = {}
    for ring_size in (2, 3, 5, 8):
        transaction = build_spend(
            keys[0], state, 0, _outputs(keys[0], 1, 8), fee=2, ring_size=ring_size
        )
        sizes[ring_size] = len(transaction.inputs[0].signature.encode())
    assert sizes[2] == 64 + 32 * 2
    assert sizes[8] == 64 + 32 * 8
