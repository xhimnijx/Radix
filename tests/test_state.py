import pytest

from radix_core.crypto import output_leaf
from radix_core.encoding import U64_MAX
from radix_core.merkle import OutputTree
from radix_core.rules import BlockHeaderRef
from radix_core.state import (
    MAX_MINT_AMOUNT,
    BlockRejected,
    LedgerState,
    Mint,
    Transfer,
    apply_block,
)
from radix_core.wire import OutputRecord, TransactionStatementV1, serialize_statement_v1

CHAIN_ID = b"c" * 32
ANCHOR_ROOT = OutputTree().root


def make_output(index: int) -> OutputRecord:
    commitment = bytes([index + 1]) * 64
    kem = bytes([index + 2]) * 1088
    nonce = bytes([index + 3]) * 12
    ciphertext = bytes([index + 4]) * 156
    leaf = output_leaf(commitment, kem, nonce, ciphertext)
    return OutputRecord(commitment, kem, nonce, ciphertext, leaf)


def branch(parent_height: int = 119, prefix: int = 1):
    headers = {}
    parent = None
    for height in range(parent_height + 1):
        block_id = bytes([prefix]) + height.to_bytes(31, "little")
        # These fixtures contain no outputs, so the post-state root remains stable.
        root = ANCHOR_ROOT
        headers[block_id] = BlockHeaderRef(block_id, parent, height, root)
        parent = block_id
    return headers, parent


def make_transfer(index: int, nullifier: bytes, fee: int, proof: bytes = b"valid") -> Transfer:
    statement = TransactionStatementV1(
        chain_id=CHAIN_ID,
        anchor_height=60,
        root_out=ANCHOR_ROOT,
        fee=fee,
        nullifiers=(nullifier,),
        outputs=(make_output(index),),
    )
    return Transfer(statement, proof)


def run_block(
    state,
    headers,
    parent,
    transfers,
    mint,
    *,
    max_total_proof_bytes=4096,
    max_total_statement_bytes=1_048_576,
    verify_transfer=None,
    verify_mint=None,
):
    return apply_block(
        state,
        candidate_height=120,
        parent_id=parent,
        headers=headers,
        chain_id=CHAIN_ID,
        transfers=transfers,
        mint=mint,
        scheduled_subsidy=5,
        aggregate_fee_limit=100,
        max_transfers=16,
        max_total_proof_bytes=max_total_proof_bytes,
        verify_transfer=(
            verify_transfer
            if verify_transfer is not None
            else lambda statement, proof: proof == b"valid"
        ),
        verify_mint=(
            verify_mint
            if verify_mint is not None
            else lambda mint_record, value: mint_record.proof == b"mint" and value == 10
        ),
        max_total_statement_bytes=max_total_statement_bytes,
    )


def test_successful_block_appends_transfers_in_order_then_mint(monkeypatch):
    append_many = OutputTree.append_many
    append_calls = []

    def count_append_calls(tree, leaves, **kwargs):
        append_calls.append(1)
        return append_many(tree, leaves, **kwargs)

    monkeypatch.setattr(OutputTree, "append_many", count_append_calls)
    state = LedgerState.empty()
    headers, parent = branch()
    first, second, minted = make_output(0), make_output(1), make_output(2)
    result = run_block(
        state,
        headers,
        parent,
        [make_transfer(0, b"n" * 64, 2), make_transfer(1, b"m" * 64, 3)],
        Mint((minted,), b"mint"),
    )
    assert len(append_calls) == 1
    assert result.tree.leaf_count == 3
    assert result.tree.leaf_at(0) == first.leaf
    assert result.tree.leaf_at(1) == second.leaf
    assert result.tree.leaf_at(2) == minted.leaf
    assert result.nullifiers == frozenset((b"n" * 64, b"m" * 64))
    assert result.commitments == frozenset((first.commitment, second.commitment, minted.commitment))
    assert state.tree.leaf_count == 0
    assert state.nullifiers == frozenset()


def test_duplicate_nullifier_across_transfers_rejects_atomically():
    state = LedgerState.empty()
    headers, parent = branch()
    transfers = [make_transfer(0, b"n" * 64, 2), make_transfer(1, b"n" * 64, 3)]
    with pytest.raises(BlockRejected, match="duplicate nullifier"):
        run_block(state, headers, parent, transfers, Mint((make_output(2),), b"mint"))
    assert state.tree.leaf_count == 0
    assert state.tree.root == ANCHOR_ROOT
    assert not state.nullifiers and not state.commitments


def test_late_transfer_failure_and_mint_failure_leave_parent_untouched():
    state = LedgerState.empty()
    headers, parent = branch()
    transfers = [make_transfer(0, b"n" * 64, 2), make_transfer(1, b"m" * 64, 3, b"bad")]
    with pytest.raises(BlockRejected, match="proof rejected"):
        run_block(state, headers, parent, transfers, Mint((make_output(2),), b"mint"))
    with pytest.raises(BlockRejected, match="issuance amount rejected"):
        apply_block(
            state,
            candidate_height=120,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=[make_transfer(0, b"n" * 64, 2)],
            mint=Mint((make_output(2),), b"bad"),
            scheduled_subsidy=5,
            aggregate_fee_limit=100,
            max_transfers=16,
            max_total_proof_bytes=4096,
            verify_transfer=lambda *_: True,
            verify_mint=lambda *_: False,
        )
    assert state.tree.leaf_count == 0
    assert not state.nullifiers and not state.commitments


def test_block_rejects_empty_transfer_lists_only_if_other_rules_fail():
    state = LedgerState.empty()
    headers, parent = branch()
    result = apply_block(
        state,
        candidate_height=120,
        parent_id=parent,
        headers=headers,
        chain_id=CHAIN_ID,
        transfers=(),
        mint=Mint((make_output(0),), b"mint"),
        scheduled_subsidy=5,
        aggregate_fee_limit=100,
        max_transfers=16,
        max_total_proof_bytes=4096,
        verify_transfer=lambda *_: True,
        verify_mint=lambda _mint, amount: amount == 5,
    )
    assert result.tree.leaf_count == 1


def test_block_rejects_invalid_parent_or_candidate_height():
    state = LedgerState.empty()
    headers, parent = branch()
    with pytest.raises(BlockRejected, match="candidate height"):
        apply_block(
            state,
            candidate_height=0,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=(),
            mint=Mint((make_output(0),), b"mint"),
            scheduled_subsidy=5,
            aggregate_fee_limit=100,
            max_transfers=16,
            max_total_proof_bytes=4096,
            verify_transfer=lambda *_: True,
            verify_mint=lambda *_: True,
        )
    with pytest.raises(BlockRejected, match="candidate parent"):
        run_block(state, headers, b"z" * 32, (), Mint((make_output(0),), b"mint"))


def test_block_rejects_wrong_chain_and_invalid_anchor():
    state = LedgerState.empty()
    headers, parent = branch()
    transfer = make_transfer(0, b"n" * 64, 0)
    wrong_chain_statement = TransactionStatementV1(
        chain_id=b"z" * 32,
        anchor_height=60,
        root_out=ANCHOR_ROOT,
        fee=0,
        nullifiers=(b"n" * 64,),
        outputs=(make_output(0),),
    )
    with pytest.raises(BlockRejected, match="chain ID mismatch"):
        run_block(state, headers, parent, [Transfer(wrong_chain_statement, b"valid")], Mint((make_output(1),), b"mint"))

    future_anchor = TransactionStatementV1(
        chain_id=CHAIN_ID,
        anchor_height=120,
        root_out=ANCHOR_ROOT,
        fee=0,
        nullifiers=(b"n" * 64,),
        outputs=(make_output(0),),
    )
    with pytest.raises(BlockRejected, match="anchor"):
        run_block(state, headers, parent, [Transfer(future_anchor, b"valid")], Mint((make_output(1),), b"mint"))


def test_block_rejects_zero_length_mint_even_when_verifier_accepts():
    state = LedgerState.empty()
    headers, parent = branch()
    with pytest.raises(BlockRejected, match="1..16"):
        apply_block(
            state,
            candidate_height=120,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=(),
            mint=Mint((), b"mint"),
            scheduled_subsidy=1,
            aggregate_fee_limit=100,
            max_transfers=16,
            max_total_proof_bytes=4096,
            verify_transfer=lambda *_: True,
            verify_mint=lambda *_: True,
        )
    assert state.tree.leaf_count == 0


def test_block_rejects_output_subclass_that_overrides_validation_methods():
    class LyingOutputRecord(OutputRecord):
        def serialize(self):
            return b"pretend canonical"

        def leaf_matches_fields(self):
            return True

    forged = LyingOutputRecord(b"x", b"bad", b"bad", b"bad", b"z" * 64)
    statement = TransactionStatementV1(
        chain_id=CHAIN_ID,
        anchor_height=60,
        root_out=ANCHOR_ROOT,
        fee=0,
        nullifiers=(b"n" * 64,),
        outputs=(forged,),
    )
    state = LedgerState.empty()
    headers, parent = branch()
    with pytest.raises(BlockRejected, match="canonical OutputRecord"):
        run_block(
            state,
            headers,
            parent,
            [Transfer(statement, b"valid")],
            Mint((make_output(1),), b"mint"),
        )
    assert state.tree.leaf_count == 0
    assert state.nullifiers == frozenset()


def test_transfer_verifier_receives_normalized_statement():
    original = make_transfer(0, b"n" * 64, 0)
    object.__setattr__(original.statement, "serialize", lambda: b"forged bytes")
    observed = []

    def verify_transfer(statement, proof):
        assert statement is not original.statement
        assert statement.serialize() == serialize_statement_v1(statement)
        observed.append(statement)
        return proof == b"valid"

    state = LedgerState.empty()
    headers, parent = branch()
    result = apply_block(
        state,
        candidate_height=120,
        parent_id=parent,
        headers=headers,
        chain_id=CHAIN_ID,
        transfers=[original],
        mint=Mint((make_output(1),), b"mint"),
        scheduled_subsidy=5,
        aggregate_fee_limit=100,
        max_transfers=16,
        max_total_proof_bytes=4096,
        verify_transfer=verify_transfer,
        verify_mint=lambda _mint, amount: amount == 5,
    )
    assert observed
    assert result.tree.leaf_count == 2


def test_verifier_callbacks_cannot_mutate_canonical_transfer_or_mint_snapshots():
    state = LedgerState.empty()
    headers, parent = branch()
    first_output, second_output, minted_output = (
        make_output(10), make_output(11), make_output(12)
    )
    first = make_transfer(10, b"a" * 64, 2, b"first")
    second = make_transfer(11, b"b" * 64, 3, b"second")
    caller_mint = Mint((minted_output,), b"mint")

    def verify_transfer(statement, proof):
        if proof == b"first":
            # Mutate the verifier-visible record and later caller-owned inputs.
            object.__setattr__(statement, "outputs", (make_output(90),))
            object.__setattr__(statement, "nullifiers", (b"x" * 64,))
            object.__setattr__(statement, "fee", 99)
            object.__setattr__(second.statement, "fee", 100)
            object.__setattr__(second.statement, "nullifiers", (b"y" * 64,))
            object.__setattr__(caller_mint, "outputs", (make_output(91),))
        return True

    def verify_mint(mint_record, expected_value):
        assert expected_value == 10  # subsidy 5 + snapshotted fees 2 + 3
        assert mint_record.outputs[0].commitment == minted_output.commitment
        object.__setattr__(mint_record, "outputs", (make_output(92),))
        return True

    result = apply_block(
        state,
        candidate_height=120,
        parent_id=parent,
        headers=headers,
        chain_id=CHAIN_ID,
        transfers=[first, second],
        mint=caller_mint,
        scheduled_subsidy=5,
        aggregate_fee_limit=100,
        max_transfers=16,
        max_total_proof_bytes=4096,
        verify_transfer=verify_transfer,
        verify_mint=verify_mint,
    )

    assert result.tree.leaf_count == 3
    assert tuple(result.tree.leaf_at(i) for i in range(3)) == (
        first_output.leaf, second_output.leaf, minted_output.leaf
    )
    assert result.nullifiers == frozenset((b"a" * 64, b"b" * 64))
    assert result.commitments == frozenset((
        first_output.commitment, second_output.commitment, minted_output.commitment
    ))


def test_verifier_callback_cannot_rewrite_selected_anchor_ancestry():
    state = LedgerState.empty()
    headers, parent = branch()
    anchor_id = bytes([1]) + (60).to_bytes(31, "little")
    original_anchor = headers[anchor_id]
    first = make_transfer(20, b"c" * 64, 0, b"first")
    second = make_transfer(21, b"d" * 64, 0, b"second")

    def verify_transfer(_statement, proof):
        if proof == b"first":
            # Mutate both the record object and the caller's header index after
            # the block has selected and snapshotted its ancestry.
            object.__setattr__(original_anchor, "output_root", b"!" * 64)
            headers[anchor_id] = BlockHeaderRef(
                anchor_id,
                original_anchor.parent_id,
                original_anchor.height,
                b"!" * 64,
            )
        return True

    result = apply_block(
        state,
        candidate_height=120,
        parent_id=parent,
        headers=headers,
        chain_id=CHAIN_ID,
        transfers=[first, second],
        mint=Mint((make_output(22),), b"mint"),
        scheduled_subsidy=5,
        aggregate_fee_limit=100,
        max_transfers=16,
        max_total_proof_bytes=4096,
        verify_transfer=verify_transfer,
        verify_mint=lambda _mint, amount: amount == 5,
    )

    assert result.tree.leaf_count == 3
    assert result.nullifiers == frozenset((b"c" * 64, b"d" * 64))


def test_block_does_not_trust_shadowed_record_serializers():
    output = make_output(0)
    object.__setattr__(output, "leaf", b"!" * 64)
    object.__setattr__(output, "leaf_matches_fields", lambda: True)
    object.__setattr__(output, "serialize", lambda: b"pretend canonical")
    statement = TransactionStatementV1(
        CHAIN_ID, 60, ANCHOR_ROOT, 0, (b"n" * 64,), (output,)
    )
    object.__setattr__(statement, "serialize", lambda: b"pretend canonical")

    state = LedgerState.empty()
    headers, parent = branch()
    with pytest.raises(BlockRejected, match="output leaf"):
        run_block(
            state,
            headers,
            parent,
            [Transfer(statement, b"valid")],
            Mint((make_output(1),), b"mint"),
        )
    assert state.tree.leaf_count == 0


def test_uniqueness_checks_cover_parent_transfer_and_mint_outputs():
    headers, parent = branch()
    output = make_output(0)
    nf = b"n" * 64
    parent_with_nullifier = LedgerState(OutputTree(), nullifiers=frozenset((nf,)))
    with pytest.raises(BlockRejected, match="duplicate nullifier"):
        run_block(
            parent_with_nullifier,
            headers,
            parent,
            [make_transfer(0, nf, 0)],
            Mint((make_output(1),), b"mint"),
        )

    parent_with_commitment = LedgerState(
        OutputTree(), commitments=frozenset((output.commitment,))
    )
    with pytest.raises(BlockRejected, match="duplicate output commitment"):
        run_block(
            parent_with_commitment,
            headers,
            parent,
            [Transfer(TransactionStatementV1(CHAIN_ID, 60, ANCHOR_ROOT, 0, (nf,), (output,)), b"valid")],
            Mint((make_output(1),), b"mint"),
        )

    state = LedgerState.empty()
    duplicate_output_transfers = [
        make_transfer(0, b"a" * 64, 0),
        make_transfer(0, b"b" * 64, 0),
    ]
    with pytest.raises(BlockRejected, match="duplicate output commitment"):
        run_block(
            state,
            headers,
            parent,
            duplicate_output_transfers,
            Mint((make_output(2),), b"mint"),
        )

    with pytest.raises(BlockRejected, match="mint contains duplicate commitments"):
        run_block(state, headers, parent, [], Mint((output, output), b"mint"))

    transfer = make_transfer(0, nf, 0)
    with pytest.raises(BlockRejected, match="mint commitment duplicates"):
        run_block(
            state,
            headers,
            parent,
            [transfer],
            Mint((transfer.statement.outputs[0],), b"mint"),
        )
    assert state.tree.leaf_count == 0


def test_structural_rejections_precede_all_verifier_callbacks():
    headers, parent = branch()
    calls = []

    def transfer_verifier(*_args):
        calls.append("transfer")
        return True

    def mint_verifier(*_args):
        calls.append("mint")
        return True

    duplicate_transfers = [
        make_transfer(0, b"duplicate".ljust(64, b"!"), 0),
        make_transfer(1, b"duplicate".ljust(64, b"!"), 0),
    ]
    with pytest.raises(BlockRejected, match="duplicate nullifier"):
        run_block(
            LedgerState.empty(),
            headers,
            parent,
            duplicate_transfers,
            Mint((make_output(2),), b"mint"),
            verify_transfer=transfer_verifier,
            verify_mint=mint_verifier,
        )
    assert calls == []

    with pytest.raises(BlockRejected, match="aggregate transfer fees"):
        run_block(
            LedgerState.empty(),
            headers,
            parent,
            [make_transfer(3, b"fee".ljust(64, b"!"), 101)],
            Mint((make_output(4),), b"mint"),
            verify_transfer=transfer_verifier,
            verify_mint=mint_verifier,
        )
    assert calls == []


def test_fee_cap_and_output_leaf_binding_fail_closed():
    state = LedgerState.empty()
    headers, parent = branch()
    with pytest.raises(BlockRejected, match="aggregate transfer fees"):
        apply_block(
            state,
            candidate_height=120,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=[make_transfer(0, b"n" * 64, 101)],
            mint=Mint((make_output(1),), b"mint"),
            scheduled_subsidy=5,
            aggregate_fee_limit=100,
            max_transfers=16,
            max_total_proof_bytes=4096,
            verify_transfer=lambda *_: True,
            verify_mint=lambda *_: True,
        )

    output = make_output(0)
    altered = OutputRecord(
        output.commitment, output.kem_ciphertext, output.nonce, output.ciphertext, b"q" * 64
    )
    malformed_statement = TransactionStatementV1(
        CHAIN_ID, 60, ANCHOR_ROOT, 0, (b"m" * 64,), (altered,)
    )
    with pytest.raises(BlockRejected, match="leaf does not match"):
        run_block(
            state,
            headers,
            parent,
            [Transfer(malformed_statement, b"valid")],
            Mint((make_output(1),), b"mint"),
        )
    assert state.tree.leaf_count == 0


def test_configured_transfer_count_limit_is_enforced():
    state = LedgerState.empty()
    headers, parent = branch()
    with pytest.raises(BlockRejected, match="transfer count"):
        apply_block(
            state,
            candidate_height=120,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=[make_transfer(0, b"n" * 64, 0)],
            mint=Mint((make_output(1),), b"mint"),
            scheduled_subsidy=0,
            aggregate_fee_limit=0,
            max_transfers=0,
            max_total_proof_bytes=4096,
            verify_transfer=lambda *_: True,
            verify_mint=lambda *_: True,
        )


def test_total_proof_byte_limit_rejects_before_callbacks_and_accepts_exact_limit():
    state = LedgerState.empty()
    headers, parent = branch()
    verifier_calls = []
    transfers = [make_transfer(0, b"n" * 64, 0, b"valid")]
    mint = Mint((make_output(1),), b"mint")

    def apply_with_cap(cap):
        return apply_block(
            state,
            candidate_height=120,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=transfers,
            mint=mint,
            scheduled_subsidy=5,
            aggregate_fee_limit=0,
            max_transfers=16,
            max_total_proof_bytes=cap,
            verify_transfer=lambda *_: verifier_calls.append("transfer") or True,
            verify_mint=lambda *_: verifier_calls.append("mint") or True,
        )

    with pytest.raises(BlockRejected, match="total proof bytes"):
        apply_with_cap(8)

    assert verifier_calls == []
    assert state.tree.leaf_count == 0

    accepted = apply_with_cap(9)  # b"valid" + b"mint" is exactly nine bytes.
    assert verifier_calls == ["transfer", "mint"]
    assert accepted.tree.leaf_count == 2
    assert state.tree.leaf_count == 0


def test_total_proof_byte_limit_precedes_statement_serialization(monkeypatch):
    import radix_core.state as state_module

    state = LedgerState.empty()
    headers, parent = branch()
    transfer = make_transfer(0, b"n" * 64, 0, b"oversized")
    mint = Mint((make_output(1),), b"mint")

    def unexpected_serialization(_statement):
        pytest.fail("statement serialization ran before proof-byte rejection")

    monkeypatch.setattr(state_module, "serialize_statement_v1", unexpected_serialization)
    with pytest.raises(BlockRejected, match="total proof bytes"):
        apply_block(
            state,
            candidate_height=120,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=[transfer],
            mint=mint,
            scheduled_subsidy=0,
            aggregate_fee_limit=0,
            max_transfers=16,
            max_total_proof_bytes=12,
            verify_transfer=lambda *_: pytest.fail("transfer verifier ran before rejection"),
            verify_mint=lambda *_: pytest.fail("mint verifier ran before rejection"),
        )

    assert state.tree.leaf_count == 0


def test_proof_byte_cap_counts_the_exact_transfer_bytes_later_verified(monkeypatch):
    import radix_core.state as state_module

    state = LedgerState.empty()
    headers, parent = branch()
    original_transfer = make_transfer(0, b"n" * 64, 0, b"valid")
    real_snapshot = state_module._snapshot_transfer
    verified_proofs = []

    def mutate_caller_record_after_cap(captured_transfer, index):
        # Simulate an adversarial concurrent caller mutation at the old
        # cap-check/snapshot boundary. The verifier must still receive the
        # immutable proof bytes that were actually measured.
        object.__setattr__(original_transfer, "proof", b"x" * 4096)
        return real_snapshot(captured_transfer, index)

    monkeypatch.setattr(state_module, "_snapshot_transfer", mutate_caller_record_after_cap)
    result = apply_block(
        state,
        candidate_height=120,
        parent_id=parent,
        headers=headers,
        chain_id=CHAIN_ID,
        transfers=[original_transfer],
        mint=Mint((make_output(1),), b"mint"),
        scheduled_subsidy=5,
        aggregate_fee_limit=0,
        max_transfers=16,
        max_total_proof_bytes=9,
        verify_transfer=lambda _statement, proof: verified_proofs.append(proof) or proof == b"valid",
        verify_mint=lambda mint_record, value: mint_record.proof == b"mint" and value == 5,
    )

    assert verified_proofs == [b"valid"]
    assert result.tree.leaf_count == 2
    assert state.tree.leaf_count == 0


def test_proof_byte_cap_counts_the_exact_mint_bytes_later_verified(monkeypatch):
    import radix_core.state as state_module

    state = LedgerState.empty()
    headers, parent = branch()
    transfer = make_transfer(0, b"n" * 64, 0, b"valid")
    original_mint = Mint((make_output(1),), b"mint")
    real_snapshot = state_module._snapshot_transfer
    verified_mint_proofs = []

    def mutate_mint_after_cap(captured_transfer, index):
        object.__setattr__(original_mint, "proof", b"y" * 4096)
        return real_snapshot(captured_transfer, index)

    monkeypatch.setattr(state_module, "_snapshot_transfer", mutate_mint_after_cap)
    result = apply_block(
        state,
        candidate_height=120,
        parent_id=parent,
        headers=headers,
        chain_id=CHAIN_ID,
        transfers=[transfer],
        mint=original_mint,
        scheduled_subsidy=5,
        aggregate_fee_limit=0,
        max_transfers=16,
        max_total_proof_bytes=9,
        verify_transfer=lambda _statement, proof: proof == b"valid",
        verify_mint=lambda mint_record, value: verified_mint_proofs.append(mint_record.proof)
        or (mint_record.proof == b"mint" and value == 5),
    )

    assert verified_mint_proofs == [b"mint"]
    assert result.tree.leaf_count == 2
    assert state.tree.leaf_count == 0


def test_total_statement_byte_limit_rejects_over_budget_and_accepts_exact_limit():
    state = LedgerState.empty()
    headers, parent = branch()
    transfer = make_transfer(0, b"n" * 64, 5)
    mint = Mint((make_output(1),), b"mint")
    statement_size = len(serialize_statement_v1(transfer.statement))

    with pytest.raises(BlockRejected, match="total statement bytes"):
        run_block(
            state,
            headers,
            parent,
            [transfer],
            mint,
            max_total_statement_bytes=statement_size - 1,
            verify_transfer=lambda *_: pytest.fail(
                "transfer verifier ran before statement-budget rejection"
            ),
            verify_mint=lambda *_: pytest.fail(
                "mint verifier ran before statement-budget rejection"
            ),
        )

    assert state.tree.leaf_count == 0
    result = run_block(
        state,
        headers,
        parent,
        [transfer],
        mint,
        max_total_statement_bytes=statement_size,
    )
    assert result.tree.leaf_count == 2
    assert state.tree.leaf_count == 0


def test_mint_total_must_fit_nonzero_u64_outputs_before_verifier_call():
    assert MAX_MINT_AMOUNT == 16 * U64_MAX
    state = LedgerState.empty()
    headers, parent = branch()

    for subsidy in (0, MAX_MINT_AMOUNT + 1):
        verifier_called = False

        def verify_mint(_mint, _amount):
            nonlocal verifier_called
            verifier_called = True
            return True

        with pytest.raises(BlockRejected, match="mint total|scheduled subsidy"):
            apply_block(
                state,
                candidate_height=120,
                parent_id=parent,
                headers=headers,
                chain_id=CHAIN_ID,
                transfers=(),
                mint=Mint((make_output(0),), b"mint"),
                scheduled_subsidy=subsidy,
                aggregate_fee_limit=0,
                max_transfers=0,
                max_total_proof_bytes=4096,
                verify_transfer=lambda *_: True,
                verify_mint=verify_mint,
            )
        assert not verifier_called
        assert state.tree.leaf_count == 0


def test_ledger_state_defensively_copies_tree_and_exposes_read_only_count():
    source = OutputTree()
    first, second = make_output(0), make_output(1)
    source.append(first.leaf)
    state = LedgerState(source)
    source.append(second.leaf)
    assert state.tree.leaf_count == 1
    assert state.tree.leaf_at(0) == first.leaf

    exposed = state.tree
    exposed.append(second.leaf)
    assert state.tree.leaf_count == 1
    with pytest.raises(AttributeError):
        source.leaf_count = 99
    with pytest.raises(ValueError, match="nullifiers"):
        LedgerState(OutputTree(), frozenset((b"short",)))


def test_block_rejects_state_whose_root_does_not_match_parent_header():
    mismatched_tree = OutputTree()
    mismatched_tree.append(make_output(9).leaf)
    state = LedgerState(mismatched_tree)
    headers, parent = branch()
    with pytest.raises(BlockRejected, match="parent state output root"):
        apply_block(
            state,
            candidate_height=120,
            parent_id=parent,
            headers=headers,
            chain_id=CHAIN_ID,
            transfers=(),
            mint=Mint((make_output(0),), b"mint"),
            scheduled_subsidy=0,
            aggregate_fee_limit=0,
            max_transfers=0,
            max_total_proof_bytes=4096,
            verify_transfer=lambda *_: True,
            verify_mint=lambda *_: True,
        )
    assert state.tree.root == mismatched_tree.root


def test_block_rejects_malformed_parent_header_without_attribute_error():
    state = LedgerState.empty()
    headers, parent = branch()
    headers[parent] = object()
    with pytest.raises(BlockRejected, match="candidate parent is missing, malformed"):
        run_block(state, headers, parent, (), Mint((make_output(0),), b"mint"))


def test_block_rejects_corrupted_internal_tree_even_if_header_root_matches_it():
    state = LedgerState.empty()
    headers, parent = branch()
    parent_header = headers[parent]
    forged_root = b"z" * 64
    state._tree._nodes[64][0] = forged_root
    headers[parent] = BlockHeaderRef(
        parent, parent_header.parent_id, parent_header.height, forged_root
    )
    with pytest.raises(BlockRejected, match="tree integrity check failed"):
        run_block(state, headers, parent, (), Mint((make_output(0),), b"mint"))
