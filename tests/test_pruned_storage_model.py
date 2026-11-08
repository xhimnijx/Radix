import re
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import pytest

from radix_core.pruned_storage_model import (
    DECIMAL_TB,
    MAX_DEPTH64_PROOF_PAYLOAD_BYTES,
    MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES,
    MAX_STATEMENT_BYTES,
    STATEMENT_BOUND_ENVELOPE_HEADER_BYTES,
    StorageAssumptions,
    estimate_storage,
    format_report,
    max_block_payload_bytes_below_pruned_target,
    max_single_envelope_per_checkpoint_assumptions,
    uncompressed_wallet_path_storage_bytes,
    uncompressed_wallet_record_and_path_bytes,
)


def test_default_scenario_keeps_pruned_and_archive_ledgers_separate():
    assumptions = StorageAssumptions()
    result = estimate_storage(assumptions)

    assert result.horizon_blocks == 7_889_400  # 1,440/day × 365.25 × 15
    assert result.recent_blocks == 43_200  # 30 days × 1,440/day
    assert result.target_bytes == DECIMAL_TB
    assert result.max_envelope_block_payload_headroom_bytes == -65_112_978
    assert not result.max_envelope_fits_block_payload
    assert result.pruned_target_strictly_met == (result.pruned_node_total_bytes < DECIMAL_TB)
    assert result.pruned_node_total_bytes == sum(
        (
            result.recent_window_payload_bytes,
            result.all_chain_headers_and_header_db_bytes,
            result.retained_recent_indexes_bytes,
            result.all_nullifier_state_bytes,
            result.all_commitment_state_bytes,
            result.compact_tree_frontier_bytes,
            result.anchor_root_history_bytes,
            result.checkpoint_records_bytes,
        )
    )
    assert result.archive_payload_bytes > result.recent_window_payload_bytes
    assert result.full_archive_total_bytes > result.pruned_node_total_bytes
    assert result.assumptions_are_protocol_enforced is False


def test_envelope_payload_fit_flag_uses_unwrapped_exact_capacity():
    base = StorageAssumptions()
    exact_fit = estimate_storage(
        replace(base, max_block_payload_bytes=MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES)
    )

    assert exact_fit.max_envelope_block_payload_headroom_bytes == 0
    assert exact_fit.max_envelope_fits_block_payload
    report = format_report(base, estimate_storage(base))
    assert "RDXL max envelope fits block payload before transaction wrapper: NO" in report


def test_rdxl_envelope_model_caps_match_rust_decoder_limits():
    root = Path(__file__).resolve().parents[1]
    rust_source = (root / "archive" / "candidate-a" / "proof_harness" / "src" / "depth64_path_opening.rs").read_text(
        encoding="utf-8"
    )
    statement_match = re.search(
        r"const MAX_STATEMENT_BYTES: usize = (\d+);", rust_source
    )
    proof_match = re.search(
        r"const MAX_PROOF_BYTES: usize = (\d+) \* 1024 \* 1024;", rust_source
    )
    header_match = re.search(
        r"const STATEMENT_HEADER_BYTES: usize = ([^;]+);", rust_source
    )

    assert statement_match is not None
    assert proof_match is not None
    assert header_match is not None
    rust_statement_bytes = int(statement_match.group(1))
    rust_proof_bytes = int(proof_match.group(1)) * 1024 * 1024
    rust_header_bytes = sum(int(part.strip()) for part in header_match.group(1).split("+"))
    assert MAX_STATEMENT_BYTES == rust_statement_bytes
    assert MAX_DEPTH64_PROOF_PAYLOAD_BYTES == rust_proof_bytes
    assert STATEMENT_BOUND_ENVELOPE_HEADER_BYTES == rust_header_bytes
    assert MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES == (
        rust_statement_bytes + rust_proof_bytes + rust_header_bytes
    )


def test_pruned_window_cannot_exceed_modeled_block_horizon():
    one_year_window = StorageAssumptions(years=1, pruned_window_days=365)
    assert one_year_window.recent_blocks <= one_year_window.horizon_blocks

    with pytest.raises(ValueError, match="modeled horizon in blocks"):
        StorageAssumptions(years=1, pruned_window_days=366)


def test_solved_block_payload_cap_is_the_largest_integer_meeting_strict_target():
    base = StorageAssumptions()
    cap = max_block_payload_bytes_below_pruned_target(base)

    assert cap is not None
    at_cap = estimate_storage(replace(base, max_block_payload_bytes=cap))
    above_cap = estimate_storage(replace(base, max_block_payload_bytes=cap + 1))
    assert at_cap.pruned_target_strictly_met
    assert above_cap.pruned_node_total_bytes >= base.target_bytes
    assert cap >= base.max_block_payload_bytes
    assert cap == 13_033_193
    assert cap < MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES

    envelope_sensitivity = max_single_envelope_per_checkpoint_assumptions(base)
    sensitivity_cap = max_block_payload_bytes_below_pruned_target(envelope_sensitivity)
    assert sensitivity_cap is not None
    assert sensitivity_cap < cap


def test_payload_cap_solver_handles_strict_one_byte_boundary():
    base = StorageAssumptions(max_block_payload_bytes=1)
    result = estimate_storage(base)
    fixed_bytes = result.pruned_node_total_bytes - result.recent_window_payload_bytes
    multiplier = base.recent_payload_multiplier
    one_byte_window_payload = (
        base.recent_blocks * multiplier.numerator + multiplier.denominator - 1
    ) // multiplier.denominator

    exact_one_byte_target = replace(
        base, target_bytes=fixed_bytes + one_byte_window_payload + 1
    )
    assert max_block_payload_bytes_below_pruned_target(exact_one_byte_target) == 1

    strict_target_miss = replace(
        base, target_bytes=fixed_bytes + one_byte_window_payload
    )
    assert max_block_payload_bytes_below_pruned_target(strict_target_miss) is None


def test_max_envelope_checkpoint_sensitivity_is_bounded_but_not_a_guarantee():
    base = StorageAssumptions()
    stress = max_single_envelope_per_checkpoint_assumptions(base)
    result = estimate_storage(stress)

    assert stress.max_checkpoint_record_bytes == MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES
    assert stress.max_checkpoint_record_bytes == 64 * 1024 * 1024 + 4_096 + 18
    assert result.pruned_node_total_bytes > estimate_storage(base).pruned_node_total_bytes
    assert result.pruned_target_strictly_met
    assert result.assumptions_are_protocol_enforced is False


def test_long_lived_nullifier_state_is_not_pruned_with_block_bodies():
    base = StorageAssumptions()
    thirty_days = estimate_storage(base)
    sixty_days = estimate_storage(replace(base, pruned_window_days=60))

    assert sixty_days.recent_window_payload_bytes == 2 * thirty_days.recent_window_payload_bytes
    assert sixty_days.retained_recent_indexes_bytes == 2 * thirty_days.retained_recent_indexes_bytes
    assert sixty_days.all_nullifier_state_bytes == thirty_days.all_nullifier_state_bytes
    assert sixty_days.all_commitment_state_bytes == thirty_days.all_commitment_state_bytes
    assert sixty_days.all_chain_headers_and_header_db_bytes == thirty_days.all_chain_headers_and_header_db_bytes
    assert sixty_days.checkpoint_records_bytes == thirty_days.checkpoint_records_bytes
    assert sixty_days.full_archive_total_bytes == thirty_days.full_archive_total_bytes
    assert sixty_days.pruned_node_total_bytes - thirty_days.pruned_node_total_bytes == (
        sixty_days.recent_window_payload_bytes
        - thirty_days.recent_window_payload_bytes
        + sixty_days.retained_recent_indexes_bytes
        - thirty_days.retained_recent_indexes_bytes
    )


def test_long_lived_commitment_uniqueness_state_scales_with_max_outputs():
    base = StorageAssumptions()
    more_outputs = replace(base, max_outputs_per_block=base.max_outputs_per_block * 2)

    base_result = estimate_storage(base)
    more_outputs_result = estimate_storage(more_outputs)
    assert more_outputs_result.all_commitment_state_bytes == (
        2 * base_result.all_commitment_state_bytes
    )
    assert more_outputs_result.pruned_node_total_bytes > base_result.pruned_node_total_bytes


def test_output_tree_frontier_is_fixed_size_under_append_only_tree_assumption():

    base = StorageAssumptions()
    more_spends = replace(base, max_spends_per_block=base.max_spends_per_block * 10)

    base_result = estimate_storage(base)
    more_spends_result = estimate_storage(more_spends)
    assert base_result.compact_tree_frontier_bytes == 65 * 64
    assert more_spends_result.compact_tree_frontier_bytes == base_result.compact_tree_frontier_bytes
    assert more_spends_result.recent_window_payload_bytes == base_result.recent_window_payload_bytes
    assert more_spends_result.retained_recent_indexes_bytes == base_result.retained_recent_indexes_bytes
    assert more_spends_result.all_nullifier_state_bytes > base_result.all_nullifier_state_bytes
    assert more_spends_result.full_archive_total_bytes > base_result.full_archive_total_bytes


def test_wallet_path_storage_is_separate_raw_per_note_estimate():
    assumptions = StorageAssumptions()

    assert uncompressed_wallet_path_storage_bytes(0, assumptions) == 0
    assert uncompressed_wallet_path_storage_bytes(1, assumptions) == 4_096
    assert uncompressed_wallet_path_storage_bytes(1_000_000, assumptions) == 4_096_000_000
    with pytest.raises(ValueError, match="nonnegative integer"):
        uncompressed_wallet_path_storage_bytes(True, assumptions)
    with pytest.raises(ValueError, match="nonnegative integer"):
        uncompressed_wallet_path_storage_bytes(-1, assumptions)


def test_wallet_record_and_path_storage_uses_explicit_serialized_record_size():
    assumptions = StorageAssumptions()

    assert uncompressed_wallet_record_and_path_bytes(0, 1_941, assumptions) == 0
    assert uncompressed_wallet_record_and_path_bytes(1, 1_429, assumptions) == 5_525
    assert uncompressed_wallet_record_and_path_bytes(1, 1_941, assumptions) == 6_037
    assert uncompressed_wallet_record_and_path_bytes(1_000_000, 1_429, assumptions) == (
        5_525_000_000
    )
    assert uncompressed_wallet_record_and_path_bytes(1_000_000, 1_941, assumptions) == (
        6_037_000_000
    )
    with pytest.raises(ValueError, match="nonnegative integer"):
        uncompressed_wallet_record_and_path_bytes(True, 1_941, assumptions)
    with pytest.raises(ValueError, match="positive integer"):
        uncompressed_wallet_record_and_path_bytes(1, 0, assumptions)


def test_strict_target_does_not_accept_exactly_one_decimal_terabyte():
    base = StorageAssumptions()
    base_result = estimate_storage(base)
    exact_limit = estimate_storage(replace(base, target_bytes=base_result.pruned_node_total_bytes))

    assert exact_limit.pruned_target_headroom_bytes == 0
    assert not exact_limit.pruned_target_exceeded
    assert not exact_limit.pruned_target_strictly_met


def test_target_comparison_uses_decimal_terabyte():
    assumptions = StorageAssumptions(
        max_blocks_per_day=1,
        max_block_payload_bytes=1,
        pruned_window_days=1,
        max_transactions_per_block=1,
        max_outputs_per_block=1,
        max_spends_per_block=1,
        header_bytes_per_block=1,
        block_index_bytes=1,
        transaction_index_bytes=1,
        output_index_bytes=1,
        nullifier_entry_bytes=1,
        nullifier_index_multiplier=Fraction(1, 1),
        recent_payload_multiplier=Fraction(1, 1),
        archive_payload_multiplier=Fraction(1, 1),
        header_storage_multiplier=Fraction(1, 1),
        checkpoint_interval_blocks=10**9,
        max_checkpoint_record_bytes=1,
        checkpoint_storage_multiplier=Fraction(1, 1),
        anchor_root_history_blocks=1,
        tree_depth=1,
        digest_bytes=1,
        target_bytes=1,
    )
    result = estimate_storage(assumptions)
    assert assumptions.target_bytes == 1  # all quantities are bytes, not GiB/TiB
    assert result.pruned_target_exceeded
    assert result.pruned_target_headroom_bytes < 0


def test_report_disclaims_unenforced_assumptions_and_separates_archive():
    assumptions = StorageAssumptions()
    text = format_report(assumptions, estimate_storage(assumptions))
    assert "not a protocol guarantee" in text
    assert "Pruned-node retained categories" in text
    assert "strictly below 1 TB target: yes" in text
    assert "Full archive (informational only; no 1 TB cap applies)" in text
    assert "Checkpoint assumption: 790 records, each up to 262,144 B" in text
    assert "RDXL max proof+statement envelope: 67,112,978 B (before transaction wrapper)" in text
    assert "RDXL envelope-only block-payload headroom: -65,112,978 B" in text
    assert "largest block-payload cap under these other assumptions:" in text
    assert "not measured or consensus-enforced" in text


@pytest.mark.parametrize(
    "changes",
    [
        {"years": 0},
        {"max_blocks_per_day": 0},
        {"max_block_payload_bytes": 0},
        {"pruned_window_days": 0},
        {"max_spends_per_block": -1},
        {"pruned_window_days": 365 * 16},
        {"recent_payload_multiplier": Fraction(0, 1)},
        {"nullifier_index_multiplier": 1.5},
        {"commitment_index_multiplier": 1.5},
        {"commitment_entry_bytes": 0},
    ],
)
def test_model_rejects_unbounded_or_invalid_assumptions(changes):
    with pytest.raises(ValueError):
        StorageAssumptions(**changes)
