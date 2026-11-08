"""Conditional storage arithmetic for a Candidate-A pruned node.

This is a planning model, not a protocol guarantee. Every value that could
bound growth is an explicit assumption; current protocol drafts do not enforce
these caps. Its 15-year horizon is a finite planning window, not a lifetime
storage bound: full-history uniqueness state continues growing unless a
consensus-authenticated bounded representation preserves duplicate rejection.
The pruned-node acceptance threshold is strictly below 10^12 decimal bytes;
the full-archive estimate is informational and has no 1 TB cap.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from fractions import Fraction
from math import ceil

DECIMAL_TB = 1_000_000_000_000
DAYS_PER_YEAR = Fraction(36525, 100)
MAX_DEPTH64_PROOF_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_STATEMENT_BYTES = 4_096
STATEMENT_BOUND_ENVELOPE_HEADER_BYTES = 18
MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES = (
    MAX_DEPTH64_PROOF_PAYLOAD_BYTES
    + MAX_STATEMENT_BYTES
    + STATEMENT_BOUND_ENVELOPE_HEADER_BYTES
)


def _positive(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _ceil_fraction(value: int, factor: Fraction) -> int:
    if factor <= 0:
        raise ValueError("storage multipliers must be positive")
    return (value * factor.numerator + factor.denominator - 1) // factor.denominator


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


@dataclass(frozen=True)
class StorageAssumptions:
    """Finite conditional caps needed to produce a numeric upper envelope."""

    years: int = 15
    max_blocks_per_day: int = 1_440
    max_block_payload_bytes: int = 2_000_000
    pruned_window_days: int = 30
    max_transactions_per_block: int = 100
    max_outputs_per_block: int = 100
    max_spends_per_block: int = 100
    header_bytes_per_block: int = 256
    block_index_bytes: int = 4_096
    transaction_index_bytes: int = 64
    output_index_bytes: int = 16
    nullifier_entry_bytes: int = 112
    nullifier_index_multiplier: Fraction = Fraction(3, 2)
    commitment_entry_bytes: int = 112
    commitment_index_multiplier: Fraction = Fraction(3, 2)
    recent_payload_multiplier: Fraction = Fraction(13, 10)
    archive_payload_multiplier: Fraction = Fraction(13, 10)
    header_storage_multiplier: Fraction = Fraction(11, 10)
    checkpoint_interval_blocks: int = 10_000
    max_checkpoint_record_bytes: int = 262_144
    checkpoint_storage_multiplier: Fraction = Fraction(11, 10)
    anchor_root_history_blocks: int = 60
    tree_depth: int = 64
    digest_bytes: int = 64
    target_bytes: int = DECIMAL_TB

    def __post_init__(self) -> None:
        for name in (
            "years",
            "max_blocks_per_day",
            "max_block_payload_bytes",
            "pruned_window_days",
            "max_transactions_per_block",
            "max_outputs_per_block",
            "max_spends_per_block",
            "header_bytes_per_block",
            "block_index_bytes",
            "transaction_index_bytes",
            "output_index_bytes",
            "nullifier_entry_bytes",
            "commitment_entry_bytes",
            "checkpoint_interval_blocks",
            "max_checkpoint_record_bytes",
            "anchor_root_history_blocks",
            "tree_depth",
            "digest_bytes",
            "target_bytes",
        ):
            _positive(name, getattr(self, name))
        if self.pruned_window_days * self.max_blocks_per_day > self.horizon_blocks:
            raise ValueError("pruned window cannot exceed the modeled horizon in blocks")
        for name in (
            "nullifier_index_multiplier",
            "commitment_index_multiplier",
            "recent_payload_multiplier",
            "archive_payload_multiplier",
            "header_storage_multiplier",
            "checkpoint_storage_multiplier",
        ):
            factor = getattr(self, name)
            if not isinstance(factor, Fraction) or factor <= 0:
                raise ValueError(f"{name} must be a positive Fraction")

    @property
    def horizon_blocks(self) -> int:
        numerator = self.max_blocks_per_day * DAYS_PER_YEAR.numerator * self.years
        return _ceil_div(numerator, DAYS_PER_YEAR.denominator)

    @property
    def recent_blocks(self) -> int:
        return self.max_blocks_per_day * self.pruned_window_days

    @property
    def checkpoint_records(self) -> int:
        # Reserve one genesis/initial checkpoint in addition to every interval,
        # including a possibly partial final interval.
        return 1 + _ceil_div(self.horizon_blocks, self.checkpoint_interval_blocks)

    @property
    def fixed_tree_frontier_bytes(self) -> int:
        # A depth-d append frontier stores at most one digest per level plus a
        # root. This excludes DB metadata and assumes the append-only tree model.
        return (self.tree_depth + 1) * self.digest_bytes


def uncompressed_wallet_path_storage_bytes(
    note_count: int,
    assumptions: StorageAssumptions = StorageAssumptions(),
) -> int:
    """Return raw bytes for one retained depth-d path per note.

    This wallet-side witness estimate is deliberately separate from pruned-node
    totals. It excludes anchors, indices, output records, database overhead, and
    any protocol-unspecified path compression.
    """

    if (
        isinstance(note_count, bool)
        or not isinstance(note_count, int)
        or note_count < 0
    ):
        raise ValueError("note_count must be a nonnegative integer")
    return note_count * assumptions.tree_depth * assumptions.digest_bytes


def uncompressed_wallet_record_and_path_bytes(
    note_count: int,
    output_record_bytes: int,
    assumptions: StorageAssumptions = StorageAssumptions(),
) -> int:
    """Return raw bytes for one serialized output record and depth-d path per note.

    The caller supplies the serialized record size for the selected wire profile.
    This excludes anchors, indices, database overhead, and path compression.
    """

    if (
        isinstance(note_count, bool)
        or not isinstance(note_count, int)
        or note_count < 0
    ):
        raise ValueError("note_count must be a nonnegative integer")
    _positive("output_record_bytes", output_record_bytes)
    path_bytes = assumptions.tree_depth * assumptions.digest_bytes
    return note_count * (output_record_bytes + path_bytes)


def max_single_envelope_per_checkpoint_assumptions(
    base: StorageAssumptions = StorageAssumptions(),
) -> StorageAssumptions:
    """Return a sensitivity with one max-size statement-bound proof per checkpoint.

    This is not a bound on a complete checkpoint/transition record: it includes
    only the current RDXL proof-payload, statement, and envelope-header limits.
    """

    return replace(
        base,
        max_checkpoint_record_bytes=MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES,
    )


@dataclass(frozen=True)
class StorageBreakdown:
    horizon_blocks: int
    recent_blocks: int
    max_envelope_block_payload_headroom_bytes: int
    max_envelope_fits_block_payload: bool
    recent_window_payload_bytes: int
    all_chain_headers_and_header_db_bytes: int
    retained_recent_indexes_bytes: int
    all_nullifier_state_bytes: int
    all_commitment_state_bytes: int
    compact_tree_frontier_bytes: int
    anchor_root_history_bytes: int
    checkpoint_records_bytes: int
    pruned_node_total_bytes: int
    archive_payload_bytes: int
    archive_indexes_bytes: int
    full_archive_total_bytes: int
    target_bytes: int
    pruned_target_headroom_bytes: int
    pruned_target_exceeded: bool
    pruned_target_strictly_met: bool
    assumptions_are_protocol_enforced: bool = False

    def as_dict(self) -> dict[str, int | bool]:
        return asdict(self)


def estimate_storage(assumptions: StorageAssumptions = StorageAssumptions()) -> StorageBreakdown:
    """Return independent pruned-node and full-archive planning totals.

    `max_block_payload_bytes` is the entire canonical block payload including
    transactions, proofs, and ciphertexts. The separately modeled header is not
    included in that payload cap. Database multipliers and index entry sizes are
    explicit, conditional assumptions rather than measured production overhead.
    """

    a = assumptions
    horizon = a.horizon_blocks
    recent = a.recent_blocks
    recent_payload = _ceil_fraction(
        recent * a.max_block_payload_bytes, a.recent_payload_multiplier
    )
    all_headers = _ceil_fraction(
        horizon * a.header_bytes_per_block, a.header_storage_multiplier
    )
    recent_indexes = recent * (
        a.block_index_bytes
        + a.max_transactions_per_block * a.transaction_index_bytes
        + a.max_outputs_per_block * a.output_index_bytes
    )
    nullifier_state = _ceil_fraction(
        horizon * a.max_spends_per_block * a.nullifier_entry_bytes,
        a.nullifier_index_multiplier,
    )
    # apply_block checks output-commitment uniqueness across all prior blocks;
    # pruning old bodies does not remove that full-horizon consensus-state need.
    commitment_state = _ceil_fraction(
        horizon * a.max_outputs_per_block * a.commitment_entry_bytes,
        a.commitment_index_multiplier,
    )
    frontier = a.fixed_tree_frontier_bytes
    anchor_history = a.anchor_root_history_blocks * a.digest_bytes
    checkpoints = _ceil_fraction(
        a.checkpoint_records * a.max_checkpoint_record_bytes,
        a.checkpoint_storage_multiplier,
    )
    pruned_total = sum(
        (
            recent_payload,
            all_headers,
            recent_indexes,
            nullifier_state,
            commitment_state,
            frontier,
            anchor_history,
            checkpoints,
        )
    )

    archive_payload = _ceil_fraction(
        horizon * a.max_block_payload_bytes, a.archive_payload_multiplier
    )
    archive_indexes = horizon * (
        a.block_index_bytes
        + a.max_transactions_per_block * a.transaction_index_bytes
        + a.max_outputs_per_block * a.output_index_bytes
    )
    archive_total = sum(
        (
            archive_payload,
            all_headers,
            archive_indexes,
            nullifier_state,
            commitment_state,
            frontier,
            checkpoints,
        )
    )
    envelope_headroom = a.max_block_payload_bytes - MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES
    return StorageBreakdown(
        horizon_blocks=horizon,
        recent_blocks=recent,
        max_envelope_block_payload_headroom_bytes=envelope_headroom,
        max_envelope_fits_block_payload=envelope_headroom >= 0,
        recent_window_payload_bytes=recent_payload,
        all_chain_headers_and_header_db_bytes=all_headers,
        retained_recent_indexes_bytes=recent_indexes,
        all_nullifier_state_bytes=nullifier_state,
        all_commitment_state_bytes=commitment_state,
        compact_tree_frontier_bytes=frontier,
        anchor_root_history_bytes=anchor_history,
        checkpoint_records_bytes=checkpoints,
        pruned_node_total_bytes=pruned_total,
        archive_payload_bytes=archive_payload,
        archive_indexes_bytes=archive_indexes,
        full_archive_total_bytes=archive_total,
        target_bytes=a.target_bytes,
        pruned_target_headroom_bytes=a.target_bytes - pruned_total,
        pruned_target_exceeded=pruned_total > a.target_bytes,
        pruned_target_strictly_met=pruned_total < a.target_bytes,
    )


def max_block_payload_bytes_below_pruned_target(
    assumptions: StorageAssumptions = StorageAssumptions(),
) -> int | None:
    """Solve the conditional per-block payload cap that leaves pruned storage < target.

    Holds every other assumption fixed and changes only the canonical block
    payload cap. Returns ``None`` if even a one-byte cap cannot meet the strict
    target. This is a policy-sizing aid, not a consensus-enforced limit.
    """

    result = estimate_storage(assumptions)
    fixed_bytes = result.pruned_node_total_bytes - result.recent_window_payload_bytes
    recent_budget_bytes = assumptions.target_bytes - 1 - fixed_bytes
    if recent_budget_bytes <= 0:
        return None

    factor = assumptions.recent_payload_multiplier
    numerator = recent_budget_bytes * factor.denominator
    denominator = result.recent_blocks * factor.numerator
    payload_cap = numerator // denominator
    if payload_cap < 1:
        return None
    return payload_cap


def format_report(assumptions: StorageAssumptions, result: StorageBreakdown) -> str:
    """Render a human-readable report with the non-enforcement caveat."""

    gib = 1_073_741_824
    tib = 1_099_511_627_776
    payload_cap = max_block_payload_bytes_below_pruned_target(assumptions)
    payload_cap_line = (
        f"  largest block-payload cap under these other assumptions: {payload_cap:,} B"
        if payload_cap is not None
        else "  no positive block-payload cap meets the strict target under these assumptions"
    )
    rows = [
        "CONDITIONAL PLANNING SCENARIO — not a protocol guarantee",
        f"Horizon: {assumptions.years} years; modeled blocks: {result.horizon_blocks:,}",
        f"Block payload cap: {assumptions.max_block_payload_bytes:,} bytes; "
        f"max block rate: {assumptions.max_blocks_per_day:,}/day",
        f"RDXL max proof+statement envelope: {MAX_SINGLE_STATEMENT_BOUND_ENVELOPE_BYTES:,} B "
        "(before transaction wrapper)",
        "RDXL max envelope fits block payload before transaction wrapper: "
        f"{'yes' if result.max_envelope_fits_block_payload else 'NO'}",
        "RDXL envelope-only block-payload headroom: "
        f"{result.max_envelope_block_payload_headroom_bytes:,} B "
        "(nonnegative is necessary, not sufficient, after transaction framing)",
        f"Pruned payload window: {assumptions.pruned_window_days} days "
        f"({result.recent_blocks:,} blocks)",
        f"Checkpoint assumption: {assumptions.checkpoint_records:,} records, each up to "
        f"{assumptions.max_checkpoint_record_bytes:,} B, every "
        f"{assumptions.checkpoint_interval_blocks:,} blocks; DB multiplier "
        f"{assumptions.checkpoint_storage_multiplier.numerator}/"
        f"{assumptions.checkpoint_storage_multiplier.denominator} (illustrative)",
        "",
        "Pruned-node retained categories (independent):",
        f"  recent payload + DB overhead: {result.recent_window_payload_bytes:,} B",
        f"  all-chain headers + DB overhead: {result.all_chain_headers_and_header_db_bytes:,} B",
        f"  recent query indexes: {result.retained_recent_indexes_bytes:,} B",
        f"  all historical nullifier state: {result.all_nullifier_state_bytes:,} B",
        f"  all historical commitment uniqueness state: {result.all_commitment_state_bytes:,} B",
        f"  compact output-tree frontier: {result.compact_tree_frontier_bytes:,} B",
        f"  anchor-root history: {result.anchor_root_history_bytes:,} B",
        f"  checkpoint records: {result.checkpoint_records_bytes:,} B",
        f"  PRUNED TOTAL: {result.pruned_node_total_bytes:,} B "
        f"({result.pruned_node_total_bytes / gib:.2f} GiB)",
        f"  1 TB decimal headroom: {result.pruned_target_headroom_bytes:,} B",
        f"  strictly below 1 TB target: {'yes' if result.pruned_target_strictly_met else 'NO'}",
        payload_cap_line,
        "",
        "Full archive (informational only; no 1 TB cap applies):",
        f"  payload + DB overhead: {result.archive_payload_bytes:,} B",
        f"  full historical indexes: {result.archive_indexes_bytes:,} B",
        f"  FULL ARCHIVE TOTAL: {result.full_archive_total_bytes:,} B "
        f"({result.full_archive_total_bytes / tib:.2f} TiB)",
        "",
        "All caps, per-entry costs, multipliers, and checkpoint sizes are illustrative "
        "inputs, not measured or consensus-enforced. The pruned-node 1 TB result is "
        "conditional; protocol-level deterministic bounds and node benchmarks remain required. "
        "The full archive is outside this storage cap.",
    ]
    return "\n".join(rows)


if __name__ == "__main__":
    assumptions = StorageAssumptions()
    print("ILLUSTRATIVE DEFAULT CHECKPOINT RECORD SCENARIO")
    print(format_report(assumptions, estimate_storage(assumptions)))

    max_envelope_assumptions = max_single_envelope_per_checkpoint_assumptions(assumptions)
    print("\nSENSITIVITY: ONE MAX-SIZE STATEMENT-BOUND PROOF ENVELOPE PER CHECKPOINT")
    print(format_report(max_envelope_assumptions, estimate_storage(max_envelope_assumptions)))
