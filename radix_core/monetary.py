"""Integer-only implementation of the draft's illustrative emission proposal.

This schedule is not selected consensus policy. It exists to make the current
monetary-policy hypothesis deterministic and testable while governance choices
remain open.
"""
from __future__ import annotations

from .encoding import U64_MAX

PROPOSED_BASE_UNITS_PER_RAD = 1_000_000_000_000
PROPOSED_BLOCKS_PER_EPOCH = 720
PROPOSED_INITIAL_SUBSIDY = 10 * PROPOSED_BASE_UNITS_PER_RAD
PROPOSED_TAIL_SUBSIDY = PROPOSED_BASE_UNITS_PER_RAD // 10
PROPOSED_DECAY_NUMERATOR = 999_525
PROPOSED_DECAY_DENOMINATOR = 1_000_000


def _build_epoch_schedule() -> tuple[int, ...]:
    """Return one exact subsidy per epoch, ending at the first tail epoch."""
    schedule = [PROPOSED_INITIAL_SUBSIDY]
    while schedule[-1] > PROPOSED_TAIL_SUBSIDY:
        next_subsidy = (
            schedule[-1] * PROPOSED_DECAY_NUMERATOR
            // PROPOSED_DECAY_DENOMINATOR
        )
        schedule.append(max(PROPOSED_TAIL_SUBSIDY, next_subsidy))
    return tuple(schedule)


PROPOSED_SUBSIDY_BY_EPOCH = _build_epoch_schedule()
PROPOSED_TAIL_EPOCH = len(PROPOSED_SUBSIDY_BY_EPOCH) - 1


def _build_full_epoch_prefix() -> tuple[int, ...]:
    prefix = [0]
    for subsidy in PROPOSED_SUBSIDY_BY_EPOCH:
        prefix.append(prefix[-1] + subsidy * PROPOSED_BLOCKS_PER_EPOCH)
    return tuple(prefix)


_PROPOSED_FULL_EPOCH_PREFIX = _build_full_epoch_prefix()


def proposed_subsidy_at_height_v1(height: int) -> int:
    """Return the proposal's subsidy in base units at a U64 block height.

    Height zero evaluates to epoch zero; this does not decide whether genesis
    receives a mint. The value is a proposal fixture, not a consensus rule; the
    state transition intentionally still requires an explicit subsidy from its
    caller.
    """
    if type(height) is not int or not 0 <= height <= U64_MAX:
        raise ValueError("block height must be a U64")
    epoch = height // PROPOSED_BLOCKS_PER_EPOCH
    if epoch < len(PROPOSED_SUBSIDY_BY_EPOCH):
        return PROPOSED_SUBSIDY_BY_EPOCH[epoch]
    return PROPOSED_TAIL_SUBSIDY


def proposed_cumulative_subsidy_before_height_v1(exclusive_height: int) -> int:
    """Sum proposal subsidies for heights ``[0, exclusive_height)`` exactly.

    ``exclusive_height`` may be ``2**64`` to express the end of the U64 height
    domain. Python integers are deliberately used for the accumulated total:
    supply can exceed U64 even though each block height is U64.
    """
    if type(exclusive_height) is not int or not 0 <= exclusive_height <= U64_MAX + 1:
        raise ValueError("exclusive height must be between zero and 2**64")
    full_epochs, partial_blocks = divmod(
        exclusive_height, PROPOSED_BLOCKS_PER_EPOCH
    )
    scheduled_epochs = min(full_epochs, len(PROPOSED_SUBSIDY_BY_EPOCH))
    total = _PROPOSED_FULL_EPOCH_PREFIX[scheduled_epochs]
    if full_epochs > len(PROPOSED_SUBSIDY_BY_EPOCH):
        total += (
            full_epochs - len(PROPOSED_SUBSIDY_BY_EPOCH)
        ) * PROPOSED_BLOCKS_PER_EPOCH * PROPOSED_TAIL_SUBSIDY
    if partial_blocks:
        if full_epochs < len(PROPOSED_SUBSIDY_BY_EPOCH):
            subsidy = PROPOSED_SUBSIDY_BY_EPOCH[full_epochs]
        else:
            subsidy = PROPOSED_TAIL_SUBSIDY
        total += partial_blocks * subsidy
    return total
