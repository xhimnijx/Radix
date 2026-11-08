"""Candidate-B prototype: a Monero-style spend with a linkable ring signature.

Run from the repository root:

    python -m examples.candidate_b_demo

This is a *research prototype*. Amounts are public, the ring signature is
classical (not post-quantum), and recipient discovery is addressed to a published
one-time key. See CANDIDATE-B.md for the gap list. Nothing here carries value.
"""

from __future__ import annotations

import time

from radix_core.candidate_b import lsag, protocol
from radix_core.candidate_b.protocol import (
    LedgerState,
    NoteRecord,
    ProtocolError,
    apply_block,
    build_spend,
    generate_note_keypair,
)

NOTE_VALUE = 20
RING_SIZE = 5
FEE = 2
HEIGHT = 100


def main() -> int:
    print("Candidate-B prototype: linkable ring signature spend")
    print("(public amounts, equal-value rings, classical group; no value)\n")

    # A ledger with twelve notes of one denomination, as a genesis fixture.
    owners = [generate_note_keypair() for _ in range(12)]
    notes = tuple(
        NoteRecord(verification_key=owner.verification_key, value=NOTE_VALUE)
        for owner in owners
    )
    state = LedgerState.from_notes(notes, height=HEIGHT)
    print(f"ledger: {state.note_count} notes of value {NOTE_VALUE}, height {state.height}")
    print(f"note root: {state.root.hex()[:32]}...")

    # Bob receives change; the note is addressed to a fresh one-time key.
    bob = generate_note_keypair()
    change = NoteRecord(verification_key=bob.verification_key, value=NOTE_VALUE - FEE)
    alice = owners[5]

    start = time.perf_counter()
    transaction = build_spend(
        alice, state, 5, (change,), fee=FEE, ring_size=RING_SIZE
    )
    sign_ms = (time.perf_counter() - start) * 1000.0

    ring_input = transaction.inputs[0]
    signature = ring_input.signature
    print(f"\nspend built:")
    print(f"  ring size:        {len(ring_input.ring)} notes "
          f"(indices {[member.index for member in ring_input.ring]})")
    print(f"  signature bytes:  {len(signature.encode())}")
    print(f"  canonical message:{len(transaction.message())} bytes")
    print(f"  linking tag:      {signature.tag.to_bytes(32, 'big').hex()[:32]}...")
    print(f"  signing time:     {sign_ms:.1f} ms")

    start = time.perf_counter()
    protocol.validate_transaction(state, transaction)
    verify_ms = (time.perf_counter() - start) * 1000.0
    print(f"  validation time:  {verify_ms:.1f} ms (includes 64-level membership x ring)")

    next_state = apply_block(state, HEIGHT + 1, (transaction,))
    print(f"\nblock applied: height {next_state.height}, "
          f"{next_state.note_count} notes, {len(next_state.tags)} tag")

    # The tag is deterministic: a second spend of the same note reveals itself.
    print("\nattempting a double spend of the same note...")
    try:
        replay = build_spend(alice, next_state, 5, (change,), fee=FEE, ring_size=RING_SIZE)
        apply_block(next_state, HEIGHT + 2, (replay,))
    except ProtocolError as exc:
        print(f"  rejected: {exc}")
    else:
        print("  ERROR: double spend was accepted")
        return 1

    # Signer ambiguity: the signature is a valid ring signature regardless of
    # which member signed, and no field reveals the index.
    print("\nchecking that each ring member could have been the signer:")
    keys = tuple(member.record.verification_key for member in ring_input.ring)
    print(f"  verifies over the published ring: {lsag.verify(transaction.message(), keys, signature)}")

    print("\nnot implemented here: post-quantum signatures, amount hiding/range")
    print("proofs, and recipient discovery. Do not use this to protect value.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
