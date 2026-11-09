"""Wire format for a testnet spend envelope.

`setmembership.Proof` has an `encode` but no decoder, so this module supplies one
and then wraps proof, outputs and ring indices into JSON.

Rings travel as *indices* into the node's ring pool, not as keys: a depth-2 ring is
1024 lattice public keys, about 2 MB, and no chain would put that in a block. The
verifier rebuilds the ring from its own pool. That is how Monero-style ring
references work and it keeps a spend envelope around 70 KB instead of 2 MB.
"""

from __future__ import annotations

import json

from radix_core.candidate_b.lattice import ring, setmembership as S
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters
from radix_core.candidate_b.lattice.spend import Output, Spend

ENVELOPE_VERSION = 1


class CodecError(ValueError):
    """A malformed envelope or proof."""


def encode_proof(proof: S.Proof) -> bytes:
    return proof.encode()


def decode_proof(
    data: bytes, *, depth: int, rows: int, parameters: SmileParameters | None = None
) -> S.Proof:
    """Inverse of `Proof.encode`, given the shape the statement implies.

    Layout: commitment (kappa + lambda + depth + 1 polynomials), h, omega,
    response_prime (ell), response (W), then the two ternary challenges at one byte
    per coefficient.
    """
    p = SMILE if parameters is None else parameters
    poly_bytes = p.ring_degree * 4
    # kappa + rows + 2m + 1. The previous formula was kappa + lambda + depth + 1,
    # which is 23 for the tagged parameters (rows = 8) and wrong for every other
    # shape -- it happened to work only because the harness only used tagged ones.
    commitment_count = p.challenge_dim + rows + 2 * depth + 1
    width = S.masking_width(depth, p, rows)
    expected = (commitment_count + 2 + p.matrix_cols + width) * poly_bytes + 2 * p.ring_degree
    if len(data) != expected:
        raise CodecError(f"proof must be {expected} bytes for this statement, got {len(data)}")

    cursor = 0

    def take(count: int) -> tuple[tuple[int, ...], ...]:
        nonlocal cursor
        out = []
        for _ in range(count):
            out.append(ring.decode(data[cursor : cursor + poly_bytes], p))
            cursor += poly_bytes
        return tuple(out)

    commitment = take(commitment_count)
    h = take(1)[0]
    omega = take(1)[0]
    response_prime = take(p.matrix_cols)
    response = take(width)
    challenge = tuple(value - 1 for value in data[cursor : cursor + p.ring_degree])
    cursor += p.ring_degree
    challenge_prime = tuple(value - 1 for value in data[cursor : cursor + p.ring_degree])
    return S.Proof(
        commitment=commitment,
        h=h,
        omega=omega,
        challenge=challenge,
        challenge_prime=challenge_prime,
        response_prime=response_prime,
        response=response,
    )


def spend_to_dict(spend: Spend, indices: tuple[tuple[int, ...], ...]) -> dict:
    return {
        "v": ENVELOPE_VERSION,
        "anchor": spend.anchor.hex(),
        "input_values": list(spend.input_values),
        "ring_indices": [list(ring_) for ring_ in indices],
        "outputs": [{"key": [list(poly) for poly in note.key], "value": note.value} for note in spend.outputs],
        "fee": spend.fee,
        "signatures": [encode_proof(signature).hex() for signature in spend.signatures],
    }


def spend_from_dict(payload: dict, pool, *, depth: int, rows: int, p: SmileParameters = SMILE) -> tuple[Spend, tuple[tuple[int, ...], ...]]:
    """Rebuild a Spend, reconstructing each ring from the pool indices."""
    if payload.get("v") != ENVELOPE_VERSION:
        raise CodecError("unknown envelope version")
    try:
        indices = tuple(tuple(int(index) for index in ring_) for ring_ in payload["ring_indices"])
        rings = tuple(tuple(pool[index] for index in ring_) for ring_ in indices)
        outputs = tuple(
            Output(key=tuple(tuple(int(value) for value in poly) for poly in note["key"]), value=int(note["value"]))
            for note in payload["outputs"]
        )
        signatures = tuple(
            decode_proof(bytes.fromhex(blob), depth=depth, rows=rows, parameters=p)
            for blob in payload["signatures"]
        )
        spend = Spend(
            anchor=bytes.fromhex(payload["anchor"]),
            input_values=tuple(int(value) for value in payload["input_values"]),
            rings=rings,
            outputs=outputs,
            fee=int(payload["fee"]),
            signatures=signatures,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise CodecError(str(error)) from None
    return spend, indices


def envelope_bytes(spend: Spend, indices: tuple[tuple[int, ...], ...]) -> bytes:
    return json.dumps(spend_to_dict(spend, indices), separators=(",", ":")).encode()
