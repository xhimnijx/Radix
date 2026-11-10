"""Call the Rust prover as a subprocess.

The seam is deliberately narrow: build a request, run one binary, decode one proof.
Everything else in the testnet keeps calling `prover.prove_spend`.

Why a subprocess and not FFI: no crates are available offline for `pyo3`, and the
cost is ~40 ms of process start against ~500 ms of proving. If that ever matters,
this module is the only thing that changes.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
from pathlib import Path

from radix_core.candidate_b.lattice import ring, setmembership as S
from radix_core.candidate_b.lattice.params import SMILE

from .codec import decode_proof

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = REPO_ROOT / "proof_rust" / "target" / "release" / "prove_request.exe"


class RustProverError(RuntimeError):
    """The Rust prover could not be run or failed."""


def binary_path() -> Path:
    override = os.environ.get("RADIX_PROVE_BIN")
    return Path(override) if override else DEFAULT_BINARY


def available() -> bool:
    return binary_path().exists()


def _encode_polys(polys) -> bytes:
    return b"".join(ring.encode(poly, SMILE) for poly in polys)


def build_request(
    keys: S.Keys, statement: S.Statement, secret, index: int, message: bytes,
    relations=(),
) -> bytes:
    """Serialise a proving request in the layout `prove_request.rs` expects."""
    depth = keys.depth
    rows = len(statement.matrix)
    cols = SMILE.matrix_cols
    width = S.masking_width(depth, SMILE, keys.row_count)
    if len(keys.rows0) != SMILE.challenge_dim or len(keys.rows) != rows + 2 * depth + 1:
        raise RustProverError("keys do not match the statement shape")

    header = struct.pack(
        "<9I",
        depth,
        rows,
        cols,
        SMILE.challenge_dim,
        width,
        index,
        len(message),
        len(keys.range_rows),
        len(keys.carry_rows),
    )
    parts = [header, message]
    for row in keys.rows0:
        parts.append(_encode_polys(row))
    for row in keys.rows:
        parts.append(_encode_polys(row))
    for row in keys.range_rows:
        parts.append(_encode_polys(row))
    for row in keys.carry_rows:
        parts.append(_encode_polys(row))
    for row in statement.matrix:
        parts.append(_encode_polys(row))
    for key in statement.keys:
        parts.append(_encode_polys(key))
    parts.append(_encode_polys(secret))
    # Relations: count, then per relation the weights, the positions and the constant.
    parts.append(struct.pack("<I", len(relations)))
    for relation in relations:
        parts.append(struct.pack("<I", len(relation.weights)))
        for weight in relation.weights:
            parts.append(_encode_polys((weight,)))
        for position in relation.positions:
            parts.append(struct.pack("<i", position))
        parts.append(b"\x01" if relation.constant is not None else b"\x00")
        if relation.constant is not None:
            parts.append(_encode_polys((relation.constant,)))
    return b"".join(parts)


def prove(
    keys: S.Keys,
    statement: S.Statement,
    secret,
    index: int,
    message: bytes,
    seed: int = 2026,
) -> S.Proof:
    """Run the Rust prover and return a proof the Python verifier accepts."""
    binary = binary_path()
    if not binary.exists():
        raise RustProverError(
            f"the Rust prover is not built: {binary}. "
            "Run packaging/build-windows.ps1 or cargo build --release --bin prove_request."
        )

    request = build_request(keys, statement, secret, index, message)
    with tempfile.TemporaryDirectory(prefix="radix-prove-") as work:
        request_path = Path(work) / "request.bin"
        proof_path = Path(work) / "proof.bin"
        request_path.write_bytes(request)

        try:
            result = subprocess.run(
                [str(binary), str(request_path), str(proof_path), str(seed)],
                capture_output=True,
                timeout=600,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RustProverError(f"could not run the Rust prover: {error}") from None

        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise RustProverError(f"the Rust prover failed: {detail}")
        if not proof_path.exists():
            raise RustProverError("the Rust prover produced no output")

        return decode_proof(
            proof_path.read_bytes(), depth=keys.depth, rows=len(statement.matrix)
        )


def verify(keys: S.Keys, statement: S.Statement, proof, message: bytes, relations=()) -> bool:
    """Check a proof with the Rust verifier. Same request format as proving.

    Exit codes are kept distinct on purpose: 0 verified, 1 the proof is wrong, 2 the
    input was malformed. A node rejecting a transaction and a node finding a bug are
    different events and should not look the same.
    """
    binary = verify_binary_path()
    if not binary.exists():
        raise RustProverError(
            f"the Rust verifier is not built: {binary}. "
            "Run cargo build --release --bin verify_request."
        )

    # The request format carries the secret, which verification never reads; a zero
    # secret keeps one serialiser for both directions.
    request = build_request(keys, statement, _zero_secret(), 0, message, relations)

    with tempfile.TemporaryDirectory(prefix="radix-verify-") as work:
        request_path = Path(work) / "request.bin"
        proof_path = Path(work) / "proof.bin"
        request_path.write_bytes(request)
        proof_path.write_bytes(proof.encode())

        try:
            result = subprocess.run(
                [str(binary), str(request_path), str(proof_path)],
                capture_output=True,
                timeout=600,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RustProverError(f"could not run the Rust verifier: {error}") from None

        if result.returncode == 2:
            detail = result.stderr.decode(errors="replace").strip()
            raise RustProverError(f"the Rust verifier rejected the request: {detail}")
        return result.returncode == 0


def _zero_secret():
    """A secret of the right shape, for a request whose secret is never read.

    Polynomials, not encoded bytes: `build_request` encodes, so returning bytes here
    would encode twice and fail the degree check.
    """
    zero = tuple([0] * SMILE.ring_degree)
    return tuple(zero for _ in range(SMILE.matrix_cols))


def verify_binary_path() -> Path:
    override = os.environ.get("RADIX_VERIFY_BIN")
    if override:
        return Path(override)
    name = "verify_request.exe" if os.name == "nt" else "verify_request"
    return binary_path().with_name(name)


def verify_tagged_spend(parameters, spend) -> bool:
    """The node's verifier, routed through Rust, for a tagged spend.

    Mirrors `tagged.verify_tagged_spend` but hands each proof to the Rust verifier.
    The statement is the extended one: `A_ext = [A; A']` and `(pk_j, T)` for every
    member, exactly as the prover built it.
    """
    if not spend.balanced:
        return False
    message = spend.message()
    keys = parameters.keys
    extended_matrix = parameters.matrix + parameters.tag_matrix
    for ring_keys, tag, signature in zip(spend.rings, spend.tags, spend.signatures):
        extended_ring = tuple(key + tag for key in ring_keys)
        statement = S.Statement(
            matrix=extended_matrix, keys=extended_ring, depth=parameters.depth
        )
        if not verify(keys, statement, signature, message):
            return False
    return True


def prove_tagged(
    parameters,
    secret,
    public,
    ring_keys,
    message: bytes,
    seed: int = 2026,
):
    """The tagged path the testnet needs: prove over `A_ext` with the tag folded in.

    Mirrors `ring_signature.sign_tagged` but routes the proof through Rust. The tag
    itself is computed here, in Python, from the same `A'` the parameters carry.
    """
    tag = RS_tag_of(parameters, secret)
    extended_matrix = parameters.matrix + parameters.tag_matrix
    extended_public = public + tag
    extended_ring = tuple(key + tag for key in ring_keys)
    if extended_public not in extended_ring:
        raise RustProverError("the public key is not in the ring")

    keys = parameters.keys
    statement = S.Statement(
        matrix=extended_matrix, keys=extended_ring, depth=parameters.depth
    )
    index = extended_ring.index(extended_public)
    proof = prove(keys, statement, secret, index, message, seed)
    return proof, tag


def RS_tag_of(parameters, secret):
    from radix_core.candidate_b.lattice import ring_signature as RS

    return RS.tag_of(parameters, secret, SMILE)
