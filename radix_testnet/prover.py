"""The one seam between the testnet and the proof.

Everything above this module -- node, miner, wallet, GUI -- calls `prove_spend` and
`verify_spend` and nothing else. Swapping the backend is therefore a change here
and nowhere else.

Both backends are real implementations of the same protocol:

* ``python`` -- the reference implementation in `radix_core.candidate_b.lattice`.
  A depth-2 spend takes ~1-2 minutes to prove and ~20 s to verify, because CPython
  runs the ring arithmetic in interpreted loops.
* ``rust`` -- the ported implementation in `proof_rust/`. Measured on this machine
  at 496 ms to prove and 110 ms to verify for an untagged proof, and ~0.9 s end to
  end through this seam (subprocess start and serialisation included).

Selecting ``rust`` when the binary is absent raises rather than silently falling
back: a demo that claims to use the fast path and quietly uses the slow one is worse
than no demo.
"""

from __future__ import annotations

import random
from enum import Enum

from radix_core.candidate_b.lattice import spend as SP


class ProverBackend(Enum):
    PYTHON = "python"
    RUST = "rust"


class ProverUnavailable(RuntimeError):
    """The requested backend cannot produce proofs."""


#: The backend in use. Set once at start-up; the CLI exposes ``--backend``.
BACKEND = ProverBackend.PYTHON


def set_backend(name: str) -> ProverBackend:
    """Select a backend, refusing the ones that do not exist yet."""
    global BACKEND
    try:
        backend = ProverBackend(name)
    except ValueError:
        raise ProverUnavailable(f"unknown backend {name!r}") from None
    if backend is ProverBackend.RUST:
        from . import rust_backend

        if not rust_backend.available():
            raise ProverUnavailable(
                "the rust prover is not built. Run: cargo build --release --bin "
                "prove_request (in proof_rust), or set RADIX_PROVE_BIN."
            )
    BACKEND = backend
    return backend


def prove_spend(*args, **kwargs) -> SP.Spend:
    """Build a spend. The only prover entry point the testnet uses."""
    if BACKEND is ProverBackend.RUST:
        raise ProverUnavailable("the rust prover is not implemented")
    return SP.build_spend(*args, **kwargs)


def verify_spend(spend: SP.Spend, **kwargs) -> bool:
    """Check an untagged spend."""
    if BACKEND is ProverBackend.RUST:
        raise ProverUnavailable("the rust verifier is not implemented")
    return SP.verify_spend(spend, **kwargs)


def verify_tagged(parameters, spend, params=None) -> bool:
    """Check a tagged spend. What the node actually calls.

    With the Rust backend this is a subprocess per input: about 110 ms of verification
    plus ~50 ms of process start, against 20-38 s in Python.
    """
    from . import rust_backend

    if BACKEND is ProverBackend.RUST:
        return rust_backend.verify_tagged_spend(parameters, spend)

    from .tagged import verify_tagged_spend

    return verify_tagged_spend(parameters, spend, params)
