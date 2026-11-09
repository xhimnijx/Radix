"""The one seam between the testnet and the proof.

Everything above this module -- node, miner, wallet, GUI -- calls `prove_spend` and
`verify_spend` and nothing else. Swapping the backend is therefore a change here
and nowhere else.

There are two backends and only one is implemented:

* ``python`` -- the reference implementation in `radix_core.candidate_b.lattice`.
  Real proofs, no shortcuts. A depth-2 spend takes ~1-2 minutes to prove and ~20 s
  to verify, because CPython runs the ring arithmetic in interpreted loops.
* ``rust`` -- **not implemented**. `proof_rust` currently contains the arithmetic
  layer only (ring, quartic slots, CRT, multiplication, norms) and has been
  measured at 20.1 us per multiplication, which projects to ~0.47 s to prove and
  37 ms to verify. It has no keygen, commitments, transcript, recursion or
  challenge derivation, so it cannot produce a signature yet.

Selecting ``rust`` raises rather than silently falling back: a demo that claims to
use the fast path and quietly uses the slow one is worse than no demo.
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
    """Check a tagged spend. What the node actually calls."""
    if BACKEND is ProverBackend.RUST:
        raise ProverUnavailable("the rust verifier is not implemented")
    from .tagged import verify_tagged_spend

    return verify_tagged_spend(parameters, spend, params)
