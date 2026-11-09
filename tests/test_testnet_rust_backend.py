"""The Rust backend, behind the seam, checked by the Python verifier.

Slow by nature: a real tagged proof plus the Python verifier, which is itself slow.
Skipped when the Rust binary is not built rather than silently passing.
"""

import random

import pytest

from radix_core.candidate_b.lattice import ring, ring_signature as RS
from radix_core.candidate_b.lattice.spend import Output
from radix_testnet import params as P, prover, rust_backend, tagged

pytestmark = pytest.mark.slow


@pytest.fixture(scope="module")
def rig():
    if not rust_backend.available():
        pytest.skip(f"the Rust prover is not built: {rust_backend.binary_path()}")
    parameters = P.parameters()
    rng = random.Random(11)
    secret, public = RS.keygen(parameters, rng)
    ring_keys = [tuple(ring.sample_uniform(rng) for _ in range(4)) for _ in range(1024)]
    ring_keys[42] = public
    return parameters, secret, public, tuple(ring_keys)


def test_the_rust_backend_produces_a_proof_python_accepts(rig):
    parameters, secret, public, ring_keys = rig
    message = b"seam"

    start = prover.BACKEND
    assert prover.set_backend("rust") is prover.ProverBackend.RUST
    try:
        proof, tag = rust_backend.prove_tagged(
            parameters, secret, public, ring_keys, message
        )
    finally:
        prover.set_backend(start.value)

    assert proof.size_bytes == 36_608  # tagged: k' = 4 rows
    assert RS.verify_tagged(parameters, ring_keys, tag, message, proof)
    assert not RS.verify_tagged(parameters, ring_keys, tag, b"other", proof)


def test_a_tagged_spend_built_through_the_backend_verifies(rig):
    parameters, secret, public, ring_keys = rig
    start = prover.BACKEND
    assert prover.set_backend("rust") is prover.ProverBackend.RUST
    try:
        spend = tagged.build_tagged_spend(
            parameters,
            secrets=(secret,),
            publics=(public,),
            rings=(ring_keys,),
            input_values=(1000,),
            outputs=(Output(key=public, value=1000),),
            fee=0,
            anchor=b"\x00" * 32,
            rng=random.Random(3),
        )
    finally:
        prover.set_backend(start.value)

    assert tagged.verify_tagged_spend(parameters, spend)


def test_the_backend_refuses_when_the_binary_is_missing(monkeypatch):
    monkeypatch.setenv("RADIX_PROVE_BIN", "C:/definitely/not/here.exe")
    with pytest.raises(prover.ProverUnavailable, match="not built"):
        prover.set_backend("rust")


def test_the_rust_verifier_agrees_with_the_python_verifier(rig):
    """The node's verification path, both ways, on the same tagged spend."""
    parameters, secret, public, ring_keys = rig
    from radix_core.candidate_b.lattice.spend import Output

    start = prover.BACKEND
    try:
        prover.set_backend("rust")
        spend = tagged.build_tagged_spend(
            parameters,
            secrets=(secret,),
            publics=(public,),
            rings=(ring_keys,),
            input_values=(1000,),
            outputs=(Output(key=public, value=1000),),
            fee=0,
            anchor=b"\x00" * 32,
            rng=random.Random(4),
        )
        rust_verdict = prover.verify_tagged(parameters, spend)

        prover.set_backend("python")
        python_verdict = prover.verify_tagged(parameters, spend)
    finally:
        prover.set_backend(start.value)

    assert rust_verdict is True
    assert rust_verdict == python_verdict


def test_the_rust_verifier_rejects_a_tampered_proof(rig):
    parameters, secret, public, ring_keys = rig
    from radix_core.candidate_b.lattice.spend import Output

    start = prover.BACKEND
    try:
        prover.set_backend("rust")
        spend = tagged.build_tagged_spend(
            parameters,
            secrets=(secret,),
            publics=(public,),
            rings=(ring_keys,),
            input_values=(1000,),
            outputs=(Output(key=public, value=1000),),
            fee=0,
            anchor=b"\x00" * 32,
            rng=random.Random(6),
        )
        assert prover.verify_tagged(parameters, spend) is True

        tampered = tagged.TaggedSpend(
            anchor=spend.anchor,
            input_values=spend.input_values,
            rings=spend.rings,
            outputs=(Output(key=public, value=999),),
            fee=0,
            signatures=spend.signatures,
            tags=spend.tags,
        )
        assert prover.verify_tagged(parameters, tampered) is False
    finally:
        prover.set_backend(start.value)
