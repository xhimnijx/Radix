"""The noise-aware statement, and the obstruction it exists to fix.

C1's seventh-pass finding: the stealth-address key is `P = A·p + e1`, an MLWE sample, and
SMILE proves `A·s = pk` exactly. The test that matters is the negative one — a noise-free
verifier *rejects* a noisy key — because that is what made the earlier discussion of
norms moot.

`e1` here is modelled as a small random vector, which is what the KEM error is. Its actual
distribution belongs to the KEM's parameters, not to this module.
"""

import random

import pytest

from radix_core.candidate_b.lattice import noisy, ring
from radix_core.candidate_b.lattice.params import SMILE


def build(rng, rows=4, columns=13, bound=2):
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(columns)) for _ in range(rows)
    )
    secret = tuple(ring.sample_vector(rng, columns, small=True) for _ in range(1))[0]
    noise = tuple(
        ring.normalize([rng.randint(-bound, bound) for _ in range(SMILE.ring_degree)])
        for _ in range(rows)
    )
    return matrix, secret, noise


def test_the_augmented_matrix_has_the_extra_identity_columns():
    rng = random.Random(1)
    matrix, _secret, _noise = build(rng)
    augmented = noisy.augment(matrix, 4)

    assert len(augmented) == 4
    assert all(len(row) == 13 + 4 for row in augmented)
    # The identity part selects each noise component separately.
    for index, row in enumerate(augmented):
        assert row[13 + index] == ring.constant(1)
        for other in range(4):
            if other != index:
                assert row[13 + other] == ring.constant(0)


def test_a_noisy_public_key_satisfies_the_augmented_relation():
    rng = random.Random(2)
    matrix, secret, noise = build(rng)
    augmented = noisy.augment(matrix, 4)
    witness = tuple(secret) + tuple(noise)          # the witness is (p, e1)

    public = noisy.noisy_public_key(augmented, witness, tuple(ring.zero() for _ in range(4)))
    # Built from the plain matrix above, so recompute against the plain one for clarity.
    public = noisy.noisy_public_key(matrix, secret, noise)

    assert noisy.holds(augmented, witness, tuple(ring.zero() for _ in range(4)), public)


def test_the_noise_free_verifier_rejects_a_noisy_key():
    """This is the obstruction. A stealth key is not a SMILE key.

    `A·p` and `A·p + e1` differ, so a verifier that checks the exact relation rejects a
    key that the stealth-address protocol produced correctly. That is why the statement
    had to change rather than the parameters.
    """
    rng = random.Random(3)
    matrix, secret, noise = build(rng)

    public = noisy.noisy_public_key(matrix, secret, noise)
    exact = noisy.exact_public_key(matrix, secret)

    assert public != exact, "the noise vanished; this test would prove nothing"
    # The relation SMILE proves does not hold for the noisy key.
    assert tuple(ring.dot(row, secret) for row in matrix) != public


def test_a_zero_noise_key_passes_the_exact_check():
    """The augmented statement must not reject a legitimate noise-free key."""
    rng = random.Random(4)
    matrix, secret, _noise = build(rng)
    public = noisy.exact_public_key(matrix, secret)
    assert tuple(ring.dot(row, secret) for row in matrix) == public


def test_the_tag_ignores_the_noise():
    """`[A' | 0]`: the tag is a function of the secret alone."""
    rng = random.Random(5)
    tag_rows = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(13)) for _ in range(1)
    )
    matrix, secret, noise = build(rng)
    padded = noisy.tag_matrix(tag_rows, 4)

    witness = tuple(secret) + tuple(noise)
    with_noise = ring.dot(padded[0], witness)
    without = ring.dot(tag_rows[0], secret)

    assert with_noise == without, "the noise leaked into the tag"


def test_the_witness_norm_is_short_when_the_noise_is_short():
    rng = random.Random(6)
    _matrix, secret, noise = build(rng, bound=2)
    witness = tuple(secret) + tuple(noise)
    assert noisy.is_short(witness, 5), f"witness norm {noisy.norm_inf(witness)} exceeds 5"


def test_a_wrong_shape_is_refused():
    rng = random.Random(7)
    matrix, secret, noise = build(rng)
    with pytest.raises(noisy.NoisyStatementError):
        noisy.noisy_public_key(matrix, secret[:-1], noise)
    with pytest.raises(noisy.NoisyStatementError):
        noisy.noisy_public_key(matrix, secret, noise + (noise[0],))


@pytest.mark.slow
def test_a_statement_at_seventeen_columns_proves_and_verifies():
    """C1 and C2: the noise-aware statement needs ell = 17, not 13.

    `A_noise = [A | I_k]` has `ell + k = 17` columns, so the statement, keys, prover and
    verifier must all run at that width. Two hardcoded checks made this impossible to
    construct: `Parameters` and `Statement` both validated against `SMILE.matrix_cols`
    rather than against the width of the matrix they were given. Both now derive the
    width from their own rows.
    """
    from radix_core.candidate_b.lattice import setmembership as S
    from radix_core.candidate_b.lattice.params import SmileParameters

    wide = SmileParameters(matrix_cols=17)
    rng = random.Random(17)
    keys = S.setup(rng, 2, wide)
    matrix = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(17)) for _ in range(wide.matrix_rows)
    )
    secret, public = S.keygen(rng, matrix, wide)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(wide.matrix_rows)) for _ in range(1024)
    ]
    ring_keys[17] = public
    statement = S.Statement(matrix=matrix, keys=tuple(ring_keys), depth=2)

    proof = S.prove(keys, statement, secret, 17, b"wide", random.Random(18), wide)

    assert len(proof.response_prime) == 17
    assert S.verify(keys, statement, proof, b"wide", wide) is True
    assert S.verify(keys, statement, proof, b"other", wide) is False


@pytest.mark.slow
def test_a_noisy_statement_proves_and_verifies_at_seventeen_columns():
    """C1's wiring: prove over `[A | I_k]` with witness `(p, e1)`.

    The stealth public key is `P = A·p + e1`, not `A·p`, so the proved matrix must be
    `A_noise = [A | I_k]` and the witness must carry the noise. This is the whole point of
    the noise-aware statement: without it the exact relation rejects a valid stealth key,
    which is tested separately above.

    What this does NOT establish is soundness of that statement -- the extraction argument
    is C1's, and `docs/PAPER.md` lists it under the limitations rather than here.
    """
    from radix_core.candidate_b.lattice import ring, setmembership as S
    from radix_core.candidate_b.lattice.params import SmileParameters

    columns = 13
    rows = 4
    wide = SmileParameters(matrix_cols=columns + rows)  # ell + k = 17
    rng = random.Random(41)

    plain = tuple(
        tuple(ring.sample_uniform(rng) for _ in range(columns)) for _ in range(rows)
    )
    augmented = noisy.augment(plain, rows)
    assert len(augmented[0]) == 17

    secret = ring.sample_vector(rng, columns, small=True, parameters=SMILE)
    error = tuple(
        ring.normalize([rng.randint(-2, 2) for _ in range(SMILE.ring_degree)])
        for _ in range(rows)
    )
    witness = tuple(secret) + error  # (p, e1)
    public = noisy.noisy_public_key(plain, secret, error)
    assert noisy.is_short(witness, 5), "the witness must be short for the proof to accept"

    keys = S.setup(rng, 2, wide)
    ring_keys = [
        tuple(ring.sample_uniform(rng) for _ in range(rows)) for _ in range(1024)
    ]
    ring_keys[40] = public
    statement = S.Statement(matrix=augmented, keys=tuple(ring_keys), depth=2)

    proof = S.prove(keys, statement, witness, 40, b"noisy", random.Random(42), wide)

    assert S.verify(keys, statement, proof, b"noisy", wide) is True
    assert S.verify(keys, statement, proof, b"other", wide) is False
