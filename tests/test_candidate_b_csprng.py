"""The CSPRNG the wallet derives keys and proof masks from.

Replaces Python's `random.Random`, which is Mersenne Twister. MT19937 recovers its whole state
from 624 consecutive outputs and makes no unpredictability claim, so it is the wrong primitive for
key material or for zero-knowledge masks -- a predictable mask reveals the secret it was meant to
hide.
"""

import collections

import pytest

from radix_core.candidate_b.lattice import csprng


def test_it_provides_the_methods_the_samplers_use():
    rng = csprng.fresh()
    assert isinstance(rng.getrandbits(8), int)
    assert 0 <= rng.randrange(10) < 10
    assert 3 <= rng.randrange(3, 7) < 7
    assert 3 <= rng.randint(3, 7) <= 7
    assert 0.0 <= rng.random() < 1.0


def test_the_same_seed_gives_the_same_stream():
    first = csprng.from_seed(b"a seed")
    second = csprng.from_seed(b"a seed")
    assert [first.getrandbits(32) for _ in range(4)] == [
        second.getrandbits(32) for _ in range(4)
    ]


def test_different_seeds_diverge_immediately():
    first = csprng.from_seed(b"one")
    second = csprng.from_seed(b"two")
    assert first.getrandbits(64) != second.getrandbits(64)


def test_a_fresh_generator_is_not_reproducible():
    """Two fresh instances must not agree, or the default is not a random source."""
    assert csprng.fresh().getrandbits(128) != csprng.fresh().getrandbits(128)


def test_randrange_is_unbiased_enough_to_cover_the_whole_range():
    rng = csprng.from_seed(b"coverage")
    seen = collections.Counter(rng.randrange(7) for _ in range(2000))
    assert set(seen) == set(range(7))
    # Exact rejection sampling should land close to uniform; this is a smoke test, not a proof.
    for count in seen.values():
        assert 200 < count < 380, seen


def test_randrange_rejects_an_empty_range():
    rng = csprng.fresh()
    with pytest.raises(ValueError):
        rng.randrange(5, 5)


def test_getrandbits_is_bounded_by_the_requested_width():
    rng = csprng.from_seed(b"width")
    for bits in (1, 7, 8, 31, 64):
        for _ in range(20):
            assert 0 <= rng.getrandbits(bits) < (1 << bits)


def test_it_is_not_mersenne_twister():
    """The point of the change, asserted rather than assumed.

    MT19937's next output is a function of its state, and its state is recoverable from outputs.
    At minimum the type must not be `random.Random`, and the stream must not equal one seeded the
    way the old code seeded it.
    """
    import random

    rng = csprng.from_seed(b"same")
    legacy = random.Random(int.from_bytes(__import__("hashlib").sha256(b"same").digest(), "big"))
    assert not isinstance(rng, random.Random)
    assert rng.getrandbits(64) != legacy.getrandbits(64)
