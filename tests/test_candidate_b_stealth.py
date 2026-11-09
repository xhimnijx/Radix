"""One-time addressing: the derivation, and what the sender cannot compute.

Two properties are what matter, and both are tested rather than argued:

1. The sender computes the same stealth public key and tag as the recipient, from public
   data plus a shared secret.
2. The sender cannot compute the stealth *secret*, because it does not know the spend key.

The structure is C1's and C2's: a short shift (a uniform one makes the key undecryptable),
and a public tag image `T_K = A'·k` so the sender can compute `T` without `p`.
"""

import random

import pytest

from radix_core.candidate_b.lattice import ring, stealth
from radix_core.candidate_b.lattice.params import SMILE
from radix_testnet import params as TP

PARAMETERS = TP.parameters()


def spend_key(rng):
    return ring.sample_vector(rng, len(PARAMETERS.matrix[0]), small=True, parameters=SMILE)


def test_the_sender_and_the_recipient_agree_on_the_public_key():
    rng = random.Random(1)
    key = spend_key(rng)
    shared = b"a shared secret from the KEM"
    meta = stealth.meta_address(key, PARAMETERS)

    sender = stealth.sender_derive(meta, shared, PARAMETERS)
    secret = stealth.recipient_derive(key, shared, PARAMETERS)

    assert stealth.public_of(secret, PARAMETERS) == sender["public"]
    assert stealth.tag_of(secret, PARAMETERS) == sender["tag"]


def test_a_different_shared_secret_gives_a_different_stealth_key():
    rng = random.Random(2)
    key = spend_key(rng)
    meta = stealth.meta_address(key, PARAMETERS)

    first = stealth.sender_derive(meta, b"one", PARAMETERS)
    second = stealth.sender_derive(meta, b"two", PARAMETERS)

    assert first["public"] != second["public"]
    assert first["tag"] != second["tag"]


def test_the_sender_never_holds_the_stealth_secret():
    """It has the shift and the public key, and not the spend key."""
    rng = random.Random(3)
    key = spend_key(rng)
    meta = stealth.meta_address(key, PARAMETERS)
    sender = stealth.sender_derive(meta, b"secret", PARAMETERS)

    assert "secret" not in sender
    # What the sender can do: subtract A·delta from A·p and recover A·k, which is already
    # public. What it cannot do is recover k itself, and so cannot form p = k + delta.
    recovered = tuple(
        ring.sub(a, b, SMILE)
        for a, b in zip(sender["public"], stealth.public_of(sender["shift"], PARAMETERS))
    )
    assert recovered == stealth.public_of(key, PARAMETERS)


def test_the_stealth_secret_bound_depends_on_both_distributions():
    """`p = k + delta`, so its width is the sum of the two widths.

    `delta` is CBD of width 2. The spend key here is the proof's own small sample,
    uniform in [-5, 5], so `p` reaches 7 and NOT the proof's mu = 5. That is C2's
    parameter point made concrete: with a Kyber CBD spend key of width 2, `p` reaches 4
    and fits; with a uniform-small key it does not. The bound is asserted as what it is
    rather than quietly loosened, because which of the two a wallet uses is a parameter
    decision, not an implementation detail.
    """
    rng = random.Random(4)
    worst = 0
    for index in range(4):
        key = spend_key(rng)
        secret = stealth.recipient_derive(key, b"shared" + bytes([index]), PARAMETERS)
        worst = max(worst, stealth.norm_inf(secret, PARAMETERS))
    assert worst <= 5 + stealth.SHIFT_ETA, (
        f"the stealth secret reached norm {worst}, above the sum of the two widths"
    )


def test_the_meta_address_publishes_the_tag_image():
    rng = random.Random(5)
    key = spend_key(rng)
    meta = stealth.meta_address(key, PARAMETERS)
    assert meta["tag"] == stealth.tag_of(key, PARAMETERS)


def test_an_empty_shared_secret_is_refused():
    with pytest.raises(stealth.StealthError, match="shared secret"):
        stealth.short_shift(b"", PARAMETERS)


def test_the_shift_is_short():
    shift = stealth.short_shift(b"any secret", PARAMETERS)
    assert stealth.norm_inf(shift, PARAMETERS) <= 2, "the shift must be CBD-width, not uniform"
