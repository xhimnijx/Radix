import pytest

from radix_core.entropy import (
    EntropyError,
    draw_aead_nonce_v1,
    draw_note_blinding,
    draw_random_bytes,
    draw_spend_secret,
)


class PredictableEntropy:
    def __init__(self):
        self.calls = []

    def token_bytes(self, length):
        self.calls.append(length)
        return bytes([len(self.calls)]) * length


def test_protocol_material_requests_exact_lengths_and_independent_draws():
    source = PredictableEntropy()
    secret = draw_spend_secret(source)
    rho, randomness = draw_note_blinding(source)
    nonce = draw_aead_nonce_v1(source)

    assert len(secret) == 64
    assert len(rho) == len(randomness) == 64
    assert rho != randomness
    assert len(nonce) == 12
    assert source.calls == [64, 64, 64, 12]


def test_entropy_source_rejects_bad_requests_and_nonconforming_providers():
    source = PredictableEntropy()
    for invalid in (0, -1, True, 1.5):
        with pytest.raises(ValueError, match="positive integer"):
            draw_random_bytes(invalid, source)

    class ShortEntropy:
        def token_bytes(self, length):
            return b"short"

    with pytest.raises(EntropyError, match="byte count"):
        draw_random_bytes(32, ShortEntropy())

    class FailingEntropy:
        def token_bytes(self, length):
            raise OSError("source unavailable")

    with pytest.raises(EntropyError, match="failed"):
        draw_random_bytes(32, FailingEntropy())

    with pytest.raises(EntropyError, match="token_bytes"):
        draw_random_bytes(32, object())


def test_default_system_entropy_source_returns_requested_shapes():
    assert len(draw_spend_secret()) == 64
    assert tuple(map(len, draw_note_blinding())) == (64, 64)
    assert len(draw_aead_nonce_v1()) == 12
