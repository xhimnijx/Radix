import pytest

from radix_core.crypto import note_commitment, note_kdf, note_owner, nullifier, output_leaf, spend_public


def test_candidate_a_note_hash_formulas_known_answer_vector():
    spend_secret = bytes(range(64))
    shared_secret = bytes(range(32))
    rho = bytes(range(64))
    randomness = bytes([170]) * 64
    pk_s = spend_public(spend_secret)
    owner = note_owner(pk_s, shared_secret)
    commitment = note_commitment(owner, 123456789, rho, randomness)
    nf = nullifier(spend_secret, shared_secret, rho)
    kem_ciphertext = bytes([17]) * 1088
    nonce = bytes([34]) * 12
    ciphertext = bytes([51]) * 156
    leaf = output_leaf(commitment, kem_ciphertext, nonce, ciphertext)

    assert owner.hex() == (
        "cc4810af2987d299ac9389d6473d7095c7ff72498ddd635e5379a8a2cb9cd8a5"
        "f05ff4946addde3c34e035a4cdf766d39912b239cb382ee2038f37c2348dc06e"
    )
    assert commitment.hex() == (
        "6db251f8679a8fa1d399305fd2c938dd2a79361f259d2c6b206e7e23b8deca36"
        "21699f53b493ea342bc57ef90fae7563e02fafc92ec041195b6940cdf70fdc09"
    )
    assert nf.hex() == (
        "1667f9f61253f15353231b57c4357c0c16d1397d676a76c9ac2fa297446789c6"
        "703ed9babc107c635d07d983b00252725011aa0d58af95bef4b467dce795ac8e"
    )
    assert leaf.hex() == (
        "68a22758ecf19c9d7590d74964fe584bda873bcd9931ff8e3220b0c6c4f0c571"
        "b6d96c6b90f2f721fc7fbf41bc824b598477984625a19db4764af680997cca7a"
    )
    assert note_kdf(shared_secret, kem_ciphertext, commitment).hex() == (
        "66b35b21de0610f83936c132858bf0fc17026d556ab1550b4e7cecfe077f6d4b"
    )


def test_note_hash_functions_reject_malformed_lengths_and_amounts():
    with pytest.raises(ValueError):
        spend_public(b"short")
    with pytest.raises(ValueError):
        note_owner(b"p" * 64, b"k" * 31)
    with pytest.raises(ValueError):
        note_commitment(b"o" * 64, 0, b"r" * 64, b"s" * 64)
    with pytest.raises(ValueError):
        note_commitment(b"o" * 64, True, b"r" * 64, b"s" * 64)
    with pytest.raises(ValueError):
        nullifier(b"s" * 64, b"k" * 32, b"r" * 63)
    with pytest.raises(ValueError):
        output_leaf(b"c" * 64, b"t" * 1087, b"n" * 12, b"x" * 156)
