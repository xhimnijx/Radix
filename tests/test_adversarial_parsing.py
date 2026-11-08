import random

from radix_core.crypto import output_leaf
from radix_core.wire import OutputRecord, TransactionStatementV1, parse_statement_v1


def make_output(index: int, size: int) -> OutputRecord:
    commitment = bytes([index + 1]) * 64
    kem = bytes([index + 2]) * 1088
    nonce = bytes([index + 3]) * 12
    ciphertext = bytes([index + 4]) * size
    return OutputRecord(commitment, kem, nonce, ciphertext, output_leaf(commitment, kem, nonce, ciphertext))


def sample_statement() -> TransactionStatementV1:
    return TransactionStatementV1(
        chain_id=b"c" * 32,
        anchor_height=(1 << 64) - 1,
        root_out=b"r" * 64,
        fee=(1 << 64) - 1,
        nullifiers=(b"n" * 64, b"m" * 64),
        outputs=(make_output(0, 156), make_output(1, 668)),
    )


def test_deterministic_random_bytes_do_not_escape_parser_errors():
    rng = random.Random(0x5241444958)
    for _ in range(1000):
        raw = rng.randbytes(rng.randrange(0, 2400))
        try:
            parsed = parse_statement_v1(raw)
        except ValueError:
            continue
        assert parsed.serialize() == raw


def test_single_byte_mutations_are_rejected_or_roundtrip_canonically():
    encoded = sample_statement().serialize()
    # Probe header, values, vector headers, and nested output frames.
    positions = list(range(min(128, len(encoded)))) + [len(encoded) // 2, len(encoded) - 1]
    for position in sorted(set(positions)):
        mutated = bytearray(encoded)
        mutated[position] ^= 0x80
        try:
            parsed = parse_statement_v1(bytes(mutated))
        except ValueError:
            continue
        assert parsed.serialize() == bytes(mutated)
