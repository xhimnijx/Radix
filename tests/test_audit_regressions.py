"""Regressions for defects found in the 2026-11-08 workspace audit.

Each test here corresponds to a `SECURITY-NOTES.md` entry and fails against the
pre-fix implementation.
"""

import inspect
import itertools

import pytest

from radix_core import monetary
from radix_core.cryptography_backend import (
    CryptographyAes256GcmProvider,
    CryptographyMlKem768Provider,
)
from radix_core.merkle import OutputTree
from radix_core.providers import AeadNonceRegistry
from radix_core.wallet import create_note_output_v1, generate_wallet_keys_v1
from radix_core.wallet_keystore import seal_wallet_keys_v1

KEM = CryptographyMlKem768Provider()
AEAD = CryptographyAes256GcmProvider()
SPEND_SECRET = bytes(range(64))


def test_append_many_does_not_consume_an_unbounded_iterable():
    tree = OutputTree()
    leaf = b"\x01" * 64

    with pytest.raises(ValueError, match="declared limit|capacity"):
        tree.append_many(itertools.repeat(leaf), limit=3)

    # The failed append must not have mutated the tree.
    assert tree.leaf_count == 0


def test_append_many_rejects_a_stream_longer_than_its_limit():
    tree = OutputTree()
    with pytest.raises(ValueError, match="declared limit|capacity"):
        tree.append_many((b"\x02" * 64 for _ in range(4)), limit=3)
    assert tree.leaf_count == 0


def test_append_many_still_accepts_exactly_the_limit():
    tree = OutputTree()
    tree.append_many((bytes([index + 1]) * 64 for index in range(3)), limit=3)
    assert tree.leaf_count == 3


def test_output_creation_rejects_a_noncanonical_viewing_key():
    # The first packed 12-bit coefficient is 3329 == q, which is not canonical.
    noncanonical = b"\x01\x0d" + b"\x00" * 1182
    with pytest.raises(ValueError, match="noncanonical polynomial coefficient"):
        create_note_output_v1(
            KEM,
            AEAD,
            noncanonical,
            SPEND_SECRET,
            1,
            entropy_source=lambda _: b"",
        )


def test_nonce_registry_default_is_unbounded():
    # A bounded default caused permanent note-creation failure after 100k
    # outputs, because the registry never evicts.
    default = inspect.signature(AeadNonceRegistry.__init__).parameters["max_entries"].default
    assert default is None


class _PersistentLookingRegistry(AeadNonceRegistry):
    """Reports durability and silently skips reservation."""

    def __init__(self) -> None:
        super().__init__(max_entries=None)

    @property
    def is_persistent(self) -> bool:
        return True

    def reserve(self, key: bytes, nonce: bytes) -> None:
        return None


def test_wallet_sealing_rejects_a_subclass_that_skips_reservation():
    keys = generate_wallet_keys_v1(KEM)
    with pytest.raises(ValueError, match="persistent AeadNonceRegistry"):
        seal_wallet_keys_v1(
            keys,
            b"correct horse battery staple",
            kem_provider=KEM,
            nonce_registry=_PersistentLookingRegistry(),
        )


def test_subsidy_schedule_cannot_hang_on_a_non_decaying_multiplier(monkeypatch):
    monkeypatch.setattr(
        monetary, "PROPOSED_DECAY_NUMERATOR", monetary.PROPOSED_DECAY_DENOMINATOR
    )
    with pytest.raises(ValueError, match="epoch bound"):
        monetary._build_epoch_schedule()
