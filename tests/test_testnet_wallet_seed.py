"""Wallet portability: a phrase in, the same accounts out.

The point of these tests is the property that matters to a user — *the same twelve
words rebuild the same wallet on another device* — plus the failure that matters more:
a mistyped phrase must be refused, not silently accepted as a different wallet.
"""

import pathlib
import random

import pytest

from radix_testnet import mnemonic as M
from radix_testnet import params as P
from radix_testnet.node import WALLET_FILE, Node, StateError
from radix_testnet.wallet import Wallet

PARAMETERS = P.parameters()


# ------------------------------------------------------------------ BIP-39
def test_the_official_bip39_vectors_pass():
    """If these four disagree, the phrases are not standard and cannot be checked."""
    vectors = [
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
    ]
    for entropy_hex, expected in vectors:
        entropy = bytes.fromhex(entropy_hex)
        assert M.to_mnemonic(entropy) == expected
        assert M.to_entropy(expected) == entropy


def test_a_twelve_word_phrase_carries_128_bits():
    phrase = M.new_phrase(128)
    assert len(phrase.split()) == 12
    assert len(M.to_entropy(phrase)) == 16

    phrase = M.new_phrase(256)
    assert len(phrase.split()) == 24
    assert len(M.to_entropy(phrase)) == 32


#: A phrase with a known-correct checksum, used for the deterministic cases below.
FIXED_PHRASE = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)


def test_a_mistyped_word_is_usually_rejected():
    """BIP-39's checksum catches 15 of 16 single-word errors -- not all of them.

    The first version of this test asserted that every substitution was rejected and
    failed intermittently, which is the test being wrong rather than the code: four
    checksum bits detect 93.75% of single-word errors by construction.
    """
    words = FIXED_PHRASE.split()
    for position in (0, 5, 11):
        broken = list(words)
        broken[position] = "zoo"
        with pytest.raises(M.MnemonicError, match="checksum"):
            M.to_entropy(" ".join(broken))


def test_the_checksum_is_four_bits_and_this_case_gets_through():
    """A deliberate example of the 1-in-16 case, so nobody trusts the checksum too far.

    Replacing word 5 with "letter" leaves a valid checksum and yields a *different*
    wallet. A phrase must be written down correctly; the checksum is a typo detector,
    not a guarantee.
    """
    broken = FIXED_PHRASE.split()
    broken[5] = "letter"
    recovered = M.to_entropy(" ".join(broken))
    assert recovered != M.to_entropy(FIXED_PHRASE)
    assert len(recovered) == 16


def test_most_random_single_word_errors_are_caught():
    caught = 0
    trials = 64
    for _ in range(trials):
        words = M.new_phrase(128).split()
        words[0] = "zoo" if words[0] != "zoo" else "abandon"
        try:
            M.to_entropy(" ".join(words))
        except M.MnemonicError:
            caught += 1
    # Expected 93.75%; allow a lot of slack because 64 trials is a small sample.
    assert caught >= trials * 0.75, f"only {caught}/{trials} were caught"


def test_an_unknown_word_is_rejected():
    with pytest.raises(M.MnemonicError, match="not in the word list"):
        M.to_entropy("abandon abandon abandon abandon abandon abandon abandon abandon "
                     "abandon abandon abandon radix")


def test_the_wrong_number_of_words_is_rejected():
    with pytest.raises(M.MnemonicError, match="12, 15, 18, 21 or 24"):
        M.to_entropy("abandon " * 10)


# ------------------------------------------------------------- the wallet
def test_the_same_phrase_rebuilds_the_same_accounts():
    phrase = M.new_phrase(128)
    first = Wallet.from_mnemonic(phrase, PARAMETERS)
    second = Wallet.from_mnemonic(phrase, PARAMETERS)

    assert [account.public for account in first.accounts] == [
        account.public for account in second.accounts
    ]
    assert [account.secret for account in first.accounts] == [
        account.secret for account in second.accounts
    ]
    assert first.fingerprint == second.fingerprint


def test_the_phrase_survives_whitespace_and_case():
    phrase = M.new_phrase(128)
    messy = "  " + phrase.upper().replace(" ", "   ") + "\n"
    assert Wallet.from_mnemonic(messy, PARAMETERS).fingerprint == Wallet.from_mnemonic(
        phrase, PARAMETERS
    ).fingerprint


def test_a_different_phrase_gives_a_different_wallet():
    one = Wallet.from_mnemonic(M.new_phrase(128), PARAMETERS)
    two = Wallet.from_mnemonic(M.new_phrase(128), PARAMETERS)
    assert one.fingerprint != two.fingerprint
    assert one.accounts[0].public != two.accounts[0].public


def test_the_derivation_version_changes_the_wallet():
    """A parameter change must be a new version, never a silent reshuffle."""
    phrase = M.new_phrase(128)
    v1 = Wallet.from_mnemonic(phrase, PARAMETERS, version="v1")
    v2 = Wallet.from_mnemonic(phrase, PARAMETERS, version="v2")
    assert v1.fingerprint != v2.fingerprint
    assert v1.accounts[0].public != v2.accounts[0].public
    # and v1 still reproduces itself, which is the promise that matters
    assert Wallet.from_mnemonic(phrase, PARAMETERS, version="v1").fingerprint == v1.fingerprint


def test_a_generated_wallet_round_trips_through_its_phrase():
    wallet = Wallet.generate(PARAMETERS)
    assert wallet.phrase is not None
    restored = Wallet.from_mnemonic(wallet.phrase, PARAMETERS)
    assert restored.fingerprint == wallet.fingerprint
    assert [a.public for a in restored.accounts] == [a.public for a in wallet.accounts]


def test_the_fingerprint_is_domain_separated_from_the_seed():
    """The fingerprint must not be a prefix of the seed, or it would leak the seed."""
    wallet = Wallet.generate(PARAMETERS)
    assert wallet.fingerprint != wallet.seed[:4].hex()
    assert len(wallet.fingerprint) == 8
    assert all(character in "0123456789abcdef" for character in wallet.fingerprint)


# ---------------------------------------------------------------- the node
def test_the_node_writes_a_phrase_and_reloads_the_same_wallet(tmp_path):
    first = Node(data_dir=tmp_path, persist=True)
    assert first.wallet_created is True
    phrase_file = tmp_path / WALLET_FILE
    assert phrase_file.exists()

    second = Node(data_dir=tmp_path, persist=True)
    assert second.wallet_created is False
    assert second.faucet.fingerprint == first.faucet.fingerprint
    assert [a.public for a in second.faucet.accounts] == [
        a.public for a in first.faucet.accounts
    ]


def test_a_restored_phrase_reproduces_the_original_node_wallet(tmp_path):
    """The actual backup story: write the phrase down, wipe, restore, same wallet."""
    first = Node(data_dir=tmp_path, persist=True)
    phrase = first.faucet.phrase
    assert phrase

    other = tmp_path / "second"
    (other).mkdir()
    (other / WALLET_FILE).write_text(phrase + "\n", encoding="utf-8")
    restored = Node(data_dir=other, persist=True)
    assert restored.wallet_created is False
    assert restored.faucet.fingerprint == first.faucet.fingerprint


def test_a_corrupt_phrase_file_refuses_to_start(tmp_path):
    (tmp_path / WALLET_FILE).write_text("not a real phrase at all", encoding="utf-8")
    with pytest.raises(StateError, match="could not be read as a wallet phrase"):
        Node(data_dir=tmp_path, persist=True)


def test_a_missing_phrase_beside_an_existing_chain_refuses_to_start(tmp_path):
    """Otherwise the chain's outputs would be orphaned by a new wallet."""
    Node(data_dir=tmp_path, persist=True)
    (tmp_path / WALLET_FILE).unlink()
    with pytest.raises(StateError, match="missing but a chain exists"):
        Node(data_dir=tmp_path, persist=True)


def test_the_status_reports_a_fingerprint_and_never_the_phrase(tmp_path):
    node = Node(data_dir=tmp_path, persist=True)
    status = node.status()
    assert status["wallet"]["fingerprint"] == node.faucet.fingerprint
    assert status["wallet"]["fresh"] is True
    rendered = repr(status)
    for word in node.faucet.phrase.split():
        # a single common word could appear by accident; the whole phrase must not
        assert node.faucet.phrase not in rendered
