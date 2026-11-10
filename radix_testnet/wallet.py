"""Correct the spend model: accounts are the unit of spendability.

Two facts force this design, and both come from the cryptography rather than from a
preference:

1. A ring signature hides *which* output it spends, so the chain cannot remove the
   spent output. It keeps every output and tracks spent **tags** instead.
2. The same-witness tag is `T = A' s`, a function of the *secret*, not of the note.
   So one keypair owns one tag, and any spend from that keypair burns it.

Therefore an account -- one keypair -- can be spent once, and change must go to a
different account. That is not a harness shortcut: it is what per-key linkability
means, and a real wallet would give every output its own key via one-time
addressing (B2, not built).
"""

from __future__ import annotations

import base64
import hashlib

from radix_core.candidate_b.lattice import csprng
import random
from dataclasses import dataclass, field

from radix_core.candidate_b.lattice import ring, ring_signature as RS
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters
from radix_core.candidate_b.lattice.spend import Output

from . import mnemonic as M
from . import tagged as T

ADDRESS_PREFIX = "rtx"
ACCOUNTS = 4


class WalletError(ValueError):
    """A wallet could not do what was asked."""


def _rng_for(seed: bytes, index: int):
    """The stream a wallet account's keys are derived from.

    A CSPRNG, not `random.Random`. MT19937 recovers its whole state from 624 consecutive
    outputs and makes no unpredictability claim, so it is the wrong primitive for key
    material. The seed is still the account's position in the wallet, so derivation stays
    deterministic and recoverable from the mnemonic -- that is the requirement -- but the
    stream itself is cryptographic.
    """
    from radix_core.candidate_b.lattice import csprng

    digest = hashlib.sha3_256(b"radix/wallet/rng/v1" + seed + index.to_bytes(4, "little")).digest()
    return csprng.CipherRng(digest)


def _encode_body(blob: bytes) -> str:
    """base64url, not hex.

    A lattice public key is 4 x 512 = 2048 bytes. Hex doubles that to 4096
    characters, which cannot fit in a QR code (byte mode tops out at 2953 bytes);
    base64url gives 2731 characters, which can. The address is the same key either
    way.
    """
    return base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")


def _decode_body(body: str) -> bytes:
    padding = "=" * (-len(body) % 4)
    try:
        return base64.urlsafe_b64decode(body + padding)
    except (ValueError, base64.binascii.Error):
        raise WalletError("the address body is not valid base64url") from None


def address_of(public: tuple, p: SmileParameters = SMILE) -> str:
    return ADDRESS_PREFIX + "1" + _encode_body(b"".join(ring.encode(poly, p) for poly in public))


def parse_address(address: str, p: SmileParameters = SMILE) -> tuple:
    if not address.startswith(ADDRESS_PREFIX + "1"):
        raise WalletError("not a testnet address")
    blob = _decode_body(address[len(ADDRESS_PREFIX) + 1 :])
    poly_bytes = p.ring_degree * 4
    if len(blob) != p.matrix_rows * poly_bytes:
        raise WalletError("an address must hold k polynomials")
    return tuple(
        ring.decode(blob[index * poly_bytes : (index + 1) * poly_bytes], p)
        for index in range(p.matrix_rows)
    )


def tag_of(secret: tuple, parameters: RS.Parameters, p: SmileParameters | None = None) -> bytes:
    """The spend tag for one keypair: `A' s`, encoded."""
    sm = SMILE if p is None else p
    return b"".join(ring.encode(poly, sm) for poly in RS.tag_of(parameters, secret, sm))


@dataclass
class Account:
    """One keypair: one address, one tag, spendable once on this chain."""

    index: int
    secret: tuple
    public: tuple
    notes: list[Output] = field(default_factory=list)

    @property
    def address(self) -> str:
        return address_of(self.public)

    @property
    def short(self) -> str:
        return f"{ADDRESS_PREFIX}1{hashlib.sha256(self.address.encode()).hexdigest()[:16]}"

    @property
    def balance(self) -> int:
        return sum(note.value for note in self.notes)


@dataclass
class Wallet:
    """A seed, a set of accounts, and the notes each account can spend.

    The seed comes from a mnemonic phrase (see `mnemonic.py`), so a wallet is
    portable: the same twelve words rebuild the same four accounts on any device.
    """

    seed: bytes
    parameters: RS.Parameters
    accounts: list[Account] = field(default_factory=list)
    #: The phrase this wallet came from, when it came from one.
    phrase: str | None = None
    #: Which derivation produced the seed; bumping it keeps old phrases working.
    version: str = "v1"

    @classmethod
    def generate(cls, parameters: RS.Parameters, strength: int = 128) -> "Wallet":
        """A fresh wallet from the operating system's CSPRNG."""
        phrase = M.new_phrase(strength)
        return cls(
            seed=M.wallet_seed(phrase),
            parameters=parameters,
            phrase=phrase,
        )

    @classmethod
    def from_mnemonic(
        cls, phrase: str, parameters: RS.Parameters, version: str = "v1"
    ) -> "Wallet":
        """Rebuild a wallet from a phrase. Raises `MnemonicError` if it is corrupt."""
        cleaned = M.normalise(phrase)
        # Raises on a bad checksum before any key derivation happens.
        M.to_entropy(cleaned)
        return cls(
            seed=M.wallet_seed(cleaned, version),
            parameters=parameters,
            phrase=cleaned,
            version=version,
        )

    @property
    def fingerprint(self) -> str:
        """A short, non-secret identifier for this wallet.

        Two devices showing the same fingerprint hold the same wallet. It is derived
        from the seed with a separate domain tag, so it reveals nothing usable.
        """
        digest = hashlib.sha256(b"radix/wallet/fingerprint" + self.seed).digest()
        return digest[:4].hex()

    def __post_init__(self) -> None:
        if not self.accounts:
            for index in range(ACCOUNTS):
                secret, public = RS.keygen(self.parameters, _rng_for(self.seed, index))
                self.accounts.append(Account(index=index, secret=secret, public=public))

    # ---------------------------------------------------------------- notes
    def scan(self, chain) -> int:
        """Refresh notes, excluding accounts whose tag has been spent."""
        spent = chain.spent_tags
        for account in self.accounts:
            account.notes = []
        for note in chain.outputs.values():
            for account in self.accounts:
                if note.key != account.public:
                    continue
                if tag_of(account.secret, self.parameters) in spent:
                    continue
                account.notes.append(note)
        return sum(len(account.notes) for account in self.accounts)

    @property
    def balance(self) -> int:
        return sum(account.balance for account in self.accounts)

    def spendable_account(self, amount: int, fee: int) -> Account:
        for account in self.accounts:
            for note in account.notes:
                if note.value == amount + fee:
                    return account
        for account in self.accounts:
            for note in sorted(account.notes, key=lambda note: note.value):
                if note.value > amount + fee:
                    return account
        raise WalletError(f"no unspent note covers {amount} + {fee} (balance {self.balance})")

    def account_for(self, note: Output) -> Account:
        for account in self.accounts:
            if note.key == account.public and note in account.notes:
                return account
        raise WalletError("no account owns that note")

    # ---------------------------------------------------------------- sending
    def build_spend(
        self,
        chain,
        recipient: str,
        amount: int,
        fee: int,
        rng: random.Random | None = None,
        change_account: int | None = None,
    ) -> tuple[T.TaggedSpend, tuple[tuple[int, ...], ...]]:
        """Build a tagged spend from one account. The slow part: 1-2 minutes."""
        if amount <= 0:
            raise WalletError("the amount must be positive")
        self.scan(chain)
        source = self.spendable_account(amount, fee)
        note = None
        for candidate in sorted(source.notes, key=lambda entry: entry.value):
            if candidate.value >= amount + fee:
                note = candidate
                break
        if note is None:
            raise WalletError("no note large enough")
        change_value = note.value - amount - fee

        outputs = [Output(key=parse_address(recipient), value=amount)]
        if change_value:
            index = change_account if change_account is not None else (source.index + 1) % len(self.accounts)
            outputs.append(Output(key=self.accounts[index].public, value=change_value))

        # The zero-knowledge masks come from this generator. A predictable mask reveals
        # the secret it was meant to hide, so the default must be cryptographic.
        generator = rng or csprng.fresh()
        indices = chain.ring_for(source.public, generator)
        ring_keys = tuple(chain.pool[index] for index in indices)
        spend = T.build_tagged_spend(
            self.parameters,
            secrets=(source.secret,),
            publics=(source.public,),
            rings=(ring_keys,),
            input_values=(note.value,),
            outputs=tuple(outputs),
            fee=fee,
            anchor=chain.anchor,
            rng=generator,
        )
        return spend, (indices,)
