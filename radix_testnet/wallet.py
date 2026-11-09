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

import hashlib
import random
from dataclasses import dataclass, field

from radix_core.candidate_b.lattice import ring, ring_signature as RS
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters
from radix_core.candidate_b.lattice.spend import Output

from . import tagged as T

ADDRESS_PREFIX = "rtx"
ACCOUNTS = 4


class WalletError(ValueError):
    """A wallet could not do what was asked."""


def _rng_for(seed: bytes, index: int) -> random.Random:
    digest = hashlib.sha256(seed + index.to_bytes(4, "little")).digest()
    return random.Random(int.from_bytes(digest, "big"))


def address_of(public: tuple, p: SmileParameters = SMILE) -> str:
    return ADDRESS_PREFIX + "1" + b"".join(ring.encode(poly, p) for poly in public).hex()


def parse_address(address: str, p: SmileParameters = SMILE) -> tuple:
    if not address.startswith(ADDRESS_PREFIX + "1"):
        raise WalletError("not a testnet address")
    try:
        blob = bytes.fromhex(address[len(ADDRESS_PREFIX) + 1 :])
    except ValueError:
        raise WalletError("the address is not valid hex") from None
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
    """A seed, a set of accounts, and the notes each account can spend."""

    seed: bytes
    parameters: RS.Parameters
    accounts: list[Account] = field(default_factory=list)

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

        generator = rng or random.Random()
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
