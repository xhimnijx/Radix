"""Value commitments, so that a spend can balance without revealing amounts.

Why this exists
---------------
Every output in the testnet carries its value as a plain integer. This module makes the
value a committed quantity, so a transaction can prove `sum(inputs) = sum(outputs) + fee`
without the verifier learning any of the numbers.

What it is, precisely
---------------------
A commitment to an amount `a` with randomness `r` is

    C = G·a + B·r          G ∈ R_q^kappa,  B ∈ R_q^{kappa x kappa},  r ∈ R_q^kappa

where `a` is the constant polynomial holding the amount, `G` and `B` are fixed matrices
derived from a label, and `r` is drawn uniformly. The commitment is a vector of `kappa`
polynomials, i.e. 1280 bytes.

- **Additively homomorphic**: `C(a, r) + C(a', r') = C(a + a', r + r')`, because both
  sides are linear over `R_q`.
- **Balance** is then one equation: the inputs' commitments minus the outputs' minus the
  fee's must equal `B·(sum r_in - sum r_out)`. The sender sets the output randomness so
  that the difference is zero, and the verifier checks the commitment difference is the
  zero vector -- without learning a single amount.
- **Hiding** comes from `r` being uniform; **binding** from `B` being a random matrix, so
  finding two openings is a module-SIS problem.

Two limits, stated rather than buried
-------------------------------------
1. **Amounts must be below `q`, about 2^32.** The amount is a single coefficient of the
   constant polynomial. The paper does not have this limit because it encodes the amount
   as 32 base-4 digits, which covers 64 bits -- but those digits do *not* add linearly,
   which is exactly why the paper needs a carry proof (reference [25], see
   `docs/CONFIDENTIAL-TRANSACTIONS.md` section 5). This module deliberately takes the
   linear, carry-free encoding and inherits the 32-bit ceiling.
2. **There is no range proof here.** A commitment to a negative amount is
   indistinguishable from a commitment to `q - |a|`. Without a range proof a sender can
   mint money by committing to a negative output. That is why this module is a
   *foundation*: it makes balance checkable, and it is not yet safe to use for value.
   `value_in_range` is the hook where the digit-membership proof will attach.

This is a testnet-level module. For mainnet the commitment belongs in
`radix_core/candidate_b/lattice` beside the key commitments, because it is part of the
statement the ring signature proves rather than something layered on top.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from radix_core.candidate_b.lattice import ring
from radix_core.candidate_b.lattice.params import SMILE, SmileParameters

#: Domain separation, so these matrices cannot collide with any other setup.
LABEL_VALUE = b"radix/amount/value/v1"
LABEL_BLIND = b"radix/amount/blind/v1"


class AmountError(ValueError):
    """An amount is out of range, or a balance does not hold."""


def _matrix(label: bytes, rows: int, columns: int, p: SmileParameters):
    """A deterministic random matrix, so every node derives the same parameters."""
    out = []
    for row in range(rows):
        line = []
        for column in range(columns):
            seed = hashlib.sha256(
                label + row.to_bytes(4, "little") + column.to_bytes(4, "little")
            ).digest()
            values = []
            counter = 0
            while len(values) < p.ring_degree:
                block = hashlib.sha256(seed + counter.to_bytes(4, "little")).digest()
                counter += 1
                for offset in range(0, len(block) - 3, 4):
                    word = int.from_bytes(block[offset : offset + 4], "little")
                    values.append(word % p.modulus)
                    if len(values) == p.ring_degree:
                        break
            line.append(tuple(values))
        out.append(tuple(line))
    return tuple(out)


@dataclass(frozen=True)
class Parameters:
    """The two matrices a commitment needs, derived once."""

    value: tuple  # G: kappa polynomials, one per row of the commitment
    blind: tuple  # B: kappa x kappa polynomials

    @classmethod
    def derive(cls, p: SmileParameters = SMILE) -> "Parameters":
        matrix = _matrix(LABEL_VALUE, p.challenge_dim, 1, p)
        return cls(
            value=tuple(row[0] for row in matrix),
            blind=_matrix(LABEL_BLIND, p.challenge_dim, p.challenge_dim, p),
        )


def check_amount(amount: int, p: SmileParameters = SMILE) -> int:
    """Amounts are single coefficients, so they must fit the field."""
    if type(amount) is not int:
        raise AmountError("an amount must be an integer")
    if not 0 <= amount < p.modulus:
        raise AmountError(
            f"amount {amount} does not fit a single coefficient (q = {p.modulus}); "
            "the base-4 digit encoding in docs/CONFIDENTIAL-TRANSACTIONS.md is what "
            "removes this ceiling, at the cost of a carry proof"
        )
    return amount


def commit(
    amount: int,
    randomness: tuple,
    parameters: Parameters,
    p: SmileParameters = SMILE,
) -> tuple:
    """`G·amount + B·randomness`, a vector of kappa polynomials."""
    check_amount(amount, p)
    if len(randomness) != p.challenge_dim:
        raise AmountError(f"randomness must have {p.challenge_dim} polynomials")

    return tuple(
        ring.add(
            ring.dot(parameters.blind[row], randomness, p),
            ring.scalar(amount, parameters.value[row], p),
            p,
        )
        for row in range(p.challenge_dim)
    )


def open_commitment(commitment: tuple, amount: int, randomness: tuple,
                    parameters: Parameters, p: SmileParameters = SMILE) -> bool:
    """Does this commitment open to this amount under this randomness?"""
    return commit(amount, randomness, parameters, p) == tuple(commitment)


def combine(commitments, p: SmileParameters = SMILE) -> tuple:
    """Sum a list of commitments; the result commits to the sum of the amounts."""
    total = tuple(ring.zero(p) for _ in range(p.challenge_dim))
    for commitment in commitments:
        if len(commitment) != p.challenge_dim:
            raise AmountError("commitments must all have kappa polynomials")
        total = tuple(ring.add(a, b, p) for a, b in zip(total, commitment))
    return total


def fee_commitment(fee: int, parameters: Parameters, p: SmileParameters = SMILE) -> tuple:
    """The fee is public, so its commitment uses zero randomness."""
    return commit(fee, tuple(ring.zero(p) for _ in range(p.challenge_dim)), parameters, p)


def negate(commitment: tuple, p: SmileParameters = SMILE) -> tuple:
    """The additive inverse of a commitment, coefficient by coefficient."""
    return tuple(ring.neg(poly, p) for poly in commitment)


def balanced(
    inputs,
    outputs,
    fee: int,
    parameters: Parameters,
    p: SmileParameters = SMILE,
) -> bool:
    """`sum(inputs) = sum(outputs) + fee`, checked on commitments.

    Holds exactly when the amounts balance *and* the input randomness sums to the output
    randomness. A sender who wants an unbalanced transaction cannot produce the second
    condition without opening the commitments, which is a module-SIS problem.
    """
    check_amount(fee, p)
    difference = combine(
        list(inputs)
        + [negate(combine(outputs, p), p), negate(fee_commitment(fee, parameters, p), p)],
        p,
    )
    return all(all(coefficient == 0 for coefficient in poly) for poly in difference)


def value_in_range(amount: int, p: SmileParameters = SMILE) -> bool:
    """The hook a range proof attaches to.

    Today it can only check the field bound. A real range proof -- the digit-membership
    argument from `docs/CONFIDENTIAL-TRANSACTIONS.md` section 1 -- is what makes a
    *committed* amount provably non-negative.
    """
    return 0 <= amount < p.modulus
