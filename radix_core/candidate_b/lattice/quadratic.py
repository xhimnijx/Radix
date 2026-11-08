"""The quadratic form of the p. 23 constraint equation, k = 1, m = 1.

Given public rows ``b_1, b_2, b_3``, mask ``y``, randomness ``r``, challenge
``c`` and a challenge polynomial ``gamma``, p. 23 defines

    f_eta = <b_eta, z> - c * t_eta,        z = y + c r,   t_eta = <b_eta, r> + value_eta

which equals ``<b_eta, y> - c * value_eta``, and then forms

    F_1 = f_1 f_{m+k+1} + c * sum_i gamma_i f_{m+i}.

Expanding at ``k = m = 1`` gives an exact quadratic in ``c``:

    F_1 = A_1 A_3 + c (gamma A_2 - A_1 x_2 - A_3 v_1) + c^2 (v_1 x_2 - gamma x_1),

with ``A_eta = <b_eta, y>``. The ``c^2`` coefficient is therefore *exactly*
``y_1`` from equation (20), which is why proving the constraint reduces to
proving a value that the prover can commit to once: the verifier can compute the
``c^0`` and ``c^1`` terms itself from the commitments, and the whole equation
holds iff the committed ``y_1`` matches.

This module implements the algebra and the coefficient extraction. It is an
experimental check of the equation, **not** a zero-knowledge proof of it: the
commitments and the masked responses are modelled here in the clear.
"""

from __future__ import annotations

from .params import SMILE, SmileParameters
from .ring import Poly
from . import ring

INVERSE_TWO = (SMILE.modulus + 1) // 2


class QuadraticError(ValueError):
    """The equation's inputs are malformed."""


def _p(parameters: SmileParameters | None = None) -> SmileParameters:
    return SMILE if parameters is None else parameters


def commit(b: Poly, randomness: Poly, value: Poly, parameters: SmileParameters | None = None) -> Poly:
    """t = <b, r> + value, the row-wise BDLOP component."""
    p = _p(parameters)
    return ring.add(ring.dot(b, randomness, p), value, p)


def masked_response(
    b: Poly, z: Poly, t: Poly, challenge: Poly, parameters: SmileParameters | None = None
) -> Poly:
    """f = <b, z> - c * t, which equals <b, y> - c * value."""
    p = _p(parameters)
    return ring.sub(ring.dot(b, z, p), ring.mul(challenge, t, p), p)


def product_form(
    first: Poly,
    third: Poly,
    second: Poly,
    gamma: Poly,
    challenge: Poly,
    parameters: SmileParameters | None = None,
) -> Poly:
    """F_1 = f_1 f_3 + c * gamma * f_2, the k = m = 1 instance."""
    p = _p(parameters)
    return ring.add(
        ring.mul(first, third, p),
        ring.mul(ring.mul(challenge, gamma, p), second, p),
        p,
    )


def quadratic_coefficient(
    at_zero: Poly,
    at_one: Poly,
    at_two: Poly,
    parameters: SmileParameters | None = None,
) -> Poly:
    """Second divided difference: (F(2) - 2F(1) + F(0)) / 2."""
    p = _p(parameters)
    return ring.scalar(
        (p.modulus + 1) // 2,
        ring.add(ring.sub(at_two, ring.scalar(2, at_one, p), p), at_zero, p),
        p,
    )


def expected_quadratic_coefficient(
    v_one: Poly,
    x_two: Poly,
    gamma: Poly,
    x_one: Poly,
    parameters: SmileParameters | None = None,
) -> Poly:
    """y_1 = v_1 . x_2 - gamma . x_1, equation (20) at k = m = 1."""
    p = _p(parameters)
    return ring.sub(ring.mul(v_one, x_two, p), ring.mul(gamma, x_one, p), p)


def evaluate(
    rows: tuple[Poly, Poly, Poly],
    mask: Poly,
    randomness: Poly,
    values: tuple[Poly, Poly, Poly],
    gamma: Poly,
    challenge: Poly,
    parameters: SmileParameters | None = None,
) -> tuple[Poly, Poly, Poly]:
    """(F_1, f_1, f_2, f_3) for one challenge value; rows are (b_1, b_2, b_3)."""
    p = _p(parameters)
    first, second, third = rows
    v_one, x_one, x_two = values
    z = tuple(
        ring.add(a, ring.mul(challenge, b, p), p) for a, b in zip(mask, randomness)
    )
    f_one = masked_response(first, z, commit(first, randomness, v_one, p), challenge, p)
    f_two = masked_response(second, z, commit(second, randomness, x_one, p), challenge, p)
    f_three = masked_response(third, z, commit(third, randomness, x_two, p), challenge, p)
    return product_form(f_one, f_three, f_two, gamma, challenge, p), f_one, f_two, f_three
