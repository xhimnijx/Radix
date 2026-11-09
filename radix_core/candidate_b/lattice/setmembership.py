"""SMILE set-membership proof: Fig. 7 (protocol), Fig. 8 (recursion), Fig. 9 (checks).

Candidate B rests on this: prove that a short secret ``s`` satisfies
``A s = pk_iota`` for one *unspecified* ``iota`` in a public ring of ``n = l^m``
keys, without revealing which. It is the lattice analogue of Monero's ring
signature, and it is what Fig. 6 sketches and Figs. 7-9 specify.

Transcribed from the full version (ePrint 2021/564):

* ``t = (t_0, t_1 .. t_{k+2m+1})`` is a BDLOP commitment to
  ``(0_kappa, v_1..v_m, w', x_2..x_m, g, psi)`` under one randomness ``r``;
* ``P``'s ``j``-th column is ``NTT(-c' * pk_j)`` (eq. 31), so membership is the
  tensor relation ``P(v_1 (x) ... (x) v_m) = x_1``;
* the Fig. 8 recursion cuts that relation down one tensor factor at a time,
  producing ``y_j`` whose first ``d/l`` coefficients must vanish;
* ``h = g + y_1 + ... + y_m`` is sent; the verifier checks its zero prefix
  (Fig. 9 line 15) and one quadratic equation in ``c`` (line 13) that forces the
  ``v_i`` binary.

Deviations, stated because they matter:

1. **Historical note, no longer accurate:** masks *used* to be uniform in
   ``[-2^20, 2^20]``, which dwarfs ``||c r||``, so the response is statistically
   independent of the secret without aborting. Proofs are larger than SMILE's.
2. **``e_1`` placement in ``F_m``.** Fig. 9 line 12 puts ``-e_1 sum gamma`` at
   order ``c``; Fig. 7's ``y_m`` carries it in the ``c^2`` coefficient. Only the
   ``c^2`` coefficient is checked -- the ``c^0`` part is fixed by ``omega``,
   committed before ``c`` exists, and the ``c^1`` part is absorbed by ``psi`` -- so
   the ``<1, v_i> = 1`` constraint is only enforceable at order ``c^2``. This
   implementation follows Fig. 7 and puts it there: with it at order ``c`` the
   honest prover's check cannot pass.
3. **``m >= 2``.** The block matrix of eq. (23) has shape ``(m+1)l x ml``, which
   does not match ``P_1``'s ``kl`` rows when ``m = 1`` and ``k > 1``; the paper's
   formulas assume the recursive case. ``m = 1`` is rejected explicitly rather
   than silently mis-proved.
4. **The message is bound** into ``c'``, as a ring signature requires.
5. Research component. No security claim without independent review.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from . import ntt, recursion as R, ring, subring, tag as tagmod, transcript
from .params import SMILE, SmileParameters
from .ring import Poly

# Rejection-sampling parameters. Calibrated in experiments/mask_calibration.py:
# T(W) = 296*sqrt(W) is the measured 99th percentile of ||c r||_2, and
# s = T / sqrt(2 ln M) with M = sqrt(3/2) gives MASK_STD_FACTOR = 1.567*296.
MASK_M = math.sqrt(1.5)
MASK_STD_FACTOR = 464.0
MAX_ATTEMPTS = 64

#: Kept for the older uniform-mask callers; the main proof no longer uses it.
MASK_BOUND = 1 << 20
PROOF_TAG = b"radix/b/setmembership/v1"
SLOTS = SMILE.subring_dimension


class SetMembershipError(ValueError):
    """The keys, statement, witness, or proof are malformed."""




def _p(parameters: SmileParameters | None = None) -> SmileParameters:
    return SMILE if parameters is None else parameters


def _add_all(polys, p: SmileParameters) -> Poly:
    total = ring.zero(p)
    for poly in polys:
        total = ring.add(total, poly, p)
    return total


def _lift(vector: tuple[tuple[int, ...], ...], p: SmileParameters) -> Poly:
    return subring.from_constants(tuple(element[0] for element in vector), p)


def _e1(p: SmileParameters) -> Poly:
    return _lift(tuple((1, 0, 0, 0) if s == 0 else (0, 0, 0, 0) for s in range(SLOTS)), p)


def _ones(p: SmileParameters) -> Poly:
    return _lift(tuple((1, 0, 0, 0) for _ in range(SLOTS)), p)


def masking_width(
    depth: int, parameters: SmileParameters | None = None, row_count: int | None = None
) -> int:
    """W = kappa + lambda + rows + 2m + 1, the width of r, y, z and the key rows.

    ``row_count`` is the height of the public matrix: ``k`` for the paper's
    protocol, ``k + k'`` when the tag rows of ``A_ext = [A; A']`` are folded in.
    """
    sm = _p(parameters)
    if type(depth) is not int or depth < 2:
        raise SetMembershipError("depth must be at least 2 (see the module docstring)")
    rows = sm.matrix_rows if row_count is None else row_count
    if type(rows) is not int or rows < 1:
        raise SetMembershipError("the matrix must have at least one row")
    return sm.challenge_dim + sm.masking_dim + rows + 2 * depth + 1


def _poly_from(raw: bytes, p: SmileParameters) -> Poly:
    if len(raw) != 4 * p.ring_degree:
        raise SetMembershipError("poly source has the wrong length")
    return tuple(int.from_bytes(raw[4 * i : 4 * (i + 1)], "little") % p.modulus for i in range(p.ring_degree))


def _draw(tx: transcript.Transcript, label: bytes, p: SmileParameters) -> Poly:
    return _poly_from(tx.challenge(label, 4 * p.ring_degree), p)


def _draw_ternary(tx: transcript.Transcript, label: bytes, p: SmileParameters) -> Poly:
    raw = tx.challenge(label, p.ring_degree)
    return tuple(0 if byte < 128 else (1 if byte < 192 else -1) for byte in raw)


def _gamma_elements(gamma: tuple[Poly, ...], p: SmileParameters) -> tuple[tuple[int, ...], ...]:
    out = []
    for poly in gamma:
        out.extend(subring.slots(poly, p))
    return tuple(out)



def mask_std(width: int) -> float:
    """Per-coefficient mask width for a vector of `width` components."""
    if type(width) is not int or width < 1:
        raise SetMembershipError("width must be a positive integer")
    return MASK_STD_FACTOR * math.sqrt(width)


def _gaussian(rng: random.Random, width: int, p: SmileParameters) -> tuple[Poly, ...]:
    """A mask of `width` polynomials, per-coefficient standard deviation `s`.

    The coefficients come from a **discrete** Gaussian read out of a table, which is
    the object Lemma A.6 is stated for. The table is shared byte for byte with the Rust
    implementation, so the two cannot sample different distributions -- the defect that
    made the previous rounding sampler unportable as well as imprecise.
    """
    from . import gaussian as gauss

    return tuple(
        tuple(gauss.sample(rng, width) % p.modulus for _ in range(p.ring_degree))
        for _ in range(width)
    )


def _response_bound(width: int, p: SmileParameters) -> int:
    """beta^2 = s^2 * 2 * width * d, the l2 bound the verifier checks."""
    sigma = mask_std(width)
    return sigma * sigma * 2 * width * p.ring_degree


def _l2_squared(vector: tuple[Poly, ...], p: SmileParameters) -> int:
    return sum(ring.l2_squared(poly, p) for poly in vector)


def _inner(left: tuple[Poly, ...], right: tuple[Poly, ...], p: SmileParameters) -> int:
    total = 0
    for a, b in zip(left, right):
        total += sum(
            ring.centered(x, p) * ring.centered(y, p) for x, y in zip(a, b)
        )
    return total


def _reject(
    response: tuple[Poly, ...],
    product: tuple[Poly, ...],
    sigma: float,
    rng: random.Random,
    p: SmileParameters,
) -> bool:
    """The paper's Rej1 (Fig. 10): bimodal, so the mask can be 11x narrower."""
    inner = _inner(response, product, p)
    if inner < 0:
        return True
    norm_sq = _l2_squared(product, p)
    exponent = (-2 * inner + norm_sq) / (2 * sigma * sigma) - math.log(MASK_M)
    return rng.random() > math.exp(min(0.0, exponent))


def _is_unit(poly: Poly, p: SmileParameters) -> bool:
    """Whether `poly` is invertible in R_q.

    The exact condition depends on how the quartics factor, and the two cases are
    genuinely different:

    * split quartic -- `R_q ~ Z_q^128` -- so a unit needs **all 128 NTT
      coordinates** nonzero; a merely nonzero residue is only the weaker
      "not all four coordinates vanish" and would admit zero divisors;
    * irreducible quartic -- `R_q ~ (F_{q^4})^32` -- so a **nonzero residue** is a
      unit of a field, and there is no NTT to consult.

    The verifier must check this: the line-13 argument divides by `c^2`, and a
    non-unit `c` hides a coordinate where the binaryness constraint is vacuous.
    """
    if ntt.try_transform(p.modulus, p.ring_degree) is not None:
        return all(coefficient != 0 for coefficient in ntt.forward(poly, p))
    return all(residue != (0, 0, 0, 0) for residue in subring.slots(poly, p))


def _paper_to_slot(position: int, depth: int, rows: int, p: SmileParameters) -> int:
    """Map the paper's t-index (1..k+2m+1) to its position in the commitment vector.

    The vector starts with ``t_0`` (kappa entries), so paper position ``j`` maps to
    ``kappa + j - 1``; the ``g`` commitment sits right after ``t_{m+k}`` and the
    ``x_2 .. x_m`` commitments are appended at the end, before ``psi``.
    """
    kappa = p.challenge_dim
    if position == rows + 2 * depth + 1:
        return kappa + rows + 2 * depth  # psi, the final entry
    if position <= depth + rows:
        return kappa + position - 1
    if position == rows + 2 * depth:
        return kappa + depth + rows
    return kappa + depth + rows + (position - (depth + rows))


@dataclass(frozen=True)
class Keys:
    """Public parameters: B_0 (kappa rows) and b_1 .. b_{k+2m+1} (W wide)."""

    rows0: tuple[tuple[Poly, ...], ...]
    rows: tuple[tuple[Poly, ...], ...]
    depth: int
    row_count: int | None = None

    @property
    def count(self) -> int:
        return SMILE.matrix_rows if self.row_count is None else self.row_count

    def __post_init__(self) -> None:
        width = masking_width(self.depth, None, self.count)
        if len(self.rows0) != SMILE.challenge_dim:
            raise SetMembershipError("B_0 must have kappa rows")
        if len(self.rows) != self.count + 2 * self.depth + 1:
            raise SetMembershipError("wrong number of b rows")
        for row in self.rows0 + self.rows:
            if len(row) != width:
                raise SetMembershipError("key rows must have width W")


def setup(
    rng: random.Random,
    depth: int,
    parameters: SmileParameters | None = None,
    row_count: int | None = None,
) -> Keys:
    sm = _p(parameters)
    rows = sm.matrix_rows if row_count is None else row_count
    width = masking_width(depth, sm, rows)
    rows0 = tuple(
        tuple(ring.sample_uniform(rng, sm) for _ in range(width)) for _ in range(sm.challenge_dim)
    )
    b_rows = tuple(
        tuple(ring.sample_uniform(rng, sm) for _ in range(width))
        for _ in range(rows + 2 * depth + 1)
    )
    return Keys(rows0=rows0, rows=b_rows, depth=depth, row_count=row_count)


@dataclass(frozen=True)
class Statement:
    """The public ring: A and the ``l^m`` public keys."""

    matrix: tuple[tuple[Poly, ...], ...]
    keys: tuple[tuple[Poly, ...], ...]
    depth: int

    def __post_init__(self) -> None:
        if not self.matrix:
            raise SetMembershipError("A must have at least one row")
        if any(len(row) != SMILE.matrix_cols for row in self.matrix):
            raise SetMembershipError("A must have ell columns")
        if self.depth < 2:
            raise SetMembershipError("depth must be at least 2")
        if len(self.keys) != SLOTS**self.depth:
            raise SetMembershipError("the ring must have l^m keys")
        if any(len(key) != len(self.matrix) for key in self.keys):
            raise SetMembershipError("each public key must have k components")


def keygen(
    rng: random.Random, matrix: tuple[tuple[Poly, ...], ...], parameters: SmileParameters | None = None
) -> tuple[tuple[Poly, ...], tuple[Poly, ...]]:
    sm = _p(parameters)
    secret = ring.sample_vector(rng, sm.matrix_cols, small=True, parameters=sm)
    return secret, tuple(ring.dot(row, secret, sm) for row in matrix)


#: Coefficients of `z` above this are rejected by the verifier, so they fit in 16 bits.
BOUND_MULTIPLIER = 12


def response_bound_infinity(width: int) -> int:
    """The infinity-norm bound on `z`: the paper's `12 * sigma`."""
    return int(BOUND_MULTIPLIER * mask_std(width))


def encode_bounded(vector: tuple[Poly, ...]) -> bytes:
    """Two bytes per coefficient, centred. `q - a` is negative `a`."""
    half = SMILE.modulus // 2
    out = bytearray()
    for poly in vector:
        for value in poly:
            centred = value - SMILE.modulus if value > half else value
            out += int(centred).to_bytes(2, "little", signed=True)
    return bytes(out)


def decode_bounded(data: bytes, count: int) -> tuple[Poly, ...]:
    """Inverse of `encode_bounded`, reducing back into [0, q)."""
    polys = []
    cursor = 0
    for _ in range(count):
        poly = []
        for _ in range(SMILE.ring_degree):
            value = int.from_bytes(data[cursor : cursor + 2], "little", signed=True)
            cursor += 2
            poly.append(value % SMILE.modulus)
        polys.append(tuple(poly))
    return tuple(polys)


@dataclass(frozen=True)
class Proof:
    commitment: tuple[Poly, ...]
    h: Poly
    omega: Poly
    challenge: Poly
    challenge_prime: Poly
    response_prime: tuple[Poly, ...]
    response: tuple[Poly, ...]
    tag_proof: "tagmod.TagProof | None" = None

    def encode(self) -> bytes:
        """Challenges are ternary (one byte each); `z` is bounded (two bytes each).

        The response `z` is the only large vector whose coefficients are provably
        small: the verifier rejects any coefficient above `12*sigma`, which for
        `sigma = 2665.5` is 31,986 and fits a signed 16-bit integer. Storing it as a
        residue modulo `q` costs four bytes for no added information.
        """
        body = b"".join(
            ring.encode(poly) for poly in self.commitment + (self.h, self.omega)
        )
        # Both responses are bounded by 12 sigma and fit 16 bits; z' has its own sigma.
        body += encode_bounded(self.response_prime)
        body += encode_bounded(self.response)
        body += bytes(coefficient + 1 for coefficient in self.challenge)
        body += bytes(coefficient + 1 for coefficient in self.challenge_prime)
        if self.tag_proof is not None:
            body += self.tag_proof.encode()
        return body

    @property
    def size_bytes(self) -> int:
        return len(self.encode())


def _index_vectors(index: int, depth: int) -> tuple[tuple[int, ...], ...]:
    digits = []
    value = index
    for _ in range(depth):
        digits.append(value % SLOTS)
        value //= SLOTS
    if value:
        raise SetMembershipError("index is outside the ring")
    return tuple(
        tuple(1 if position == digit else 0 for position in range(SLOTS))
        for digit in reversed(digits)
    )


def _set_matrix(
    c_prime: Poly, statement: Statement, p: SmileParameters
) -> tuple[tuple[tuple[int, ...], ...], ...]:
    """P: row (component, slot), column j = NTT(-c' pk_j)."""
    columns = []
    for key in statement.keys:
        element = []
        for component in range(len(statement.matrix)):
            element.extend(subring.slots(ring.neg(ring.mul(c_prime, key[component], p), p), p))
        columns.append(tuple(element))
    return tuple(
        tuple(column[row] for column in columns)
        for row in range(len(statement.matrix) * SLOTS)
    )


def _b_transpose(poly: Poly, p: SmileParameters) -> Poly:
    """B^T gamma: the vector whose slots are all equal to gamma's first slot.

    B has a first row of ones, so (B^T gamma)_i = gamma_0 for every i. This is
    what encodes ``<1, v_i> = 1``: pairing it with a one-hot ``v_i`` selects
    gamma_0, which is exactly the ``<e_1, gamma>`` term it must cancel.
    """
    first = subring.slots(poly, p)[0]
    return subring.glue(tuple(first for _ in range(SLOTS)), p)


def _final_x(
    matrix: tuple[tuple[tuple[int, ...], ...], ...],
    gamma_m: tuple[Poly, ...],
    depth: int,
    p: SmileParameters,
) -> tuple[Poly, ...]:
    """x_{m+1} = P~_m^T gamma_m, one polynomial per tensor factor (eq. 23)."""
    blocks = [_b_transpose(gamma_m[index + 1], p) for index in range(depth - 1)]
    tail = subring.glue(R.challenge_block(subring.slots(gamma_m[0], p), matrix, p), p)
    blocks.append(ring.add(tail, _b_transpose(gamma_m[depth], p), p))
    return tuple(blocks)


def ring_digest(statement: "Statement", p: SmileParameters) -> bytes:
    """A digest of the ring, in order, so a proof binds the ring it was made for.

    Without this, the proof binds the message, ``w``, the commitments, ``h``, ``omega``
    and ``c`` -- but not the keys. The verifier rebuilds the ring from its own pool, so
    the scheme is sound only as long as prover and verifier are the same process. On a
    network they are not: the node chooses a ring by pool index, and a proof made
    against a different pool would still verify.

    Absorbed as a transcript label, so it costs **zero proof bytes** and changes no
    check: a prover working from one ring derives a different ``c`` from a verifier
    holding another, and the proof simply fails.

    Both implementations must hash the keys identically, or cross-language verification
    breaks -- the same discipline the discrete Gaussian will need.
    """
    tx = transcript.Transcript(b"radix/ring/v1")
    for key in statement.keys:
        tx.absorb(b"pk", b"".join(ring.encode(poly, p) for poly in key))
    return tx.challenge(b"ring", 32)


def _head(
    message: bytes,
    w: tuple[Poly, ...],
    commitment: tuple[Poly, ...],
    p: SmileParameters,
    digest: bytes,
) -> transcript.Transcript:
    tx = transcript.Transcript(PROOF_TAG).absorb(b"message", message)
    # The ring first: it is the statement, and a proof must not outlive it.
    tx.absorb(b"ring", digest)
    tx.absorb(b"w", b"".join(ring.encode(poly, p) for poly in w))
    tx.absorb(b"t", b"".join(ring.encode(poly, p) for poly in commitment))
    return tx



def _tag_context(c_prime: Poly, t0: Poly, p: SmileParameters) -> bytes:
    """Bind the tag proof to this signature: its c' and its t_0."""
    return (
        PROOF_TAG
        + bytes(coefficient + 1 for coefficient in c_prime)
        + ring.encode(t0, p)
    )


def prove(
    keys: Keys,
    statement: Statement,
    secret: tuple[Poly, ...],
    index: int,
    message: bytes,
    rng: random.Random,
    parameters: SmileParameters | None = None,
    tag_keys: "tagmod.TagKeys | None" = None,
) -> Proof:
    """Fig. 7 with rejection sampling; retries until a mask is accepted.

    Expected 2M^2 ~ 3 attempts. A full attempt is rebuilt each time because the
    mask is fresh, so a rejection costs a whole proof.
    """
    for _attempt in range(MAX_ATTEMPTS):
        result = _prove_once(
            keys, statement, secret, index, message, rng, parameters, tag_keys
        )
        if result is not None:
            return result
    raise SetMembershipError("rejection sampling did not accept a proof")


def _prove_once(
    keys: Keys,
    statement: Statement,
    secret: tuple[Poly, ...],
    index: int,
    message: bytes,
    rng: random.Random,
    parameters: SmileParameters | None = None,
    tag_keys: "tagmod.TagKeys | None" = None,
) -> "Proof | None":
    """One attempt. Returns None when rejection sampling rejects."""
    sm = _p(parameters)
    depth = keys.depth
    if depth != statement.depth:
        raise SetMembershipError("key and statement depth disagree")
    if not 0 <= index < SLOTS**depth:
        raise SetMembershipError("index is outside the ring")
    if tag_keys is not None:
        raise SetMembershipError(
            "the separate tag proof is WITHDRAWN and forgeable (see tag.py and "
            "REVIEW-FINDINGS.md). Use ring_signature.sign_tagged, which proves "
            "T = A' s inside this relation."
        )
    if tuple(ring.dot(row, secret, sm) for row in statement.matrix) != statement.keys[index]:
        raise SetMembershipError("the secret does not open the claimed ring member")
    rows = len(statement.matrix)
    width = masking_width(depth, sm, rows)

    randomness = ring.sample_vector(rng, width, small=True, parameters=sm)
    mask = _gaussian(rng, width, sm)
    mask_prime = _gaussian(rng, sm.matrix_cols, sm)

    w = tuple(ring.dot(row, mask, sm) for row in keys.rows0)
    w_prime = tuple(ring.dot(row, mask_prime, sm) for row in statement.matrix)
    v_vectors = tuple(
        tuple((value, 0, 0, 0) for value in vector) for vector in _index_vectors(index, depth)
    )
    v_polys = tuple(_lift(vector, sm) for vector in v_vectors)

    g_poly = tuple(
        0 if position < sm.ring_degree // SLOTS else rng.randrange(sm.modulus)
        for position in range(sm.ring_degree)
    )
    values: dict[int, Poly] = {}
    for i in range(1, depth + 1):
        values[i] = v_polys[i - 1]
    for i in range(1, rows + 1):
        values[depth + i] = w_prime[i - 1]
    values[rows + 2 * depth] = g_poly

    commitment = list(tuple(ring.dot(row, randomness, sm) for row in keys.rows0))
    for position in list(range(1, depth + rows + 1)) + [rows + 2 * depth]:
        commitment.append(
            ring.add(ring.dot(keys.rows[position - 1], randomness, sm), values[position], sm)
        )

    tx = _head(message, w, tuple(commitment), sm, ring_digest(statement, sm))
    c_prime = _draw_ternary(tx, b"c-prime", sm)
    if not _is_unit(c_prime, sm):
        return None
    product_prime = tuple(ring.mul(c_prime, secret[i], sm) for i in range(sm.matrix_cols))
    response_prime = tuple(
        ring.add(mask_prime[i], product_prime[i], sm) for i in range(sm.matrix_cols)
    )
    if _reject(response_prime, product_prime, mask_std(sm.matrix_cols), rng, sm):
        return None
    tx.absorb(b"z-prime", b"".join(ring.encode(poly, sm) for poly in response_prime))

    set_matrix = _set_matrix(c_prime, statement, sm)
    x1_polys = tuple(
        ring.sub(w_prime[i], ring.dot(statement.matrix[i], response_prime, sm), sm)
        for i in range(rows)
    )

    ys: list[Poly] = []
    weights: dict[int, tuple[Poly, ...]] = {}
    xs: list[Poly] = []
    matrix = set_matrix
    for level in range(1, depth):
        count = rows if level == 1 else 1
        gamma = tuple(_draw(tx, b"gamma", sm) for _ in range(count))
        weights[level] = gamma
        matrix = R.reduce_matrix(_gamma_elements(gamma, sm), matrix, depth - level + 1)
        x_next = subring.glue(R.matrix_vector(matrix, R.tensor(v_vectors[level:])), sm)
        if level == 1:
            y = ring.sub(
                ring.mul(v_polys[0], x_next, sm),
                _add_all((ring.mul(x1_polys[i], gamma[i], sm) for i in range(rows)), sm),
                sm,
            )
        else:
            y = ring.sub(ring.mul(v_polys[level - 1], x_next, sm), ring.mul(xs[-1], gamma[0], sm), sm)
        ys.append(y)
        xs.append(x_next)
        commitment.append(
            ring.add(ring.dot(keys.rows[depth + rows + level - 1], randomness, sm), x_next, sm)
        )
        tx.absorb(b"t-level", ring.encode(commitment[-1], sm))

    gamma_m = tuple(_draw(tx, b"gamma-m", sm) for _ in range(depth + 1))
    x_last = _final_x(matrix, gamma_m, depth, sm)
    e1_sum = _add_all((gamma_m[i + 1] for i in range(depth)), sm)
    y_m = ring.sub(
        _add_all((ring.mul(v_polys[i], x_last[i], sm) for i in range(depth)), sm),
        ring.add(ring.mul(xs[-1], gamma_m[0], sm), ring.mul(_e1(sm), e1_sum, sm), sm),
        sm,
    )
    ys.append(y_m)
    h = _add_all([g_poly] + ys, sm)
    tx.absorb(b"h", ring.encode(h, sm))
    alphas = tuple(_draw(tx, b"alpha", sm) for _ in range(depth + 1))

    a_values = {
        position: ring.dot(keys.rows[position - 1], mask, sm)
        for position in range(1, rows + 2 * depth + 2)
    }
    psi_levels: list[Poly] = []
    omega_levels: list[Poly] = []
    for level in range(1, depth):
        if level == 1:
            gamma_term = _add_all(
                (ring.mul(weights[1][i], a_values[depth + i + 1], sm) for i in range(rows)), sm
            )
            body = ring.sub(
                ring.sub(gamma_term, ring.mul(a_values[1], xs[0], sm), sm),
                ring.mul(a_values[depth + rows + 1], v_polys[0], sm),
                sm,
            )
        else:
            body = ring.sub(
                ring.sub(
                    ring.mul(weights[level][0], a_values[depth + rows + level - 1], sm),
                    ring.mul(a_values[level], xs[level - 1], sm),
                    sm,
                ),
                ring.mul(a_values[depth + rows + level], v_polys[level - 1], sm),
                sm,
            )
        psi_levels.append(body)
        omega_levels.append(ring.mul(a_values[level], a_values[depth + rows + level], sm))

    psi_m = ring.sub(
        ring.mul(gamma_m[0], a_values[rows + 2 * depth - 1], sm),
        _add_all((ring.mul(x_last[i], a_values[i + 1], sm) for i in range(depth)), sm),
        sm,
    )
    psi_levels.append(psi_m)
    psi_sm = ring.sub(_add_all(psi_levels, sm), a_values[rows + 2 * depth], sm)
    omega_sm = _add_all(omega_levels, sm)

    psi_bin = _add_all(
        (
            ring.mul(
                alphas[i + 1],
                ring.mul(
                    a_values[i + 1],
                    ring.sub(ring.constant(1, sm), ring.scalar(2, v_polys[i], sm), sm),
                    sm,
                ),
                sm,
            )
            for i in range(depth)
        ),
        sm,
    )
    omega_bin = _add_all(
        (ring.mul(alphas[i + 1], ring.mul(a_values[i + 1], a_values[i + 1], sm), sm) for i in range(depth)),
        sm,
    )
    psi = ring.add(ring.mul(alphas[0], psi_sm, sm), psi_bin, sm)
    omega = ring.add(
        ring.add(ring.mul(alphas[0], omega_sm, sm), omega_bin, sm),
        a_values[rows + 2 * depth + 1],
        sm,
    )
    commitment.append(
        ring.add(ring.dot(keys.rows[rows + 2 * depth], randomness, sm), psi, sm)
    )

    tx.absorb(b"t-psi", ring.encode(commitment[-1], sm))
    tx.absorb(b"omega", ring.encode(omega, sm))
    challenge = _draw_ternary(tx, b"c", sm)
    if not _is_unit(challenge, sm):
        return None
    product = tuple(ring.mul(challenge, randomness[i], sm) for i in range(width))
    response = tuple(ring.add(mask[i], product[i], sm) for i in range(width))
    if _reject(response, product, mask_std(width), rng, sm):
        return None
    tag_proof = None
    if tag_keys is not None:
        tag_proof = tagmod.prove_tag(
            tag_keys,
            secret,
            mask_prime,
            c_prime,
            response_prime,
            _tag_context(c_prime, commitment[0], sm),
            rng,
            sm,
        )
    return Proof(
        commitment=tuple(commitment),
        h=h,
        omega=omega,
        challenge=challenge,
        challenge_prime=c_prime,
        response_prime=response_prime,
        response=response,
        tag_proof=tag_proof,
    )


def verify(
    keys: Keys,
    statement: Statement,
    proof: Proof,
    message: bytes,
    parameters: SmileParameters | None = None,
    tag_keys: "tagmod.TagKeys | None" = None,
) -> bool:
    """Fig. 9 lines 01-15, plus the optional B3 tag proof."""
    sm = _p(parameters)
    try:
        depth = keys.depth
        if depth != statement.depth or type(proof) is not Proof:
            return False
        rows = len(statement.matrix)
        width = masking_width(depth, sm, rows)
        if len(proof.commitment) != sm.challenge_dim + rows + 2 * depth + 1:
            return False
        if len(proof.response_prime) != sm.matrix_cols or len(proof.response) != width:
            return False
        # l2 bounds, as the paper states them: beta = s sqrt(2Wd) and
        # beta' = s' sqrt(2 ell d). The old check was l-infinity, which let the
        # response bound rather than the secret bound act as the security parameter.
        # The paper also requires an infinity-norm check on z, which the compact
        # encoding depends on: a coefficient above 12*sigma would not fit in 16 bits.
        limit = response_bound_infinity(width)
        for poly in proof.response:
            if any(min(value, sm.modulus - value) > limit for value in poly):
                return False
        if _l2_squared(proof.response, sm) > _response_bound(width, sm):
            return False
        limit_prime = response_bound_infinity(sm.matrix_cols)
        for poly in proof.response_prime:
            if any(min(value, sm.modulus - value) > limit_prime for value in poly):
                return False
        if _l2_squared(proof.response_prime, sm) > _response_bound(sm.matrix_cols, sm):
            return False
        # The line-13 argument divides by c^2 and the tag argument by c', so both
        # must be units. Without this check a non-unit challenge leaves a
        # coordinate where the constraint is vacuous (review finding, 2026-11-08).
        if not _is_unit(proof.challenge, sm) or not _is_unit(proof.challenge_prime, sm):
            return False

        # Fig. 9 line 03 inverted: w = B_0 z - c t_0, so it need not be sent.
        w = tuple(
            ring.sub(product, scaled, sm)
            for product, scaled in zip(
                tuple(ring.dot(row, proof.response, sm) for row in keys.rows0),
                tuple(
                    ring.mul(proof.challenge, poly, sm)
                    for poly in proof.commitment[: sm.challenge_dim]
                ),
            )
        )
        head_length = sm.challenge_dim + depth + rows + 1
        tx = _head(
        message, w, proof.commitment[:head_length], sm, ring_digest(statement, sm)
    )
        if _draw_ternary(tx, b"c-prime", sm) != proof.challenge_prime:
            return False
        tx.absorb(b"z-prime", b"".join(ring.encode(poly, sm) for poly in proof.response_prime))

        # line 04: t_{m+i} -= (A z')_i
        slot_of = {
            position: _paper_to_slot(position, depth, rows, sm)
            for position in range(1, rows + 2 * depth + 2)
        }
        a_z = tuple(ring.dot(row, proof.response_prime, sm) for row in statement.matrix)
        values = list(proof.commitment)
        for i in range(1, rows + 1):
            at = slot_of[depth + i]
            values[at] = ring.sub(values[at], a_z[i - 1], sm)

        # line 05
        f = {
            position: ring.sub(
                ring.dot(keys.rows[position - 1], proof.response, sm),
                ring.mul(proof.challenge, values[slot_of[position]], sm),
                sm,
            )
            for position in range(1, rows + 2 * depth + 2)
        }

        # lines 06-09
        set_matrix = _set_matrix(proof.challenge_prime, statement, sm)
        matrix = set_matrix
        weights: dict[int, tuple[Poly, ...]] = {}
        for level in range(1, depth):
            count = rows if level == 1 else 1
            gamma = tuple(_draw(tx, b"gamma", sm) for _ in range(count))
            weights[level] = gamma
            matrix = R.reduce_matrix(_gamma_elements(gamma, sm), matrix, depth - level + 1)
            tx.absorb(b"t-level", ring.encode(proof.commitment[slot_of[depth + rows + level]], sm))
        gamma_m = tuple(_draw(tx, b"gamma-m", sm) for _ in range(depth + 1))
        x_last = _final_x(matrix, gamma_m, depth, sm)
        e1_sum = _add_all((gamma_m[i + 1] for i in range(depth)), sm)

        # line 10
        total = ring.add(
            ring.mul(f[1], f[depth + rows + 1], sm),
            ring.mul(
                proof.challenge,
                _add_all((ring.mul(weights[1][i], f[depth + i + 1], sm) for i in range(rows)), sm),
                sm,
            ),
            sm,
        )
        # line 11
        for level in range(2, depth):
            total = ring.add(
                total,
                ring.add(
                    ring.mul(f[level], f[depth + rows + level], sm),
                    ring.mul(
                        proof.challenge,
                        ring.mul(weights[level][0], f[depth + rows + level - 1], sm),
                        sm,
                    ),
                    sm,
                ),
                sm,
            )
        # line 12, with the e_1 term at order c^2 (see the module docstring)
        total = ring.add(
            total,
            ring.sub(
                ring.mul(
                    proof.challenge,
                    ring.sub(
                        ring.mul(gamma_m[0], f[rows + 2 * depth - 1], sm),
                        _add_all((ring.mul(x_last[i], f[i + 1], sm) for i in range(depth)), sm),
                        sm,
                    ),
                    sm,
                ),
                ring.mul(
                    ring.mul(proof.challenge, proof.challenge, sm),
                    ring.mul(_e1(sm), e1_sum, sm),
                    sm,
                ),
                sm,
            ),
            sm,
        )

        # line 13
        inner = ring.sub(
            ring.sub(total, ring.mul(proof.challenge, f[rows + 2 * depth], sm), sm),
            ring.mul(ring.mul(proof.challenge, proof.challenge, sm), proof.h, sm),
            sm,
        )
        tx.absorb(b"h", ring.encode(proof.h, sm))
        alphas = tuple(_draw(tx, b"alpha", sm) for _ in range(depth + 1))
        tx.absorb(b"t-psi", ring.encode(proof.commitment[-1], sm))
        tx.absorb(b"omega", ring.encode(proof.omega, sm))
        if _draw_ternary(tx, b"c", sm) != proof.challenge:
            return False

        lhs = ring.add(
            ring.add(
                ring.mul(alphas[0], inner, sm),
                _add_all(
                    (
                        ring.mul(
                            alphas[i + 1],
                            ring.add(
                                ring.mul(f[i + 1], f[i + 1], sm),
                                ring.mul(proof.challenge, f[i + 1], sm),
                                sm,
                            ),
                            sm,
                        )
                        for i in range(depth)
                    ),
                    sm,
                ),
                sm,
            ),
            f[rows + 2 * depth + 1],
            sm,
        )
        if lhs != proof.omega:
            return False

        # lines 14-15
        prefix = sm.ring_degree // SLOTS
        if any(proof.h[i] != 0 for i in range(prefix)):
            return False

        if tag_keys is not None:
            # The separate tag proof is WITHDRAWN and forgeable; refusing here means a
            # caller cannot accidentally accept a proof whose tag was checked by a
            # construction known to be broken. Use ring_signature.verify_tagged.
            raise SetMembershipError("the separate tag proof is withdrawn; use verify_tagged")
        # A proof carrying a tag came from the withdrawn construction. Accepting it
        # here would let a ledger take a signature whose linkability was never checked.
        return proof.tag_proof is None
        if tag_keys is not None:
            if proof.tag_proof is None:
                return False
            if not tagmod.verify_tag(
                tag_keys,
                proof.tag_proof,
                proof.challenge_prime,
                proof.response_prime,
                _tag_context(proof.challenge_prime, proof.commitment[0], sm),
                sm,
            ):
                return False
        return True
    except (TypeError, ValueError, KeyError, IndexError):
        return False
