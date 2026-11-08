"""SMILE parameter manifest (B1).

Values are transcribed from the SMILE full version
(`studies/2021-564.pdf`, ePrint 2021/564), with page/figure references, because a
lattice scheme is meaningless without them and guessing is unsafe.

Source facts:
* p. 48, Fig. 11: ``n, m, µ, k, ℓ, κ, λ`` with ``µ=5, k=4, ℓ=13, κ=10, λ=10`` and
  proof sizes 15.96-21.53 KB for rings of 2^5..2^25.
* p. 48, caption: "For all parameter sets, we choose (q, d, l) = (≈2^32, 128, 32)".
* p. 9, Fig. 2: ring-signature sizes 16-22 KB at ~128-bit security.
* p. 12, Fig. 3: (2,2)-account transaction proof 24-36 KB for rings 2^5..2^25;
  (1,2) 22-28 KB.

The modulus is only specified to ~2^32 in the paper, so this prototype fixes an
exact NTT-friendly prime of that size and records the deviation. Ring arithmetic
and the BDLOP commitment are implemented against it; no security claim is made
for the prototype modulus until a reviewer pins the exact SMILE parameters.
"""

from __future__ import annotations

from dataclasses import dataclass

#: 32-bit, prime, q == 1 mod 256. Chosen so a 2d-th root of unity exists for
#: d=128 if NTT is added later. NOT yet verified to be the paper's modulus.
PROTOTYPE_MODULUS = 4294962689
MODULUS_FROM_PAPER = False

RING_DEGREE = 128
SUBRING_DIMENSION = 32
MATRIX_ROWS = 4          # k
MATRIX_COLS = 13         # ell
CHALLENGE_DIM = 10       # kappa
MASKING_DIM = 10         # lambda
SECRET_BOUND = 5         # mu
SECURITY_BITS = 128      # paper's target (Section "parameters")


@dataclass(frozen=True)
class SmileParameters:
    """The (q, d, l, k, ell, kappa, lambda, mu) manifest with provenance."""

    modulus: int = PROTOTYPE_MODULUS
    ring_degree: int = RING_DEGREE
    subring_dimension: int = SUBRING_DIMENSION
    matrix_rows: int = MATRIX_ROWS
    matrix_cols: int = MATRIX_COLS
    challenge_dim: int = CHALLENGE_DIM
    masking_dim: int = MASKING_DIM
    secret_bound: int = SECRET_BOUND

    def __post_init__(self) -> None:
        if self.ring_degree & (self.ring_degree - 1):
            raise ValueError("ring degree must be a power of two")
        if self.ring_degree % self.subring_dimension:
            raise ValueError("subring dimension must divide the ring degree")
        for name in (
            "matrix_rows",
            "matrix_cols",
            "challenge_dim",
            "masking_dim",
            "secret_bound",
        ):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be positive")
        if not 2 <= self.modulus < (1 << self.ring_degree.bit_length() + 32):
            raise ValueError("modulus is out of the expected range")

    @property
    def ntt_capacity(self) -> int:
        """Largest power of two dividing q-1 (upper bound on NTT length)."""
        value = self.modulus - 1
        power = 0
        while value % 2 == 0:
            value //= 2
            power += 1
        return 1 << power

    @property
    def full_element_bytes(self) -> int:
        return self.ring_degree * 4

    def ring_signature_size_bytes(self, ring_size: int, m: int = 1) -> int:
        """Paper-style estimate: (kappa + k + 2m + 2) full R_q elements."""
        elements = self.challenge_dim + self.matrix_rows + 2 * m + 2
        return elements * self.full_element_bytes


SMILE = SmileParameters()

#: Ring signature sizes reported by the paper (Fig. 11, p. 48), in KB.
PAPER_RING_SIGNATURE_KB = {
    1 << 5: 15.96,
    1 << 10: 17.27,
    1 << 15: 18.73,
    1 << 20: 20.15,
    1 << 25: 21.53,
}

#: Transaction proof sizes (Fig. 3, p. 12), KB, for (M, S) input/output accounts.
PAPER_TRANSACTION_KB = {
    (2, 2): {1 << 5: 24, 1 << 10: 27, 1 << 15: 30, 1 << 20: 33, 1 << 25: 36},
    (1, 2): {1 << 5: 22, 1 << 10: 24, 1 << 15: 25, 1 << 20: 27, 1 << 25: 28},
}


def estimate_ring_signature_kb(ring_size: int) -> float:
    """Interpolate the paper's Fig. 11 table in log2(ring size)."""
    if ring_size < 1:
        raise ValueError("ring size must be positive")
    points = sorted(PAPER_RING_SIGNATURE_KB.items())
    if ring_size <= points[0][0]:
        return points[0][1]
    for (low_n, low_kb), (high_n, high_kb) in zip(points, points[1:]):
        if low_n <= ring_size <= high_n:
            span = high_n.bit_length() - low_n.bit_length()
            position = (ring_size.bit_length() - 1) - (low_n.bit_length() - 1)
            return low_kb + (high_kb - low_kb) * position / span
    return points[-1][1]
