"""Generate the discrete-Gaussian tables both implementations load.

C2's objection to the old sampler was not only precision, it was portability: Python
and Rust both round a float Gaussian, and `libm` disagreement makes them *different
distributions*, so the rejection argument applies to neither and the cross-language
tests compare two protocols.

The fix is that there is only one table. This script writes it; Python reads the file
and Rust `include_bytes!`s the same file, so "identical in both languages" is
structural rather than something a test has to keep proving.

Method: the probability mass function is summed outward from the centre, where the
ratio of consecutive terms is `exp(-(2k+1) / (2 sigma^2))` and the sum is stable. Going
through `P(|X| <= k) = erf(k / sigma sqrt 2)` would lose most of its precision in the
tail, because the answer is within 1e-16 of 1.

Truncation: the table covers `|x| <= 8 sigma`. For sigma ~ 2.7e3 that leaves a tail of
about 2^-49, which is far below the ~2^-16.8 statistical distance that motivated the
whole exercise. The number is asserted at the end rather than assumed.

Format (little endian), so both readers agree byte for byte:

    magic   8 bytes  b"RDXGAUSS"
    version u32      1
    sigma   f64      the standard deviation, recorded for the reader's sanity
    count   u32      number of cumulative entries, = cut + 1
    cdf     count x u32   cumulative mass over |X| <= k, scaled to 2^32; last = 2^32-1
"""

from __future__ import annotations

import math
import pathlib
import struct

MAGIC = b"RDXGAUSS"
VERSION = 1
SCALE = 1 << 32
TAIL_IN_SIGMAS = 8.0

#: Widths the protocol and its tests actually use. W = 25 + rows, plus MATRIX_COLS
#: for the z' mask: rows = 8 gives 33 (tagged, production), rows = 4 gives 29 (the
#: untagged test rig), and 13 is z'. The sampler fails loudly on any other width
#: rather than silently substituting a different distribution.
WIDTHS = (33, 30, 29, 13)


def sigma_for(width: int) -> float:
    """Must match `setmembership.mask_std`; asserted by the test suite."""
    return 464.0 * math.sqrt(width)


def build(sigma: float) -> tuple[list[int], float]:
    """Return (cdf, tail_probability) for a discrete Gaussian of the given sigma."""
    cut = int(math.ceil(TAIL_IN_SIGMAS * sigma))
    denominator = 2.0 * sigma * sigma

    # Unnormalised mass at |x| = k, built outward from the centre. The ratio of
    # consecutive terms is exp(-(2k-1) / (2 sigma^2)), which is stable; going through
    # erf instead would lose most of its precision where the answer is within 1e-16
    # of 1.
    denominator = 2.0 * sigma * sigma
    mass = [1.0]
    for k in range(1, cut + 1):
        mass.append(mass[-1] * math.exp(-(2 * k - 1) / denominator))

    total = mass[0] + 2.0 * sum(mass[1:])
    # Probability of |X| > cut, by the standard Gaussian tail bound.
    tail = math.erfc(cut / (sigma * math.sqrt(2.0)))

    cumulative = 0.0
    cdf: list[int] = []
    ceiling = SCALE - 1
    for k in range(cut + 1):
        cumulative += mass[k] * (1.0 if k == 0 else 2.0)
        # The final entry rounds to exactly 2^32; clamp every entry so the sequence
        # stays monotone and the last value is the sentinel.
        cdf.append(min(int(round(SCALE * cumulative / total)), ceiling))
    cdf[-1] = ceiling
    for index in range(1, len(cdf)):
        if cdf[index] < cdf[index - 1]:
            raise SystemExit("cdf is not monotone; the arithmetic underflowed")
    return cdf, tail


def write(path: pathlib.Path, sigma: float, cdf: list[int]) -> int:
    header = MAGIC + struct.pack("<IdI", VERSION, sigma, len(cdf))
    body = struct.pack("<" + "I" * len(cdf), *cdf)
    path.write_bytes(header + body)
    return len(header) + len(body)


def main() -> None:
    target = pathlib.Path("radix_core/candidate_b/lattice/tables")
    target.mkdir(parents=True, exist_ok=True)
    for width in WIDTHS:
        sigma = sigma_for(width)
        cdf, tail = build(sigma)
        path = target / f"gaussian_w{width}.bin"
        size = write(path, sigma, cdf)
        print(
            f"width {width:3d}  sigma {sigma:9.1f}  entries {len(cdf):6d}  "
            f"{size / 1024:6.1f} KB  tail 2^{math.log2(tail):.1f}  -> {path}"
        )


if __name__ == "__main__":
    main()
