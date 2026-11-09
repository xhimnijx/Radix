"""The two implementations sample the same discrete Gaussian.

This is the test C2's objection demands. Checking that Rust accepts a Python proof and
vice versa does **not** establish it: two different distributions both produce proofs
that verify, because verification only checks the algebra. What has to be compared is
the *sampler*.

`from_uniform(width, uniform, sign)` is a pure function in both languages — no RNG, no
floating point — so the comparison is exact rather than statistical. The Rust binary
prints the mapping over a fixed grid (the boundaries, the centre, and 128 spread
values); this test recomputes it and requires agreement on every row.
"""

import shutil
import subprocess

import pytest

from radix_core.candidate_b.lattice import gaussian as G


def _binary():
    """The dump binary, if it has been built."""
    root = __import__("pathlib").Path(__file__).resolve().parent.parent
    for name in ("gauss_dump.exe", "gauss_dump"):
        candidate = root / "proof_rust" / "target" / "release" / name
        if candidate.exists():
            return candidate
    return None


def test_from_uniform_matches_the_rust_implementation():
    binary = _binary()
    if binary is None:
        pytest.skip("proof_rust is not built; run cargo build --release --bin gauss_dump")

    result = subprocess.run(
        [str(binary)], capture_output=True, text=True, timeout=120, check=False
    )
    assert result.returncode == 0, result.stderr

    rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
    assert len(rows) == 3 * 140, f"expected 420 rows, got {len(rows)}"

    for width, uniform, positive, negative in rows:
        width = int(width)
        uniform = int(uniform)
        assert G.from_uniform(width, uniform, 0) == int(positive), (
            f"width {width}, uniform {uniform}: python says "
            f"{G.from_uniform(width, uniform, 0)}, rust says {positive}"
        )
        assert G.from_uniform(width, uniform, 1) == int(negative)


def test_the_tables_are_the_ones_the_code_uses():
    """A table for the wrong sigma would still be a valid table."""
    from radix_core.candidate_b.lattice import setmembership as S

    for width in (33, 29):
        recorded = G.sigma(width)
        expected = S.mask_std(width)
        assert abs(recorded - expected) < 1e-6, (
            f"table for width {width} is sigma {recorded}, but mask_std says {expected}"
        )


def test_the_truncation_is_negligible():
    """8 sigma leaves a tail of about 2^-49.5; state it rather than assume it."""
    import math

    for width in (33, 29, 13):
        sigma = G.sigma(width)
        cut = G.max_magnitude(width)
        assert cut == int(math.ceil(8.0 * sigma))
        tail = math.erfc(cut / (sigma * math.sqrt(2.0)))
        assert tail < 2 ** -40, f"width {width} tail is 2^{math.log2(tail):.1f}"
