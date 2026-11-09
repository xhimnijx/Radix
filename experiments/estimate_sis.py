"""Core-SVP estimates for this project's two M-SIS instances, from first principles.

Why this exists
---------------
`lattice-estimator` is the tool everyone names, and it cannot run on this machine:

    python -m pip install git+https://github.com/malb/lattice-estimator.git

installs, but `import estimator` raises `ModuleNotFoundError: No module named 'sage'`.
The estimator is written against SageMath, and SageMath does not run natively on
Windows; `fpylll` also fails to build here (`failed-wheel-build-for-install`), because
there is no C++ toolchain. WSL is not installed either. See `docs/ESTIMATOR.md` for the
exact commands and what a working machine needs.

So this script does two things instead of pretending:

1. It computes the **root-Hermite delta model** from the formulas, and asserts the
   result against the numbers already published in `REVIEW-FINDINGS.md`. That does not
   replace an estimator, but it does mean nobody has to trust our arithmetic: run this
   and check.
2. It prints the **exact SIS parameters** to paste into `lattice-estimator` on a machine
   that can run it, so the outstanding item becomes a five-minute job somewhere else
   rather than an open research question.

What the delta model is not
---------------------------
It is a sanity check, not a security proof. It assumes BKZ behaves as the geometric
series model says, ignores the practical cost of SVP calls beyond the block size, and
says nothing about the scheme's bit-security -- only about the cost of the underlying
assumption. `SECURITY-NOTES.md` says the same thing at length.
"""

from __future__ import annotations

import argparse
import math
import pathlib
import sys

# Running this file directly puts `experiments/` on sys.path, not the repository root.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from radix_core.candidate_b.lattice import params as P
from radix_core.candidate_b.lattice import setmembership as S

#: Classical and quantum Core-SVP exponents, after Alkim, Ducas, Poppelmann,
#: Schwabe (2015) and the NIST submissions.
CLASSICAL = 0.292
QUANTUM = 0.265

TWO_PI_E = 2.0 * math.pi * math.e


def delta_of_block_size(block: float) -> float:
    """The root-Hermite factor `delta(b)` in the geometric-series model."""
    return ((block / TWO_PI_E) * (math.pi * block) ** (1.0 / block)) ** (
        1.0 / (2.0 * (block - 1.0))
    )


def block_size_for(target_delta: float, low: float = 2.0, high: float = 20000.0) -> float:
    """Invert `delta_of_block_size` by bisection.

    `delta` decreases towards 1 as the block size grows, so a target delta below the
    smallest reachable value means the instance is stronger than the model can
    express; the caller distinguishes that case rather than reading a clamped number.
    """
    if target_delta <= 1.0:
        raise ValueError("a delta at or below 1 has no block size")
    for _ in range(200):
        middle = (low + high) / 2.0
        if delta_of_block_size(middle) > target_delta:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def gaussian_heuristic(dimension: int, log_det_per_coordinate: float) -> float:
    """The expected shortest vector length, as log2."""
    return (
        math.log2(math.sqrt(dimension / TWO_PI_E)) + log_det_per_coordinate
    )


def estimate(dimension: int, log_det: float, log_target: float, label: str) -> dict:
    """One instance: dimension, log2(det), log2(target norm)."""
    log_det_per_coordinate = log_det / dimension
    required_delta = 2.0 ** ((log_target - log_det_per_coordinate) / dimension)
    row = {
        "label": label,
        "dimension": dimension,
        "log_det_per_coordinate": log_det_per_coordinate,
        "target_delta": required_delta,
        "gaussian_heuristic": gaussian_heuristic(dimension, log_det_per_coordinate),
    }
    if required_delta <= 1.0:
        row["block"] = None
        row["classical"] = None
        row["quantum"] = None
        row["note"] = "target is below the Gaussian heuristic: beyond this model"
        return row
    block = block_size_for(required_delta)
    row["block"] = block
    row["classical"] = CLASSICAL * block
    row["quantum"] = QUANTUM * block
    row["note"] = ""
    return row


def instances() -> list[dict]:
    """The two relations, with the dimensions this project actually uses."""
    from radix_testnet import params as TP

    parameters = TP.parameters()
    sm = P.SMILE
    log_q = math.log2(sm.modulus)
    d = sm.ring_degree

    rows_k = len(parameters.matrix)
    columns = len(parameters.matrix[0])
    width = S.masking_width(parameters.depth, sm, rows_k + parameters.tag_rows)
    # Two different response bounds, and mixing them is what this script exists to
    # catch: relation A extracts against 2*beta' (the z' mask over MATRIX_COLS), while
    # B0 is bounded by 8*d*beta (the main mask over the full width).
    beta = math.sqrt(S._response_bound(width, sm))
    beta_prime = math.sqrt(S._response_bound(sm.matrix_cols, sm))
    log_beta = math.log2(beta)
    log_beta_prime = math.log2(beta_prime)

    rows = []
    # A: k rows, ell columns. Solution-lattice dimension ell*d, determinant q^(k*d).
    rows.append(
        estimate(
            columns * d,
            log_q * rows_k * d,
            math.log2(2.0) + log_beta_prime,
            f"A (k={rows_k}, tagged width W={width})",
        )
    )
    # B0: kappa rows, W columns, determinant q^(kappa*d).
    rows.append(
        estimate(
            width * d,
            log_q * sm.challenge_dim * d,
            math.log2(8 * d) + log_beta,
            f"B0 (W={width})",
        )
    )
    return rows


def report(rows: list[dict]) -> None:
    print(f"{'relation':38s} {'n':>5s} {'det^(1/n)':>10s} {'delta':>10s} {'block':>6s} {'classical':>10s} {'quantum':>9s}")
    for row in rows:
        block = "-" if row["block"] is None else f"{row['block']:.0f}"
        classical = "-" if row["classical"] is None else f"2^{row['classical']:.1f}"
        quantum = "-" if row["quantum"] is None else f"2^{row['quantum']:.1f}"
        print(
            f"{row['label']:38s} {row['dimension']:5d} "
            f"{'2^%.2f' % row['log_det_per_coordinate']:>10s} "
            f"{row['target_delta']:10.6f} {block:>6s} {classical:>10s} {quantum:>9s}"
            + (f"   {row['note']}" if row["note"] else "")
        )


def check(rows: list[dict]) -> None:
    """Assert against the numbers published in REVIEW-FINDINGS.md.

    If these drift, either the parameters changed or the arithmetic broke, and both
    are worth failing a build over.
    """
    by_name = {row["label"].split(" (")[0]: row for row in rows}
    expectations = [
        ("A", 1664, 158.0, 0.5),
        ("B0", 4224, 175.0, 0.5),
    ]
    failures = []
    for name, dimension, classical_bits, tolerance in expectations:
        row = by_name.get(name)
        if row is None:
            failures.append(f"{name}: not found")
            continue
        if row["dimension"] != dimension:
            failures.append(f"{name}: dimension {row['dimension']} != {dimension}")
        if row["classical"] is None or abs(row["classical"] - classical_bits) > tolerance:
            failures.append(
                f"{name}: classical {row['classical']} does not round to {classical_bits}"
            )
    if failures:
        raise SystemExit("estimates disagree with REVIEW-FINDINGS.md:\n  " + "\n  ".join(failures))
    print()
    print("check: both instances reproduce the published figures (2^158 and 2^175).")


def homework() -> None:
    """What to paste into lattice-estimator on a machine that can run it."""
    sm = P.SMILE
    from radix_testnet import params as TP

    parameters = TP.parameters()
    sm = P.SMILE
    width = S.masking_width(parameters.depth, sm, len(parameters.matrix) + parameters.tag_rows)
    beta = math.sqrt(S._response_bound(width, sm))
    print()
    print("lattice-estimator, on a machine with SageMath (Linux or macOS):")
    print()
    print("    from estimator import SIS, Q")
    print(f"    q = {sm.modulus}")
    print("    # A relation: k rows, ell columns over R_q, target 2*beta")
    print(f"    SIS(d={len(parameters.matrix)}, n={len(parameters.matrix[0])}, q=q,"
          f" m={len(parameters.matrix)}, length_bound={int(2 * beta)}, norm=2)")
    print("    # B0 relation: kappa rows, W columns, target 8*d*beta")
    print(f"    SIS(d={sm.challenge_dim}, n={width}, q=q,"
          f" m={sm.challenge_dim}, length_bound={int(8 * sm.ring_degree * beta)}, norm=2)")
    print()
    print("Both are module-SIS over R_q with d = 128, so the module dimension is")
    print("multiplied by d; pass the unrolled parameters if the tool asks.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="assert the published numbers")
    parser.add_argument("--homework", action="store_true", help="print the estimator arguments")
    arguments = parser.parse_args()

    rows = instances()
    report(rows)
    if arguments.check:
        check(rows)
    if arguments.homework:
        homework()


if __name__ == "__main__":
    main()
