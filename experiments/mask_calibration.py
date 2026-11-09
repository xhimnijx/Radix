"""Calibrate the masking width, and check C1's numbers.

C1: the irreducible-quartic q changes the CRT basis, not the ring multiplication,
so the time-domain coefficient vector of `c r` is the same negacyclic convolution
and the rejection rate `M` is unchanged. Calibrate `T = ||c r||_2` on the
coefficient vector, exactly as for the split modulus.

Their numbers: for c ternary with P(0) = 1/2, P(+-1) = 1/4 and r uniform on
[-5, 5], each coefficient of `c r` has variance 128 * E[c^2] * E[r^2]
= 128 * (1/2) * 10 = 640, so sigma ~ 25.3; the 99th percentile over W = 33
components is T ~ 1.7k and over ell = 13 components T' ~ 1.1k. The paper's
M = sqrt(3/2) then corresponds to s ~ 1.57 T, i.e. s ~ 2^10.5.

This measures all of it, because a rejection-sampling parameter that has been
guessed is a security parameter that has been guessed. It also records the trap:
the quartic-CRT multiplier must return to the coefficient basis before the norm
check, since the CRT is not an isometry.
"""

import math
import random
import statistics

from radix_core.candidate_b.lattice import params, ring

P_ = params.SMILE
D = P_.ring_degree
WIDTH = 33   # tagged W at k' = 4
ELL = P_.matrix_cols
SAMPLES = 300


def ternary(rng):
    return tuple(0 if (x := rng.random()) < 0.5 else (1 if x < 0.75 else -1) for _ in range(D))


def uniform_secret(rng):
    return tuple(rng.randint(-5, 5) for _ in range(D))


def norm(components):
    """Squared l2 norm of the concatenated coefficient vector."""
    total = 0
    for poly in components:
        total += sum(ring.centered(c, P_) ** 2 for c in poly)
    return math.isqrt(total)


def sample_norm(rng, width):
    return norm(
        tuple(ring.mul(ternary(rng), uniform_secret(rng), P_) for _ in range(width))
    )


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


def main() -> int:
    rng = random.Random(2026)

    # One coefficient's variance, to check the model C1 used.
    single = []
    for _ in range(2000):
        product = ring.mul(ternary(rng), uniform_secret(rng), P_)
        single.append(ring.centered(product[0], P_))
    print(f"coefficient variance: measured {statistics.pvariance(single):.0f}, "
          f"model 128 * E[c^2] * E[r^2] = {128 * 0.5 * 10:.0f}, "
          f"sigma = {math.sqrt(statistics.pvariance(single)):.1f}")

    for name, width in (("z  (W = 33)", WIDTH), ("z' (ell = 13)", ELL)):
        values = [sample_norm(rng, width) for _ in range(SAMPLES)]
        t99 = percentile(values, 0.99)
        print(f"\n{name}: median {statistics.median(values):.0f}, "
              f"99th percentile {t99:.0f} (2^{math.log2(t99):.1f})")
        print(f"{'s':>8}  {'2^':>5}  {'M = exp(T^2/2s^2)':>18}  {'2M^2':>7}")
        for exponent in range(10, 15):
            for power in (0.0, 0.5):
                s = 2 ** (exponent + power)
                m = math.exp(t99**2 / (2 * s * s))
                if m > 1e3 or m < 1.0:
                    continue
                print(f"{s:>8.0f}  2^{exponent + power:>4.1f}  {m:>18.3f}  {2 * m * m:>7.2f}")
        target = math.sqrt(1.5)  # the paper's M
        s_for_target = math.sqrt(t99**2 / (2 * math.log(target)))
        print(f"paper's M = sqrt(3/2) = {target:.3f} is reached at s = {s_for_target:.0f} "
              f"(2^{math.log2(s_for_target):.1f}), i.e. {s_for_target / t99:.2f} * T")

    # Recommended parameters, from the measured T rather than from a guess.
    print("\nRecommended parameters at M = sqrt(3/2):")
    print(f"{'':>6}  {'T':>6}  {'s = 1.57 T':>11}  {'beta':>10}  {'target':>9}  {'reachable':>10}  {'margin':>7}")
    for name, width, factor, reachable_bits, target_factor in (
        ("z ", WIDTH, math.sqrt(2 * WIDTH * D), 31.7, 8 * D),
        ("z'", ELL, math.sqrt(2 * ELL * D), 21.2, 2.0),
    ):
        _, t99 = None, percentile([sample_norm(rng, width) for _ in range(60)], 0.99)
        s = math.sqrt(t99**2 / (2 * math.log(math.sqrt(1.5))))
        beta = s * factor
        target = target_factor * beta
        margin = reachable_bits - math.log2(target)
        print(f"{name:>6}  {t99:>6.0f}  {s:>11.0f}  {beta:>10.0f}  {target:>9.1f}  "
              f"2^{reachable_bits:<8.1f}  {margin:>5.1f} bits")
    print("reachable norms are C1's root-Hermite values at delta = 1.0042;")
    print("a lattice estimator must confirm them before any security claim.")

    print("\nReminder from C1: the quartic-CRT multiplier must glue back to the")
    print("coefficient basis before any norm or rejection check. The CRT is not an")
    print("isometry, so a norm taken in the slot basis is a different quantity.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

