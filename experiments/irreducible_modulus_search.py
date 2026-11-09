"""Candidate moduli for C1's irreducible-quartic recommendation.

C1: keep the split modulus and soundness is capped at ~24 bits, because the
extractor needs `c - c~` invertible and the difference of two units can still be a
zero divisor. With an irreducible-quartic `q`, a nonzero quartic difference is a
unit of a field, and the challenge difference is a unit with probability `1 - q^-4`.

The arithmetic behind the criterion, which this script checks rather than assumes:

* `X^128 + 1` is the 256th cyclotomic polynomial;
* over `F_q` its irreducible factors all have degree `ord_256(q)`;
* so the factors are quartics exactly when `ord_256(q) = 4`, which happens iff
  `q = 1 mod 64` and `q != 1 mod 128`;
* such a `q` has no 128th or 256th root of unity, so the full 128-point NTT does
  not exist -- hence the quartic-CRT multiplier C1 describes.

This finds candidates. It does not claim any of them is a good parameter: the
M-LWE and M-SIS estimates have to be re-derived for whichever `q` is chosen.
"""

from math import gcd

TARGET = 1 << 32
WANTED = 5


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def order_mod_256(q: int) -> int:
    value = q % 256
    power = 1
    for exponent in range(1, 257):
        power = power * value % 256
        if power == 1:
            return exponent
    return 0


def main() -> int:
    found = []
    q = TARGET - 1
    while q > TARGET - 200_000 and len(found) < WANTED:
        if q % 64 == 1 and q % 128 != 1 and is_prime(q):
            order = order_mod_256(q)
            found.append((q, order, gcd(q - 1, 256)))
        q -= 1

    print(f"{'q':>12}  {'q-2^32':>8}  {'ord_256(q)':>10}  {'gcd(q-1,256)':>12}  quartic factors?")
    for value, order, g in found:
        print(f"{value:>12}  {value - TARGET:>8}  {order:>10}  {g:>12}  {'yes' if order == 4 else 'NO'}")
    print()
    print("for comparison, the prototype:")
    print(f"{4294962689:>12}  {4294962689 - TARGET:>8}  {order_mod_256(4294962689):>10}  "
          f"{gcd(4294962688, 256):>12}  "
          f"{'yes' if order_mod_256(4294962689) == 4 else 'NO (splits into linear factors)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
