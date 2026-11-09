"""The modulus criterion, verified: ord_256 decides slot-constancy.

C2's correction to the earlier probe: the decisive quantity is `ord_256(q)`, the
multiplicative order of `q` modulo 256, because `X^128 + 1 = Phi_256` and its
irreducible factors over `F_q` all have degree `ord_256(q)`. The "is r_i a fourth
power" proxy cannot separate ord = 2 from ord = 4; the non-square test separates
{1, 2} from {4} but not 1 from 2.

Relations, with `m = (q - 1) / 64` and `eta` a 64th root of unity:

    r_i       = eta^(2i+1)                   (the 32 roots of Y^32 = -1)
    r_i^((q-1)/2) = (-1)^m                   (square iff m even, i.e. 128 | q-1)
    factors of Phi_256 over F_q: 128 / ord_256(q) of degree ord_256(q)

    ord = 1  -> 128 linears    M_q = Z_q^128      16 idempotents/slot   slot-constancy FAILS
    ord = 2  ->  64 quadratics M_q = (F_q^2)^32    4 idempotents/slot   slot-constancy FAILS
    ord = 4  ->  32 quartics   M_q = (F_q^4)^32    2 idempotents/slot   slot-constancy HOLDS

This script finds a prime for each row and checks the classification directly.
"""

from math import gcd


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


def valuation_two(n: int) -> int:
    v = 0
    while n % 2 == 0:
        n //= 2
        v += 1
    return v


def order_mod_256(q: int) -> int:
    value, power = q % 256, 1
    for exponent in range(1, 257):
        power = power * value % 256
        if power == 1:
            return exponent
    return 0


def primitive_root_of_order(q: int, order: int):
    if (q - 1) % order:
        return None
    for base in range(2, 400):
        candidate = pow(base, (q - 1) // order, q)
        if pow(candidate, order, q) == 1 and pow(candidate, order // 2, q) != 1:
            return candidate
    return None


def classify(q: int) -> dict:
    order = order_mod_256(q)
    v2 = valuation_two(q - 1)
    eta = primitive_root_of_order(q, 64)
    row = {
        "q": q,
        "prime": is_prime(q),
        "v2": v2,
        "q mod 128": q % 128,
        "ord_256": order,
        "eta": eta is not None,
        "degree": order if order in (1, 2, 4) else None,
    }
    if eta is None:
        return row
    roots = [pow(eta, 2 * i + 1, q) for i in range(32)]
    row["distinct"] = len(set(roots)) == 32
    row["root_of_-1"] = all(pow(r, 32, q) == q - 1 for r in roots)
    # r is a square iff r^((q-1)/2) == 1; equals (-1)^((q-1)/64)
    row["squares"] = sum(1 for r in roots if pow(r, (q - 1) // 2, q) == 1)
    row["predicted"] = (-1) ** ((q - 1) // 64) == 1
    return row


def find(v2_wanted: int, limit: int = 400_000) -> int:
    q = (1 << 32) - 1
    while q > (1 << 32) - limit:
        if q % 64 == 1 and valuation_two(q - 1) == v2_wanted and is_prime(q):
            return q
        q -= 1
    return 0


TABLE = {
    1: "128 linears, Z_q^128, 16 idempotents/slot -> slot-constancy FAILS",
    2: "64 quadratics, (F_q^2)^32, 4 idempotents/slot -> slot-constancy FAILS",
    4: "32 quartics, (F_q^4)^32, 2 idempotents/slot -> slot-constancy HOLDS",
}

print(f"{'q':>12}  {'v2':>3}  {'q%128':>6}  {'ord':>4}  {'degree':>6}  {'r_i squares':>12}  {'matches (-1)^m':>14}  verdict")
for v2_wanted in (9, 7, 6):
    q = find(v2_wanted)
    row = classify(q)
    ok = row.get("squares") in (0, 32) and row["predicted"] == (row.get("squares") == 32)
    print(
        f"{row['q']:>12}  {row['v2']:>3}  {row['q mod 128']:>6}  {row['ord_256']:>4}  "
        f"{row.get('degree'):>6}  {row.get('squares'):>12}  {str(ok):>14}  "
        f"{TABLE.get(row['ord_256'], 'unexpected')}"
    )

print()
print("The prototype 4,294,962,689 sits in the v2 = 9 row: ord_256 = 1, r_i are squares,")
print("and the slots are Z_q^4, so v(v-1) = 0 leaves an arbitrary 128-bit idempotent.")
