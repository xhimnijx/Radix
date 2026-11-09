"""Does C1's irreducible-quartic q also close C2's slot-constant hole?

The two reviewers disagree on a load-bearing point.

C2: `v(v-1) = 0` in R_q makes v an idempotent, which is only slot-constant if
M_q = prod Z_q[X]/(X^4 - r_i) is a product of *fields*. C2 argues it never is,
"because r_i is an explicit fourth power for every valid q".

C1: choose q with ord_256(q) = 4. Then X^4 - r_i is irreducible over F_q, so
M_q *is* a product of fields, and its only idempotents are 0 and 1 -- which is
exactly slot-constancy.

This script tests which reading holds, on a candidate q and on the prototype.
"""

TARGET = 1 << 32
CANDIDATE = 4294966337   # ord_256 = 4
PROTOTYPE = 4294962689   # ord_256 = 1


def order_mod_256(q: int) -> int:
    value, power = q % 256, 1
    for exponent in range(1, 257):
        power = power * value % 256
        if power == 1:
            return exponent
    return 0


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


def primitive_root_of_order(q: int, order: int):
    """An element of multiplicative order exactly `order`, or None."""
    if (q - 1) % order:
        return None
    for base in range(2, 200):
        candidate = pow(base, (q - 1) // order, q)
        if pow(candidate, order, q) == 1 and all(
            pow(candidate, order // p, q) != 1 for p in (2,) if order % p == 0
        ):
            return candidate
    return None


def probe(q: int, name: str) -> None:
    print(f"\n=== {name}: q = {q} ===")
    print("prime:", is_prime(q), "| q mod 64:", q % 64, "| q mod 128:", q % 128,
          "| ord_256:", order_mod_256(q))

    # A 64th root exists iff 64 | q-1. Its odd powers are the roots of Y^32 = -1.
    zeta = primitive_root_of_order(q, 64)
    if zeta is None:
        print("no element of order 64: this q cannot carry the quartic factors")
        return
    print("64th root found:", zeta is not None, "| zeta^32 == q-1:", pow(zeta, 32, q) == q - 1)

    roots = [pow(zeta, 2 * i + 1, q) for i in range(32)]
    print("distinct r_i:", len(set(roots)) == 32)
    print("all satisfy r_i^32 = -1:", all(pow(r, 32, q) == q - 1 for r in roots))

    # X^4 - r has a root in F_q iff r is a fourth power.
    fourth_power_test = [pow(r, (q - 1) // 4, q) == 1 for r in roots]
    print("r_i that are fourth powers:", sum(fourth_power_test), "of 32")
    if all(fourth_power_test):
        print("=> X^4 - r_i splits completely; M_q ~ Z_q^128; idempotents are subsets")
    else:
        print("=> X^4 - r_i has no root in F_q; with ord_256 = 4 it is irreducible,")
        print("   so each slot is a FIELD and x^2 = x has only the solutions 0 and 1.")


probe(PROTOTYPE, "prototype (paper's regime)")
probe(CANDIDATE, "candidate (C1's regime)")
print("\nIf the candidate's slots are fields, then v(v-1) = 0 forces every slot")
print("residue to be 0 or 1, i.e. v is already slot-constant as a 32-scalar vector.")
print("That would close C2's hole with the same change that closes C1's.")
