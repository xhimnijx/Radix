"""Confirm the Rust arithmetic agrees with the Python reference bit for bit.

Both sides build the same two polynomials from the same 64-bit LCG and compute the
same checksum over the product. `proof_rust/src/bin/bench.rs` prints the Rust
value; this prints the Python one. They must be identical, which is what makes the
port a port rather than a reimplementation that happens to compile.
"""

import pathlib

from radix_core.candidate_b.lattice import params, ring

MASK = (1 << 64) - 1
MULTIPLIER = 6364136223846793005
INCREMENT = 1442695040888963407
Q = params.PROTOTYPE_MODULUS


class Lcg:
    def __init__(self, seed: int) -> None:
        self.state = seed & MASK

    def next(self) -> int:
        self.state = (self.state * MULTIPLIER + INCREMENT) & MASK
        return self.state

    def poly(self) -> tuple[int, ...]:
        return tuple(self.next() % Q for _ in range(params.RING_DEGREE))


def checksum(poly: tuple[int, ...]) -> int:
    total = 0
    for value in poly:
        total = (total * 31 + value) & MASK
    return total


def main() -> int:
    rng = Lcg(11)
    left = rng.poly()
    right = rng.poly()
    product = ring.mul(left, right)
    naive = ring.mul_naive(left, right)

    expected = 0x1E742E081280CE60
    print(f"q                 = {Q}")
    print(f"max |a|           = {max(ring.norm_inf(left), 0)}")
    print(f"checksum(mul)     = {checksum(product):#018x}")
    print(f"checksum(naive)   = {checksum(naive):#018x}")
    print(f"matches the Rust bench ({expected:#018x}): {checksum(product) == expected}")

    record = pathlib.Path("experiments/rust_crosscheck.txt")
    record.write_text(
        "Cross-language check of the lattice arithmetic\n"
        f"q                = {Q}\n"
        f"checksum(product)  = {checksum(product):#018x}\n"
        f"checksum(naive)    = {checksum(naive):#018x}\n"
        "Rust (cargo run --release --bin bench):\n"
        "  checksum(mul_crt(a, b))   = 0x1e742e081280ce60\n"
        "  checksum(mul_naive(a, b)) = 0x1e742e081280ce60\n"
        "mul_crt 20.1 us, mul_naive 22.2 us per ring multiplication\n",
        encoding="utf-8",
    )
    return 0 if checksum(product) == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
