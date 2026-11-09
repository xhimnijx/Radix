//! Candidate-B lattice arithmetic, ported from the Python reference.
//!
//! Scope is deliberately the *arithmetic layer*: the ring `Z_q[X]/(X^128+1)`, the
//! 32 quartic slots, the CRT glue, multiplication and the norms. The proof itself
//! stays in Python until this layer is measured, because the question this port
//! exists to answer is "how fast is a multiplication" -- whether the protocol works
//! is already answered.
//!
//! Everything is exact integer arithmetic. `q < 2^32`, so a product of two
//! residues fits in `u64` and the CRT accumulation uses `u128`.

pub mod sample;
pub mod verifier;
pub mod proof;
pub mod statement;
pub mod recursion;
pub mod tensor;
pub mod quadratic;
pub mod bdlop;
pub mod codec;
pub mod sha3;
pub mod transcript;

use std::sync::OnceLock;

// ---------------------------------------------------------------- parameters

/// `q = 1 mod 64`, `q != 1 mod 128`: 32 irreducible quartic factors.
pub const Q: u64 = 4_294_966_337;
pub const D: usize = 128;
pub const L: usize = 32;
pub const K: usize = 4;
pub const ELL: usize = 13;
pub const SLOT_DEGREE: usize = 4;
pub const SLOTS: usize = D / SLOT_DEGREE;

pub type Poly = [u64; D];
pub type Quartic = [u64; SLOT_DEGREE];

// ---------------------------------------------------------------- mod arithmetic

#[inline]
fn add_mod(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= Q {
        sum - Q
    } else {
        sum
    }
}

#[inline]
fn sub_mod(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

/// `floor(2^64 / q)`, for Barrett reduction.
const BARRETT_MU: u128 = (1u128 << 64) / Q as u128;

/// Multiplication modulo `q` without division.
///
/// The first version used `% Q` on a `u128`, and a 64-bit division costs more than
/// the multiplication itself: the CRT path does ~13,000 of them per ring product,
/// which made it three times slower than the naive convolution it is meant to
/// replace. Barrett reduction turns each into two multiplies and a conditional
/// subtraction.
#[inline]
fn mul_mod(a: u64, b: u64) -> u64 {
    let product = a as u128 * b as u128;
    // q_est = floor(product / q), exact to within one.
    let quotient = ((product * BARRETT_MU) >> 64) as u64;
    let mut remainder = (product - quotient as u128 * Q as u128) as u64;
    if remainder >= Q {
        remainder -= Q;
    }
    remainder
}

fn pow_mod(mut base: u64, mut exponent: u64) -> u64 {
    let mut result = 1u64;
    base %= Q;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = mul_mod(result, base);
        }
        base = mul_mod(base, base);
        exponent >>= 1;
    }
    result
}

// ---------------------------------------------------------------- the ring

pub fn zero() -> Poly {
    [0u64; D]
}

pub fn add(left: &Poly, right: &Poly) -> Poly {
    let mut out = [0u64; D];
    for index in 0..D {
        out[index] = add_mod(left[index], right[index]);
    }
    out
}

pub fn sub(left: &Poly, right: &Poly) -> Poly {
    let mut out = [0u64; D];
    for index in 0..D {
        out[index] = sub_mod(left[index], right[index]);
    }
    out
}

/// The O(d^2) reference implementation: correct by construction.
/// Map a ternary challenge (-1/0/1) to its ring representation.
pub fn lift_challenge(challenge: &[i64; D]) -> Poly {
    let mut out = [0u64; D];
    for (index, value) in challenge.iter().enumerate() {
        out[index] = match *value {
            -1 => Q - 1,
            0 => 0,
            1 => 1,
            other => (other as i128).rem_euclid(Q as i128) as u64,
        };
    }
    out
}

pub fn scalar(value: u64, poly: &Poly) -> Poly {
    let mut out = [0u64; D];
    for index in 0..D {
        out[index] = (value as u128 * poly[index] as u128 % Q as u128) as u64;
    }
    out
}

pub fn mul_naive(left: &Poly, right: &Poly) -> Poly {
    // Signed accumulation: `X^D = -1`, so wrapped terms are subtracted.
    let mut accumulator = [0i128; D];
    for i in 0..D {
        if left[i] == 0 {
            continue;
        }
        for j in 0..D {
            if right[j] == 0 {
                continue;
            }
            let product = left[i] as i128 * right[j] as i128;
            let index = i + j;
            if index < D {
                accumulator[index] += product;
            } else {
                accumulator[index - D] -= product;
            }
        }
    }
    let q = Q as i128;
    let mut out = [0u64; D];
    for index in 0..D {
        out[index] = (((accumulator[index] % q) + q) % q) as u64;
    }
    out
}

/// Signed representative in `(-q/2, q/2]`.
pub fn centered(value: u64) -> i64 {
    if value <= Q / 2 {
        value as i64
    } else {
        value as i64 - Q as i64
    }
}

pub fn l2_squared(poly: &Poly) -> u128 {
    poly.iter().map(|&c| {
        let v = centered(c);
        (v * v) as u128
    }).sum()
}

pub fn norm_inf(poly: &Poly) -> i64 {
    poly.iter().map(|&c| centered(c).abs()).max().unwrap_or(0)
}

// ---------------------------------------------------------------- quartic slots

/// A primitive 64th root of unity: `r_i = eta^(2i+1)` are the 32 roots of
/// `Y^32 = -1`, and `X^4 - r_i` are the irreducible factors of `X^128 + 1`.
fn find_eta() -> u64 {
    let exponent = (Q - 1) / 64;
    for base in 2u64..4096 {
        let candidate = pow_mod(base, exponent);
        if pow_mod(candidate, 32) == Q - 1 {
            return candidate;
        }
    }
    panic!("no element of order 64");
}

pub fn roots() -> &'static [u64; SLOTS] {
    static ROOTS: OnceLock<[u64; SLOTS]> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let eta = find_eta();
        let mut table = [0u64; SLOTS];
        for index in 0..SLOTS {
            table[index] = pow_mod(eta, 2 * index as u64 + 1);
        }
        table
    })
}

/// `y mod (X^4 - r_index)`, by Horner in the block structure.
pub fn slot(poly: &Poly, index: usize) -> Quartic {
    // Accumulate in u128 and reduce once per residue: 32 blocks of products each
    // below 2^64 sum to below 2^69. Reducing per coefficient instead cost 128
    // Barrett reductions per slot, which dominated the whole multiplication.
    let r = roots()[index];
    let mut accumulator = [0u128; SLOT_DEGREE];
    let mut power = 1u64;
    for block in 0..SLOTS {
        let base = block * SLOT_DEGREE;
        let scale = power as u128;
        for offset in 0..SLOT_DEGREE {
            accumulator[offset] += scale * poly[base + offset] as u128;
        }
        power = mul_mod(power, r);
    }
    let mut residue = [0u64; SLOT_DEGREE];
    for offset in 0..SLOT_DEGREE {
        residue[offset] = (accumulator[offset] % Q as u128) as u64;
    }
    residue
}

pub fn slots(poly: &Poly) -> [Quartic; SLOTS] {
    let mut out = [[0u64; SLOT_DEGREE]; SLOTS];
    for index in 0..SLOTS {
        out[index] = slot(poly, index);
    }
    out
}

/// The 32 CRT idempotents: `e_i` is 1 in its own slot and 0 in the others.
pub fn crt_idempotents() -> &'static [Poly; SLOTS] {
    static IDEMPOTENTS: OnceLock<[Poly; SLOTS]> = OnceLock::new();
    IDEMPOTENTS.get_or_init(|| {
        let inverse = pow_mod(SLOTS as u64, Q - 2); // 32^-1
        let mut all = [[0u64; D]; SLOTS];
        for index in 0..SLOTS {
            let r_inverse = pow_mod(roots()[index], Q - 2);
            let mut power = 1u64;
            for t in 0..SLOTS {
                all[index][SLOT_DEGREE * t] = mul_mod(power, inverse);
                power = mul_mod(power, r_inverse);
            }
        }
        all
    })
}

pub fn glue_crt(residues: &[Quartic; SLOTS]) -> Poly {
    let idempotents = crt_idempotents();
    let mut out = [0u64; D];
    let mut accumulator = [0u128; D];
    for index in 0..SLOTS {
        let residue = &residues[index];
        let e = &idempotents[index];
        for base in (0..D).step_by(SLOT_DEGREE) {
            let e_value = e[base] as u128;
            for offset in 0..SLOT_DEGREE {
                accumulator[base + offset] += residue[offset] as u128 * e_value;
            }
        }
    }
    for index in 0..D {
        out[index] = (accumulator[index] % Q as u128) as u64;
    }
    out
}

/// Product in `Z_q[X]/(X^4 - r)`.
pub fn quartic_multiply(left: &Quartic, right: &Quartic, r: u64) -> Quartic {
    let mut product = [0u128; 2 * SLOT_DEGREE - 1];
    for i in 0..SLOT_DEGREE {
        for j in 0..SLOT_DEGREE {
            product[i + j] += left[i] as u128 * right[j] as u128;
        }
    }
    let mut folded = [0u64; SLOT_DEGREE];
    for i in 0..SLOT_DEGREE {
        folded[i] = (product[i] % Q as u128) as u64;
    }
    for i in SLOT_DEGREE..product.len() {
        let value = (product[i] % Q as u128) as u64;
        folded[i - SLOT_DEGREE] = add_mod(folded[i - SLOT_DEGREE], mul_mod(r, value));
    }
    folded
}

/// Multiplication through the quartic CRT -- the path the irreducible `q` needs.
pub fn mul_crt(left: &Poly, right: &Poly) -> Poly {
    let left_slots = slots(left);
    let right_slots = slots(right);
    let table = roots();
    let mut product = [[0u64; SLOT_DEGREE]; SLOTS];
    for index in 0..SLOTS {
        product[index] = quartic_multiply(&left_slots[index], &right_slots[index], table[index]);
    }
    glue_crt(&product)
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random polynomials, so tests are reproducible.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0
        }
        fn poly(&mut self) -> Poly {
            let mut out = [0u64; D];
            for value in out.iter_mut() {
                *value = self.next() % Q;
            }
            out
        }
    }

    #[test]
    fn the_modulus_has_no_256th_root() {
        // q - 1 = 2^6 * odd, so there is no 2d-th root of unity for d = 128.
        assert_eq!((Q - 1) % 128, 64);
        assert_eq!((Q - 1) % 64, 0);
    }

    #[test]
    fn roots_are_the_32_roots_of_minus_one() {
        let table = roots();
        let mut seen = std::collections::HashSet::new();
        for &r in table.iter() {
            assert_eq!(pow_mod(r, 32), Q - 1, "r^32 must be -1");
            assert!(seen.insert(r), "roots must be distinct");
        }
        assert_eq!(seen.len(), SLOTS);
    }

    #[test]
    fn slots_and_glue_are_inverse() {
        let mut rng = Lcg(7);
        for _ in 0..3 {
            let poly = rng.poly();
            assert_eq!(glue_crt(&slots(&poly)), poly);
        }
    }

    #[test]
    fn crt_multiplication_matches_the_naive_convolution() {
        let mut rng = Lcg(11);
        for _ in 0..3 {
            let left = rng.poly();
            let right = rng.poly();
            assert_eq!(mul_crt(&left, &right), mul_naive(&left, &right));
        }
    }

    #[test]
    fn idempotents_select_their_slot() {
        let idempotents = crt_idempotents();
        for index in [0usize, 1, 17, 31] {
            assert_eq!(slot(&idempotents[index], index), [1, 0, 0, 0]);
            for other in 0..SLOTS {
                if other != index {
                    assert_eq!(slot(&idempotents[index], other), [0, 0, 0, 0]);
                }
            }
        }
    }

    #[test]
    fn norms_are_signed() {
        let mut poly = zero();
        poly[0] = Q - 1; // -1
        assert_eq!(centered(poly[0]), -1);
        assert_eq!(l2_squared(&poly), 1);
        assert_eq!(norm_inf(&poly), 1);
    }
}
