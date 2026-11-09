//! Vector operations and deterministic test sampling.
//!
//! The sampling here is **not** the prover's RNG. It is a reproducible generator
//! keyed by a label, used so that the Python reference and this port can be handed
//! the identical polynomials in a test. Without it, every cross-language check
//! would need megabytes of quoted coefficients.
//!
//! Domain and layout are mirrored in `experiments/port_vectors.py`; if the two ever
//! disagree, every cross-language vector fails at once, which is the loudest
//! possible failure mode and therefore the safest.

use crate::sha3::shake256;
use crate::{mul_crt, Poly, D, Q};

pub const SAMPLE_DOMAIN: &[u8] = b"radix/port/v1";

/// A uniform polynomial derived from `label` and `counter`.
pub fn uniform_from(label: &[u8], counter: u32) -> Poly {
    let mut input = SAMPLE_DOMAIN.to_vec();
    input.extend_from_slice(&(label.len() as u32).to_le_bytes());
    input.extend_from_slice(label);
    input.extend_from_slice(&counter.to_le_bytes());

    let mut bytes = [0u8; D * 4];
    shake256(&input, &mut bytes);

    let mut poly = [0u64; D];
    for index in 0..D {
        let start = index * 4;
        let word = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]);
        poly[index] = word as u64 % Q;
    }
    poly
}

/// A vector of `count` polynomials, counters running from `first`.
pub fn vector_from(label: &[u8], count: usize, first: u32) -> Vec<Poly> {
    (0..count)
        .map(|index| uniform_from(label, first + index as u32))
        .collect()
}

/// Sum of component-wise products: `sum_i left_i * right_i`.
pub fn dot(left: &[Poly], right: &[Poly]) -> Poly {
    assert_eq!(left.len(), right.len(), "dot needs equally sized vectors");
    let mut total = [0u64; D];
    let mut first = true;
    for (a, b) in left.iter().zip(right.iter()) {
        let product = mul_crt(a, b);
        if first {
            total = product;
            first = false;
        } else {
            for index in 0..D {
                let sum = total[index] as u128 + product[index] as u128;
                total[index] = (sum % Q as u128) as u64;
            }
        }
    }
    total
}

/// Row-by-vector product: one output polynomial per matrix row.
pub fn mat_vec(matrix: &[Vec<Poly>], vector: &[Poly]) -> Vec<Poly> {
    matrix.iter().map(|row| dot(row, vector)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampling_is_deterministic_and_label_dependent() {
        assert_eq!(uniform_from(b"a", 0), uniform_from(b"a", 0));
        assert_ne!(uniform_from(b"a", 0), uniform_from(b"b", 0));
        assert_ne!(uniform_from(b"a", 0), uniform_from(b"a", 1));
    }

    #[test]
    fn every_coefficient_is_reduced() {
        let poly = uniform_from(b"range", 3);
        assert!(poly.iter().all(|&value| value < Q));
    }

    #[test]
    fn the_label_length_is_part_of_the_input() {
        // "ab" + "c" must not collide with "a" + "bc": the length prefix prevents it.
        assert_ne!(uniform_from(b"abc", 0), uniform_from(b"ab", 0));
    }

    #[test]
    fn dot_is_linear_in_its_left_argument() {
        let a = uniform_from(b"dot-a", 0);
        let b = uniform_from(b"dot-b", 0);
        let c = uniform_from(b"dot-c", 0);
        let left = dot(&[a, b], &[c, c]);
        let sum = dot(&[a], &[c]);
        let other = dot(&[b], &[c]);
        let mut combined = [0u64; D];
        for index in 0..D {
            combined[index] = ((sum[index] as u128 + other[index] as u128) % Q as u128) as u64;
        }
        assert_eq!(left, combined);
    }

    #[test]
    fn mat_vec_has_one_row_per_output() {
        let matrix = vec![vector_from(b"row", 3, 0), vector_from(b"row", 3, 10)];
        let vector = vector_from(b"vec", 3, 100);
        assert_eq!(mat_vec(&matrix, &vector).len(), 2);
    }
}
