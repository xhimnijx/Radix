//! BDLOP commitments, mirroring `radix_core/candidate_b/lattice/bdlop.py`.
//!
//! `t = B r` and `u = <b, r> + m`. Everything here rests on the ring multiplication
//! and the vector operations already tested, so the layer only has to get the
//! *structure* right: one randomness, one row per message.

use crate::sample::{dot, mat_vec};
use crate::{Poly, D, Q};

#[derive(Debug, Clone, PartialEq)]
pub struct CommitmentKey {
    pub matrix: Vec<Vec<Poly>>,
    pub vector: Vec<Poly>,
}

impl CommitmentKey {
    pub fn new(matrix: Vec<Vec<Poly>>, vector: Vec<Poly>) -> CommitmentKey {
        let width = vector.len();
        assert!(width >= 1, "commitment vector must not be empty");
        assert!(!matrix.is_empty(), "commitment matrix must not be empty");
        for row in &matrix {
            assert_eq!(row.len(), width, "every row must have the declared width");
        }
        CommitmentKey { matrix, vector }
    }

    pub fn rows(&self) -> usize {
        self.matrix.len()
    }

    pub fn width(&self) -> usize {
        self.vector.len()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Commitment {
    pub t: Vec<Poly>,
    pub u: Poly,
}

impl Commitment {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity((self.t.len() + 1) * D * 4);
        for poly in &self.t {
            out.extend_from_slice(&crate::codec::encode_poly(poly));
        }
        out.extend_from_slice(&crate::codec::encode_poly(&self.u));
        out
    }
}

pub fn commit(key: &CommitmentKey, message: &Poly, randomness: &[Poly]) -> Commitment {
    assert_eq!(
        randomness.len(),
        key.width(),
        "randomness must have one polynomial per key column"
    );
    let t = mat_vec(&key.matrix, randomness);
    let mut u = dot(&key.vector, randomness);
    for index in 0..D {
        let sum = u[index] as u128 + message[index] as u128;
        u[index] = (sum % Q as u128) as u64;
    }
    Commitment { t, u }
}

pub fn verify(key: &CommitmentKey, commitment: &Commitment, message: &Poly, randomness: &[Poly]) -> bool {
    &commit(key, message, randomness) == commitment
}

pub fn add_commitments(left: &Commitment, right: &Commitment) -> Commitment {
    assert_eq!(left.t.len(), right.t.len(), "commitments must have the same height");
    let mut t = Vec::with_capacity(left.t.len());
    for (a, b) in left.t.iter().zip(right.t.iter()) {
        let mut sum = [0u64; D];
        for index in 0..D {
            let value = a[index] as u128 + b[index] as u128;
            sum[index] = (value % Q as u128) as u64;
        }
        t.push(sum);
    }
    let mut u = [0u64; D];
    for index in 0..D {
        u[index] = ((left.u[index] as u128 + right.u[index] as u128) % Q as u128) as u64;
    }
    Commitment { t, u }
}

pub fn add_openings(left: &[Poly], right: &[Poly]) -> Vec<Poly> {
    assert_eq!(left.len(), right.len(), "openings must have the same length");
    left.iter()
        .zip(right.iter())
        .map(|(a, b)| {
            let mut sum = [0u64; D];
            for index in 0..D {
                sum[index] = ((a[index] as u128 + b[index] as u128) % Q as u128) as u64;
            }
            sum
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::vector_from;

    fn key() -> CommitmentKey {
        let matrix = vec![
            vector_from(b"B-row", 3, 0),
            vector_from(b"B-row", 3, 8),
        ];
        CommitmentKey::new(matrix, vector_from(b"b-row", 3, 16))
    }

    #[test]
    fn an_honest_opening_verifies() {
        let key = key();
        let randomness = vector_from(b"r", 3, 32);
        let message = vector_from(b"m", 1, 40)[0];
        let commitment = commit(&key, &message, &randomness);
        assert!(verify(&key, &commitment, &message, &randomness));
    }

    #[test]
    fn a_different_message_does_not_verify() {
        let key = key();
        let randomness = vector_from(b"r", 3, 32);
        let message = vector_from(b"m", 1, 40)[0];
        let other = vector_from(b"m", 1, 41)[0];
        let commitment = commit(&key, &message, &randomness);
        assert!(!verify(&key, &commitment, &other, &randomness));
    }

    #[test]
    fn commitments_are_additively_homomorphic() {
        let key = key();
        let left = vector_from(b"r", 3, 50);
        let right = vector_from(b"r", 3, 60);
        let message_a = vector_from(b"m", 1, 70)[0];
        let message_b = vector_from(b"m", 1, 71)[0];

        let sum = add_commitments(
            &commit(&key, &message_a, &left),
            &commit(&key, &message_b, &right),
        );
        let mut message_sum = [0u64; D];
        for index in 0..D {
            message_sum[index] =
                ((message_a[index] as u128 + message_b[index] as u128) % Q as u128) as u64;
        }
        let expected = commit(&key, &message_sum, &add_openings(&left, &right));
        assert_eq!(sum, expected);
    }

    #[test]
    fn the_commitment_matches_the_python_reference() {
        // python: experiments/port_vectors.py
        //   shake_256(commitment.encode()).hexdigest(16) == 8ef836b5977e51188c10faf77e096625
        let key = key();
        let randomness = vector_from(b"r", 3, 32);
        let message = vector_from(b"m", 1, 40)[0];
        let commitment = commit(&key, &message, &randomness);
        let mut digest = [0u8; 16];
        crate::sha3::shake256(&commitment.encode(), &mut digest);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "8ef836b5977e51188c10faf77e096625");
    }

    #[test]
    fn the_commitment_has_one_row_per_key_row() {
        let key = key();
        let randomness = vector_from(b"r", 3, 32);
        let message = vector_from(b"m", 1, 40)[0];
        assert_eq!(commit(&key, &message, &randomness).t.len(), key.rows());
    }
}
