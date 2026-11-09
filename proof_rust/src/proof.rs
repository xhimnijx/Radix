//! The verifier's index plumbing and lifting, mirroring `setmembership.py`.
//!
//! These are the small functions that decide *which* commitment a paper index
//! refers to and how a 32-slot vector becomes a ring element. Both are places where
//! an error stays silent: the wrong slot still produces a well-formed polynomial,
//! and the proof simply fails to verify for no visible reason.

use crate::recursion::{challenge_block, from_constants, Quartic};
use crate::statement::ProofError;
use crate::{add, glue_crt, slots, Poly, SLOTS};

/// Map the paper's `t`-index (`1..k+2m+1`) to its position in the commitment vector.
pub fn paper_to_slot(position: usize, depth: usize, rows: usize) -> Result<usize, ProofError> {
        let kappa = super::statement::CHALLENGE_DIM;
    if position == 0 {
        return Err(ProofError("paper positions start at 1".into()));
    }
    if position == rows + 2 * depth + 1 {
        return Ok(kappa + rows + 2 * depth); // psi, the final entry
    }
    if position <= depth + rows {
        return Ok(kappa + position - 1);
    }
    if position == rows + 2 * depth {
        return Ok(kappa + depth + rows);
    }
    Ok(kappa + depth + rows + (position - (depth + rows)))
}

/// The 32 slot coordinates of each polynomial, concatenated.
pub fn gamma_elements(gamma: &[Poly]) -> Vec<Quartic> {
    let mut out = Vec::with_capacity(gamma.len() * SLOTS);
    for poly in gamma {
        out.extend_from_slice(&slots(poly));
    }
    out
}

/// `B^T gamma`: every slot equal to gamma's first slot.
///
/// `B`'s first row is all ones, so `(B^T gamma)_i = gamma_0`. This is what encodes
/// `<1, v_i> = 1`: paired with a one-hot `v_i` it selects `gamma_0`, cancelling the
/// `<e_1, gamma>` term it must cancel.
pub fn b_transpose(poly: &Poly) -> Poly {
    let first = slots(poly)[0];
    let residues: [Quartic; SLOTS] = [first; SLOTS];
    glue_crt(&residues)
}

/// `e_1`: the ring element whose slot vector is one-hot at position zero.
pub fn e1() -> Poly {
    let mut values = [0u64; SLOTS];
    values[0] = 1;
    from_constants(&values).expect("32 values")
}

/// A 32-entry constant vector lifted to a ring element.
pub fn lift(values: &[u64]) -> Poly {
    from_constants(values).expect("32 values")
}

/// The tensor of one-hot blocks selecting `index` in base `SLOTS`.
pub fn index_vectors(index: usize, depth: usize) -> Result<Vec<Vec<u64>>, ProofError> {
        let mut digits = Vec::with_capacity(depth);
    let mut value = index;
    for _ in 0..depth {
        digits.push(value % SLOTS);
        value /= SLOTS;
    }
    if value != 0 {
        return Err(ProofError("index is outside the ring".into()));
    }
    let mut out = Vec::with_capacity(depth);
    for digit in digits.iter().rev() {
        let mut block = vec![0u64; SLOTS];
        block[*digit] = 1;
        out.push(block);
    }
    Ok(out)
}

/// `x_{m+1} = P~_m^T gamma_m`, one polynomial per tensor factor (eq. 23).
pub fn final_x(
    matrix: &[Vec<Quartic>],
    gamma_m: &[Poly],
    depth: usize,
) -> Result<Vec<Poly>, ProofError> {
    let mut blocks: Vec<Poly> = Vec::with_capacity(depth);
    for index in 0..depth - 1 {
        blocks.push(b_transpose(&gamma_m[index + 1]));
    }
    let block = challenge_block(&slots(&gamma_m[0]), matrix)
        .map_err(|error| ProofError(error.0.clone()))?;
    let tail = glue_crt_of(block);
    blocks.push(add(&tail, &b_transpose(&gamma_m[depth])));
    Ok(blocks)
}

fn glue_crt_of(vector: Vec<Quartic>) -> Poly {
    let mut residues = [[0u64; 4]; SLOTS];
    for (index, element) in vector.iter().enumerate().take(SLOTS) {
        residues[index] = *element;
    }
    glue_crt(&residues)
}

/// `P`: row `(component, slot)`, column `j` is the slots of `-c' pk_j`.
///
/// This is the largest single computation in the verifier: `rows * 32` by `l^m`
/// quartic entries. The order matters -- component-major, then slot -- because the
/// paper indexes `t` by `(component, slot)` pairs and the descent relies on it.
pub fn set_matrix(c_prime: &Poly, statement: &crate::statement::Statement) -> Vec<Vec<Quartic>> {
    let rows = statement.matrix.len();
    let columns = statement.keys.len();
    let mut out = vec![vec![[0u64; 4]; columns]; rows * SLOTS];
    for (column, key) in statement.keys.iter().enumerate() {
        for component in 0..rows {
            let product = crate::mul_crt(c_prime, &key[component]);
            let negated = crate::sub(&crate::zero(), &product);
            let residues = slots(&negated);
            for slot in 0..SLOTS {
                out[component * SLOTS + slot][column] = residues[slot];
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_poly;
    use crate::sample::uniform_from;
    use crate::sha3::shake256;

    fn digest(data: &[u8]) -> String {
        let mut out = [0u8; 16];
        shake256(data, &mut out);
        out.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn paper_to_slot_matches_the_python_reference() {
        // python: [_paper_to_slot(p, 2, 4) for p in 1..12]
        let expected = [10usize, 11, 12, 13, 14, 15, 17, 16, 18, 20, 21];
        for (offset, want) in expected.iter().enumerate() {
            assert_eq!(paper_to_slot(offset + 1, 2, 4).unwrap(), *want, "position {}", offset + 1);
        }
    }

    #[test]
    fn e1_matches_the_python_reference() {
        // python: digest(ring.encode(_e1(SMILE))) == e75a97097113d7ee3206efda848f31e5
        assert_eq!(digest(&encode_poly(&e1())), "e75a97097113d7ee3206efda848f31e5");
    }

    #[test]
    fn b_transpose_matches_the_python_reference() {
        // python: digest(ring.encode(_b_transpose(gamma[0]))) == 10f028d8f8bb7b8d80daafff38f83463
        let gamma = uniform_from(b"gamma", 0);
        assert_eq!(
            digest(&encode_poly(&b_transpose(&gamma))),
            "10f028d8f8bb7b8d80daafff38f83463"
        );
    }

    #[test]
    fn gamma_elements_match_the_python_reference() {
        // python: digest of the concatenated slots == a79a2ab27b9ef1549ec9974b674e5dad
        let gamma: Vec<Poly> = (0..3).map(|index| uniform_from(b"gamma", index)).collect();
        let elements = gamma_elements(&gamma);
        let mut bytes = Vec::new();
        for element in elements {
            for value in element {
                bytes.extend_from_slice(&(value as u32).to_le_bytes());
            }
        }
        assert_eq!(digest(&bytes), "a79a2ab27b9ef1549ec9974b674e5dad");
    }

    #[test]
    fn the_set_matrix_matches_the_python_reference() {
        // python: shape 128 x 1024, digest == 7fdce86f489050132eb684d39faa5239
        use crate::statement::Statement;
        let rows = 4usize;
        let cols = 13usize;
        let matrix: Vec<Vec<Poly>> = (0..rows)
            .map(|row| (0..cols).map(|col| uniform_from(b"A", (row * cols + col) as u32)).collect())
            .collect();
        let keys: Vec<Vec<Poly>> = (0..1024)
            .map(|key| {
                (0..rows)
                    .map(|component| uniform_from(b"pk", (key * rows + component) as u32))
                    .collect()
            })
            .collect();
        let statement = Statement::new(matrix, keys, 2).unwrap();
        let c_prime = uniform_from(b"c-prime", 0);
        let matrix_out = set_matrix(&c_prime, &statement);
        assert_eq!(matrix_out.len(), rows * SLOTS);
        assert_eq!(matrix_out[0].len(), 1024);
        let mut bytes = Vec::new();
        for row in &matrix_out {
            for entry in row {
                for value in entry {
                    bytes.extend_from_slice(&(*value as u32).to_le_bytes());
                }
            }
        }
        assert_eq!(digest(&bytes), "7fdce86f489050132eb684d39faa5239");
    }

    #[test]
    fn b_transpose_is_constant_across_slots() {
        let poly = uniform_from(b"gamma", 1);
        let first = slots(&poly)[0];
        for residue in slots(&b_transpose(&poly)) {
            assert_eq!(residue, first);
        }
    }

    #[test]
    fn index_vectors_matches_the_python_reference() {
        // python: index_vectors(5, 2) selects positions 0 and 5
        let vectors = index_vectors(5, 2).unwrap();
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0][0], 1);
        assert_eq!(vectors[1][5], 1);
        assert!(index_vectors(SLOTS * SLOTS, 2).is_err());
    }
}
