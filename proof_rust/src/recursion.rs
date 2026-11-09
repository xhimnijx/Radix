//! The Fig. 8 recursion over `M_q`, mirroring `recursion.py`.
//!
//! Vectors live in `M_q^l = (Z_q^4)^32`. Multiplication between vector entries is
//! *slot-wise*: entry `j` is reduced modulo `X^4 - r_{j mod 32}`, which is why
//! `pairing` and `challenge_block` take a slot index derived from the row number.
//! Getting that index wrong does not fail loudly -- it produces a different answer
//! that still looks plausible -- so every function here has a Python digest.

use crate::{glue_crt, quartic_multiply, roots, Poly, Q, SLOTS};

pub type Quartic = [u64; 4];

#[derive(Debug, Clone, PartialEq)]
pub struct RecursionError(pub String);

impl std::fmt::Display for RecursionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "recursion error: {}", self.0)
    }
}

impl std::error::Error for RecursionError {}

pub const SLOTS_PER_BLOCK: usize = SLOTS;

#[inline]
fn add_mod(a: u64, b: u64) -> u64 {
    let sum = a + b;
    if sum >= Q {
        sum - Q
    } else {
        sum
    }
}

pub fn constant(value: u64) -> Quartic {
    [value % Q, 0, 0, 0]
}

pub fn add(left: &Quartic, right: &Quartic) -> Quartic {
    [
        add_mod(left[0], right[0]),
        add_mod(left[1], right[1]),
        add_mod(left[2], right[2]),
        add_mod(left[3], right[3]),
    ]
}

pub fn negate(value: &Quartic) -> Quartic {
    [
        (Q - value[0]) % Q,
        (Q - value[1]) % Q,
        (Q - value[2]) % Q,
        (Q - value[3]) % Q,
    ]
}

pub fn scalar(value: u64, element: &Quartic) -> Quartic {
    let mut out = [0u64; 4];
    for index in 0..4 {
        out[index] = (value as u128 * element[index] as u128 % Q as u128) as u64;
    }
    out
}

/// Quartic product reduced modulo `X^4 - r_slot`.
pub fn product(left: &Quartic, right: &Quartic, slot: usize) -> Result<Quartic, RecursionError> {
    if slot >= SLOTS {
        return Err(RecursionError("slot index is outside the decomposition".into()));
    }
    Ok(quartic_multiply(left, right, roots()[slot]))
}

/// `<left, right>` over `M_q^(32k)`, slot `j mod 32` for entry `j`.
pub fn pairing(left: &[Quartic], right: &[Quartic]) -> Result<Quartic, RecursionError> {
    if left.len() != right.len() {
        return Err(RecursionError("pairing needs equal lengths".into()));
    }
    if left.is_empty() || left.len() % SLOTS != 0 {
        return Err(RecursionError(
            "vector length must be a non-zero multiple of 32".into(),
        ));
    }
    let mut total = constant(0);
    for (index, (a, b)) in left.iter().zip(right.iter()).enumerate() {
        total = add(&total, &product(a, b, index % SLOTS)?);
    }
    Ok(total)
}

pub fn is_constant_vector(vector: &[Quartic]) -> bool {
    vector
        .iter()
        .all(|element| element[1] == 0 && element[2] == 0 && element[3] == 0)
}

/// Kronecker product over `M_q`, right index fastest; entries must be constants.
pub fn tensor(vectors: &[Vec<Quartic>]) -> Result<Vec<Quartic>, RecursionError> {
    if vectors.is_empty() {
        return Err(RecursionError("tensor product needs at least one vector".into()));
    }
    for vector in vectors {
        if vector.len() != SLOTS {
            return Err(RecursionError("each tensor factor must have 32 entries".into()));
        }
        if !is_constant_vector(vector) {
            return Err(RecursionError("tensor factors must have constant entries".into()));
        }
    }
    let mut result: Vec<Quartic> = vectors[0].iter().map(|value| constant(value[0])).collect();
    for vector in &vectors[1..] {
        let mut combined = Vec::with_capacity(result.len() * vector.len());
        for a in &result {
            for b in vector {
                combined.push(constant(
                    (a[0] as u128 * b[0] as u128 % Q as u128) as u64,
                ));
            }
        }
        result = combined;
    }
    Ok(result)
}

/// The flat vector `e_{i_1} (x) ... (x) e_{i_m}`.
pub fn one_hot_tensor(indices: &[usize]) -> Result<Vec<Quartic>, RecursionError> {
    let mut factors = Vec::with_capacity(indices.len());
    for index in indices {
        if *index >= SLOTS {
            return Err(RecursionError("tensor index is outside the subring".into()));
        }
        let mut factor = vec![constant(0); SLOTS];
        factor[*index] = constant(1);
        factors.push(factor);
    }
    tensor(&factors)
}

/// `g` on a single block: the sum of the 32 slot coordinates.
pub fn sum_of_slots(vector: &[Quartic]) -> Result<Quartic, RecursionError> {
    if vector.len() != SLOTS {
        return Err(RecursionError("g needs exactly one block of 32 entries".into()));
    }
    let mut total = constant(0);
    for element in vector {
        total = add(&total, element);
    }
    Ok(total)
}

pub fn is_binary(vector: &[Quartic]) -> bool {
    is_constant_vector(vector) && vector.iter().all(|element| element[0] <= 1)
}

pub fn is_one_hot(vector: &[Quartic]) -> bool {
    if !is_binary(vector) {
        return false;
    }
    matches!(sum_of_slots(vector), Ok(value) if value == constant(1))
}

/// `P . v` over `M_q`: the matrix entries are polynomials, the vector entries scalars.
pub fn matrix_vector(
    matrix: &[Vec<Quartic>],
    vector: &[Quartic],
) -> Result<Vec<Quartic>, RecursionError> {
    if !is_constant_vector(vector) {
        return Err(RecursionError("matrix-vector product needs a constant vector".into()));
    }
    let mut out = Vec::with_capacity(matrix.len());
    for row in matrix {
        if row.len() != vector.len() {
            return Err(RecursionError("matrix row length does not match the vector".into()));
        }
        let mut total = constant(0);
        for (element, weight) in row.iter().zip(vector.iter()) {
            if weight[0] != 0 {
                total = add(&total, &scalar(weight[0], element));
            }
        }
        out.push(total);
    }
    Ok(out)
}

/// `P = [P_1 | ... | P_32]`: 32 column blocks keyed by the first tensor index.
pub fn split(matrix: &[Vec<Quartic>], m: usize) -> Result<Vec<Vec<Vec<Quartic>>>, RecursionError> {
    if m < 1 {
        return Err(RecursionError("tensor depth must be positive".into()));
    }
    let width = SLOTS.pow((m - 1) as u32);
    for row in matrix {
        if row.len() != SLOTS * width {
            return Err(RecursionError("matrix width does not match the tensor depth".into()));
        }
    }
    let mut blocks = Vec::with_capacity(SLOTS);
    for index in 0..SLOTS {
        let mut block = Vec::with_capacity(matrix.len());
        for row in matrix {
            block.push(row[index * width..(index + 1) * width].to_vec());
        }
        blocks.push(block);
    }
    Ok(blocks)
}

/// `gamma^T P_j`: row `rest` is `sum_row gamma[row] P_j[row][rest]`, slot `row % 32`.
pub fn challenge_block(
    challenge: &[Quartic],
    block: &[Vec<Quartic>],
) -> Result<Vec<Quartic>, RecursionError> {
    if challenge.len() != block.len() {
        return Err(RecursionError("challenge height does not match the block".into()));
    }
    let width = block.first().map(|row| row.len()).unwrap_or(0);
    let mut out = Vec::with_capacity(width);
    for column in 0..width {
        let mut total = constant(0);
        for (row_index, (weight, row)) in challenge.iter().zip(block.iter()).enumerate() {
            total = add(&total, &product(weight, &row[column], row_index % SLOTS)?);
        }
        out.push(total);
    }
    Ok(out)
}

/// `P' = [gamma^T P_1 ; ... ; gamma^T P_32]`, the next level's matrix.
pub fn reduce_matrix(
    challenge: &[Quartic],
    matrix: &[Vec<Quartic>],
    m: usize,
) -> Result<Vec<Vec<Quartic>>, RecursionError> {
    let blocks = split(matrix, m)?;
    let mut out = Vec::with_capacity(blocks.len());
    for block in blocks {
        out.push(challenge_block(challenge, &block)?);
    }
    Ok(out)
}

/// The ring element whose slot vector is `values`, i.e. `NTT^-1` of the constants.
pub fn from_constants(values: &[u64]) -> Result<Poly, RecursionError> {
    if values.len() != SLOTS {
        return Err(RecursionError("from_constants needs 32 values".into()));
    }
    let mut residues = [[0u64; 4]; SLOTS];
    for (index, value) in values.iter().enumerate() {
        residues[index] = constant(*value);
    }
    Ok(glue_crt(&residues))
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

    fn digest_vector(vector: &[Quartic]) -> String {
        let mut bytes = Vec::new();
        for element in vector {
            for value in element {
                bytes.extend_from_slice(&(*value as u32).to_le_bytes());
            }
        }
        digest(&bytes)
    }

    #[test]
    fn a_one_hot_tensor_is_a_single_one() {
        let vector = one_hot_tensor(&[1, 2]).unwrap();
        assert_eq!(vector.len(), SLOTS * SLOTS);
        // `is_one_hot` is defined on a single 32-entry block, so a two-factor
        // tensor is binary but not one-hot at this level.
        assert!(is_binary(&vector));
        assert!(!is_one_hot(&vector));
        let position = vector.iter().position(|element| element[0] == 1).unwrap();
        // python: tensor.flat_index((1, 2), 32) == 34
        assert_eq!(position, 34);
    }

    #[test]
    fn pairing_matches_the_python_reference() {
        // python: digest of pairing(left, right) over two blocks
        let left: Vec<Quartic> = (0..2 * SLOTS)
            .map(|index| {
                let poly = uniform_from(b"pair-left", index as u32);
                [poly[0], poly[1], poly[2], poly[3]]
            })
            .collect();
        let right: Vec<Quartic> = (0..2 * SLOTS)
            .map(|index| {
                let poly = uniform_from(b"pair-right", index as u32);
                [poly[0], poly[1], poly[2], poly[3]]
            })
            .collect();
        let result = pairing(&left, &right).unwrap();
        let mut bytes = Vec::new();
        for value in result {
            bytes.extend_from_slice(&(value as u32).to_le_bytes());
        }
        assert_eq!(digest(&bytes), "3a917ee9452a0d80bb25bd2749349055");
    }

    #[test]
    fn matrix_vector_is_linear() {
        let matrix = vec![
            (0..SLOTS).map(|_| [7, 0, 0, 0]).collect::<Vec<_>>(),
            (0..SLOTS).map(|_| [9, 0, 0, 0]).collect::<Vec<_>>(),
        ];
        let mut vector = vec![constant(0); SLOTS];
        vector[0] = constant(2);
        let out = matrix_vector(&matrix, &vector).unwrap();
        assert_eq!(out[0], [14, 0, 0, 0]);
        assert_eq!(out[1], [18, 0, 0, 0]);
    }

    #[test]
    fn matrix_vector_rejects_a_non_constant_vector() {
        let matrix = vec![vec![[1, 0, 0, 0]; SLOTS]];
        let mut vector = vec![constant(0); SLOTS];
        vector[0] = [1, 2, 0, 0];
        assert!(matrix_vector(&matrix, &vector).is_err());
    }

    #[test]
    fn split_and_reduce_agree_on_the_shape() {
        // m = 2: width 32, so a 4 x 1024 matrix splits into 32 blocks of 4 x 32.
        let matrix: Vec<Vec<Quartic>> = (0..4)
            .map(|row| (0..SLOTS * SLOTS).map(|column| constant((row * 3 + column) as u64 % Q)).collect())
            .collect();
        let blocks = split(&matrix, 2).unwrap();
        assert_eq!(blocks.len(), SLOTS);
        assert_eq!(blocks[0].len(), 4);
        assert_eq!(blocks[0][0].len(), SLOTS);

        let challenge: Vec<Quartic> = (0..4).map(|row| constant(row as u64 + 1)).collect();
        let reduced = reduce_matrix(&challenge, &matrix, 2).unwrap();
        assert_eq!(reduced.len(), SLOTS);
        assert_eq!(reduced[0].len(), SLOTS);
    }

    #[test]
    fn from_constants_round_trips_through_the_slots() {
        let values: Vec<u64> = (0..SLOTS).map(|index| index as u64 * 5).collect();
        let poly = from_constants(&values).unwrap();
        let residues = crate::slots(&poly);
        for (index, residue) in residues.iter().enumerate() {
            assert_eq!(residue[0], values[index]);
            assert_eq!(residue[1], 0);
        }
        let _ = encode_poly(&poly);
    }
}
