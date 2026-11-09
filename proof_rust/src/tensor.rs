//! Index vectors and Kronecker products, mirroring `tensor.py`.
//!
//! Small pure functions, but load-bearing: `select_columns` turns a set of indices
//! into the columns of the proved matrix, and an off-by-one here would silently
//! prove membership of the wrong key.

use crate::Poly;

#[derive(Debug, Clone, PartialEq)]
pub struct TensorError(pub String);

impl std::fmt::Display for TensorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "tensor error: {}", self.0)
    }
}

impl std::error::Error for TensorError {}

/// The unit vector of length `dimension` with a single 1 at `index`.
pub fn one_hot(dimension: usize, index: usize) -> Result<Vec<u64>, TensorError> {
    if dimension < 1 {
        return Err(TensorError("dimension must be positive".into()));
    }
    if index >= dimension {
        return Err(TensorError("index is outside the vector".into()));
    }
    let mut out = vec![0u64; dimension];
    out[index] = 1;
    Ok(out)
}

/// Integer Kronecker product, right index varying fastest.
pub fn kron(left: &[u64], right: &[u64]) -> Result<Vec<u64>, TensorError> {
    if left.is_empty() || right.is_empty() {
        return Err(TensorError("cannot tensor an empty vector".into()));
    }
    let mut out = Vec::with_capacity(left.len() * right.len());
    for a in left {
        for b in right {
            out.push(a * b);
        }
    }
    Ok(out)
}

pub fn tensor(vectors: &[Vec<u64>]) -> Result<Vec<u64>, TensorError> {
    if vectors.is_empty() {
        return Err(TensorError("tensor product needs at least one vector".into()));
    }
    let mut result = vectors[0].clone();
    for vector in &vectors[1..] {
        result = kron(&result, vector)?;
    }
    Ok(result)
}

/// `n = l^m`: how many set elements a shape with `m` factors of width `l` addresses.
pub fn set_size(m: usize, l: usize) -> Result<usize, TensorError> {
    if !(1..=8).contains(&m) {
        return Err(TensorError("tensor factor count must be in 1..8".into()));
    }
    if l < 2 {
        return Err(TensorError("subring dimension must be at least 2".into()));
    }
    Ok(l.pow(m as u32))
}

/// The position a tuple of one-hot indices selects, base `l`, first factor fastest.
pub fn flat_index(indices: &[usize], l: usize) -> Result<usize, TensorError> {
    if indices.is_empty() {
        return Err(TensorError("at least one index is required".into()));
    }
    let mut value = 0usize;
    for index in indices {
        if *index >= l {
            return Err(TensorError("index is outside the subring dimension".into()));
        }
        value = value * l + index;
    }
    Ok(value)
}

/// The 1-position, rejecting anything that is not a unit vector.
pub fn assert_one_hot(vector: &[u64]) -> Result<usize, TensorError> {
    if vector.is_empty() {
        return Err(TensorError("vector must not be empty".into()));
    }
    if vector.iter().any(|value| *value > 1) {
        return Err(TensorError("vector entries must be 0 or 1".into()));
    }
    let positions: Vec<usize> = vector
        .iter()
        .enumerate()
        .filter(|(_, value)| **value == 1)
        .map(|(index, _)| index)
        .collect();
    if positions.len() != 1 {
        return Err(TensorError("vector must have exactly one 1".into()));
    }
    Ok(positions[0])
}

/// Columns selected, in order, by a list of one-hot index vectors.
pub fn select_columns(columns: &[Poly], indices: &[usize]) -> Result<Vec<Poly>, TensorError> {
    let mut out = Vec::with_capacity(indices.len());
    for index in indices {
        if *index >= columns.len() {
            return Err(TensorError("column index is outside the matrix".into()));
        }
        out.push(columns[*index]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_hot_matches_the_python_reference() {
        assert_eq!(one_hot(4, 2).unwrap(), vec![0, 0, 1, 0]);
        assert!(one_hot(4, 4).is_err());
        assert!(one_hot(0, 0).is_err());
    }

    #[test]
    fn kron_matches_the_python_reference() {
        assert_eq!(kron(&[1, 2], &[3, 4]).unwrap(), vec![3, 4, 6, 8]);
    }

    #[test]
    fn tensor_of_one_hots_is_one_hot_at_the_flat_index() {
        let l = 32usize;
        let indices = [2usize, 1, 3];
        let vectors: Vec<Vec<u64>> = indices
            .iter()
            .map(|index| one_hot(l, *index).unwrap())
            .collect();
        let combined = tensor(&vectors).unwrap();
        assert_eq!(combined.len(), l.pow(3));
        let position = assert_one_hot(&combined).unwrap();
        // python: tensor.flat_index((2, 1, 3), 32) == 2083
        assert_eq!(position, 2083);
        assert_eq!(flat_index(&indices, l).unwrap(), 2083);
    }

    #[test]
    fn set_size_is_l_to_the_m() {
        assert_eq!(set_size(2, 32).unwrap(), 1024);
        assert_eq!(set_size(3, 32).unwrap(), 32768);
        assert!(set_size(0, 32).is_err());
        assert!(set_size(9, 32).is_err());
    }

    #[test]
    fn assert_one_hot_rejects_non_unit_vectors() {
        assert!(assert_one_hot(&[0, 0, 0]).is_err());
        assert!(assert_one_hot(&[1, 1]).is_err());
        assert!(assert_one_hot(&[0, 2]).is_err());
        assert_eq!(assert_one_hot(&[0, 1, 0]).unwrap(), 1);
    }
}
