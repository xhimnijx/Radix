//! Keys, statements and the challenge derivations, mirroring `setmembership.py`.
//!
//! This is the scaffolding the prover and verifier share. The values that come out
//! of `draw` and `draw_ternary` are the ones that decide whether two
//! implementations agree at all: the verifier recomputes them from the proof's own
//! commitments, so a mismatched label, order or threshold makes every proof fail
//! while looking like a maths error.

use crate::codec::encode_poly;
use crate::transcript::Transcript;
use crate::Poly;
use crate::{D, Q, SLOTS};

/// Domain tag for every proof transcript.
pub const PROOF_TAG: &[u8] = b"radix/b/setmembership/v1";

pub const CHALLENGE_DIM: usize = 10; // kappa
pub const MASKING_DIM: usize = 10; // lambda
pub const MATRIX_ROWS: usize = 4; // k
pub const MATRIX_COLS: usize = 13; // ell

#[derive(Debug, Clone, PartialEq)]
pub struct ProofError(pub String);

impl std::fmt::Display for ProofError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "proof error: {}", self.0)
    }
}

impl std::error::Error for ProofError {}

/// `W = kappa + lambda + rows + 2m + 1`: the width of `r`, `y`, `z` and the key rows.
pub fn masking_width(depth: usize, rows: usize) -> Result<usize, ProofError> {
    if depth < 2 {
        return Err(ProofError("depth must be at least 2".into()));
    }
    if rows < 1 {
        return Err(ProofError("the matrix must have at least one row".into()));
    }
    Ok(CHALLENGE_DIM + MASKING_DIM + rows + 2 * depth + 1)
}

/// The number of polynomials in the commitment vector.
///
/// `kappa + rows + 2m + 1`: the `kappa` `t_0` entries, one per paper position
/// `1..k+2m+1`, and `psi`. An earlier version of this file used
/// `kappa + lambda + depth + 1`, which happens to equal 23 for the *tagged*
/// parameters (rows = 8) and is wrong everywhere else -- the Python testnet codec
/// has the same latent bug for the same reason.
pub fn commitment_count(rows: usize, depth: usize) -> usize {
    CHALLENGE_DIM + rows + 2 * depth + 1
}

/// The masking width `s = 464 * sqrt(W)`, calibrated by
/// `experiments/mask_calibration.py` so that `M = sqrt(3/2)`.
pub fn mask_std(width: usize) -> f64 {
    464.0 * (width as f64).sqrt()
}

/// A full-width polynomial drawn from the transcript.
pub fn draw(transcript: &mut Transcript, label: &[u8]) -> Poly {
    let raw = transcript.challenge(label, 4 * D);
    let mut poly = [0u64; D];
    for index in 0..D {
        let start = index * 4;
        let word = u32::from_le_bytes([raw[start], raw[start + 1], raw[start + 2], raw[start + 3]]);
        poly[index] = word as u64 % Q;
    }
    poly
}

/// A ternary challenge: `P(0) = 1/2`, `P(1) = P(-1) = 1/4`.
pub fn draw_ternary(transcript: &mut Transcript, label: &[u8]) -> [i64; D] {
    let raw = transcript.challenge(label, D);
    let mut out = [0i64; D];
    for (index, byte) in raw.iter().enumerate() {
        out[index] = if *byte < 128 {
            0
        } else if *byte < 192 {
            1
        } else {
            -1
        };
    }
    out
}

/// The transcript head: the domain, the message, `w` and the commitments.
/// A digest of the ring, in order, so a proof binds the ring it was made for.
///
/// Must match `setmembership.ring_digest` byte for byte, or cross-language
/// verification breaks. Zero proof bytes: it only moves the challenge.
pub fn ring_digest(statement: &Statement) -> Vec<u8> {
    let mut transcript = Transcript::new(b"radix/ring/v1");
    // Must match `setmembership.ring_digest` byte for byte. The parameters and the
    // proved matrix come first, so a proof cannot be replayed under different
    // parameters or against a different A.
    transcript.absorb(b"modulus", &(crate::Q as u64).to_le_bytes());
    transcript.absorb(b"degree", &(D as u32).to_le_bytes());
    transcript.absorb(b"depth", &(statement.depth as u32).to_le_bytes());
    for row in &statement.matrix {
        transcript.absorb(b"A", &encode_vector(row));
    }
    for key in &statement.keys {
        transcript.absorb(b"pk", &encode_vector(key));
    }
    transcript.challenge(b"ring", 32)
}

pub fn head(message: &[u8], w: &[Poly], commitment: &[Poly], digest: &[u8]) -> Transcript {
    let mut transcript = Transcript::new(PROOF_TAG);
    transcript.absorb(b"message", message);
    transcript.absorb(b"ring", digest);
    transcript.absorb(b"w", &encode_vector(w));
    transcript.absorb(b"t", &encode_vector(commitment));
    transcript
}

pub fn encode_vector(vector: &[Poly]) -> Vec<u8> {
    let mut out = Vec::with_capacity(vector.len() * D * 4);
    for poly in vector {
        out.extend_from_slice(&encode_poly(poly));
    }
    out
}

/// `P_0` from `kappa` rows of width `W` and the `b` rows.
#[derive(Debug, Clone, PartialEq)]
pub struct Keys {
    pub rows0: Vec<Vec<Poly>>,
    pub rows: Vec<Vec<Poly>>,
    pub depth: usize,
    pub row_count: usize,
}

impl Keys {
    pub fn new(
        rows0: Vec<Vec<Poly>>,
        rows: Vec<Vec<Poly>>,
        depth: usize,
        row_count: usize,
    ) -> Result<Keys, ProofError> {
        let width = masking_width(depth, row_count)?;
        if rows0.len() != CHALLENGE_DIM {
            return Err(ProofError("B_0 must have kappa rows".into()));
        }
        if rows.len() != row_count + 2 * depth + 1 {
            return Err(ProofError("wrong number of b rows".into()));
        }
        for row in rows0.iter().chain(rows.iter()) {
            if row.len() != width {
                return Err(ProofError("key rows must have width W".into()));
            }
        }
        Ok(Keys {
            rows0,
            rows,
            depth,
            row_count,
        })
    }

    pub fn width(&self) -> usize {
        masking_width(self.depth, self.row_count).expect("validated on construction")
    }
}

/// The public ring: `A` and the `l^m` public keys.
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub matrix: Vec<Vec<Poly>>,
    pub keys: Vec<Vec<Poly>>,
    pub depth: usize,
}

impl Statement {
    pub fn new(matrix: Vec<Vec<Poly>>, keys: Vec<Vec<Poly>>, depth: usize) -> Result<Statement, ProofError> {
        if matrix.is_empty() {
            return Err(ProofError("A must have at least one row".into()));
        }
        if matrix.iter().any(|row| row.len() != MATRIX_COLS) {
            return Err(ProofError("A must have ell columns".into()));
        }
        if depth < 2 {
            return Err(ProofError("depth must be at least 2".into()));
        }
        if keys.len() != SLOTS.pow(depth as u32) {
            return Err(ProofError("the ring must have l^m keys".into()));
        }
        if keys.iter().any(|key| key.len() != matrix.len()) {
            return Err(ProofError("each public key must have k components".into()));
        }
        Ok(Statement {
            matrix,
            keys,
            depth,
        })
    }

    pub fn rows(&self) -> usize {
        self.matrix.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_bytes(bytes: &[u8]) -> String {
        let mut out = [0u8; 16];
        crate::sha3::shake256(bytes, &mut out);
        out.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn masking_width_matches_the_python_reference() {
        assert_eq!(masking_width(2, 4).unwrap(), 29);
        assert_eq!(masking_width(2, 8).unwrap(), 33);
        assert_eq!(masking_width(3, 4).unwrap(), 31);
        assert!(masking_width(1, 4).is_err());
        assert!(masking_width(2, 0).is_err());
    }

    #[test]
    fn draw_matches_the_python_reference() {
        // python: _draw(Transcript(PROOF_TAG).absorb(b"message", b"hello"), b"alpha")
        //         digest == d35674e8f771c72d4a26a770bd5754e8
        let mut transcript = Transcript::new(PROOF_TAG);
        transcript.absorb(b"message", b"hello");
        let poly = draw(&mut transcript, b"alpha");
        assert_eq!(digest_bytes(&encode_poly(&poly)), "d35674e8f771c72d4a26a770bd5754e8");
    }

    #[test]
    fn draw_ternary_matches_the_python_reference() {
        // python: (0, 0, -1, 1, 1, 0, 1, 0, ...)
        let mut transcript = Transcript::new(PROOF_TAG);
        transcript.absorb(b"message", b"hello");
        let challenge = draw_ternary(&mut transcript, b"c");
        assert_eq!(&challenge[..8], &[0, 0, -1, 1, 1, 0, 1, 0]);
        assert!(challenge.iter().all(|value| (-1..=1).contains(value)));
    }

    #[test]
    fn the_head_binds_the_message_first() {
        let w = vec![[1u64; D]; 2];
        let commitment = vec![[2u64; D]; 3];
        let mut first = head(b"one", &w, &commitment, b"ring");
        let mut second = head(b"two", &w, &commitment, b"ring");
        assert_ne!(
            draw_ternary(&mut first, b"c"),
            draw_ternary(&mut second, b"c")
        );
    }

    #[test]
    fn the_head_binds_the_ring_digest() {
        let w = vec![[1u64; D]; 2];
        let commitment = vec![[2u64; D]; 3];
        let mut here = head(b"m", &w, &commitment, b"ring-one");
        let mut there = head(b"m", &w, &commitment, b"ring-two");
        assert_ne!(
            draw_ternary(&mut here, b"c"),
            draw_ternary(&mut there, b"c"),
            "a proof made against one ring must not transfer to another"
        );
    }

    #[test]
    fn keys_validate_their_shape() {
        let width = masking_width(2, 4).unwrap();
        let row = vec![[0u64; D]; width];
        assert!(Keys::new(vec![row.clone(); CHALLENGE_DIM], vec![row.clone(); 4 + 2 * 2 + 1], 2, 4).is_ok());
        assert!(Keys::new(vec![row.clone(); CHALLENGE_DIM - 1], vec![row.clone(); 9], 2, 4).is_err());
        assert!(Keys::new(vec![row; CHALLENGE_DIM], vec![vec![[0u64; D]; 3]; 9], 2, 4).is_err());
    }
}
