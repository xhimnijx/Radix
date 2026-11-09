//! Wire codec: polynomials and proof envelopes, matching the Python layout.
//!
//! `Proof.encode` in Python is a bare concatenation with no lengths: the decoder
//! has to be told the statement shape (how many commitment polynomials, how wide
//! `response` is) because none of that is in the bytes. That is a real design wart
//! and the port reproduces it rather than inventing a versioned format the Python
//! side would not understand.

use crate::D;

pub const POLY_BYTES: usize = D * 4;
pub const CHALLENGE_BYTES: usize = D; // ternary, one byte per coefficient

#[derive(Debug, Clone, PartialEq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "decode error: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

pub fn encode_poly(poly: &[u64; D]) -> Vec<u8> {
    let mut out = Vec::with_capacity(POLY_BYTES);
    for value in poly {
        out.extend_from_slice(&(*value as u32).to_le_bytes());
    }
    out
}

pub fn decode_poly(bytes: &[u8], offset: usize) -> Result<[u64; D], DecodeError> {
    if bytes.len() < offset + POLY_BYTES {
        return Err(DecodeError("not enough bytes for a polynomial".into()));
    }
    let mut out = [0u64; D];
    for index in 0..D {
        let start = offset + index * 4;
        out[index] = u32::from_le_bytes([
            bytes[start],
            bytes[start + 1],
            bytes[start + 2],
            bytes[start + 3],
        ]) as u64;
    }
    Ok(out)
}

/// Two bytes per coefficient, centred. The verifier bounds `z` by `12 * sigma`,
/// which the caller must have checked, so a coefficient fits a signed 16-bit value.
pub fn encode_bounded_poly(poly: &[u64; D]) -> Vec<u8> {
    let half = crate::Q / 2;
    let mut out = Vec::with_capacity(D * 2);
    for value in poly {
        let centred = if *value > half {
            *value as i64 - crate::Q as i64
        } else {
            *value as i64
        };
        out.extend_from_slice(&(centred as i16).to_le_bytes());
    }
    out
}

/// Inverse of `encode_bounded_poly`, reducing back into `[0, q)`.
pub fn decode_bounded_poly(bytes: &[u8], offset: usize) -> Result<[u64; D], DecodeError> {
    let mut out = [0u64; D];
    for (index, slot) in out.iter_mut().enumerate() {
        let start = offset + index * 2;
        let raw = i16::from_le_bytes([bytes[start], bytes[start + 1]]);
        *slot = (raw as i64).rem_euclid(crate::Q as i64) as u64;
    }
    Ok(out)
}

pub fn encode_challenge(challenge: &[i64; D]) -> Vec<u8> {
    challenge.iter().map(|value| (*value + 1) as u8).collect()
}

pub fn decode_challenge(bytes: &[u8], offset: usize) -> Result<[i64; D], DecodeError> {
    if bytes.len() < offset + CHALLENGE_BYTES {
        return Err(DecodeError("not enough bytes for a challenge".into()));
    }
    let mut out = [0i64; D];
    for index in 0..D {
        let raw = bytes[offset + index];
        if raw > 2 {
            return Err(DecodeError("challenge byte is not ternary".into()));
        }
        out[index] = raw as i64 - 1;
    }
    Ok(out)
}

/// A decoded proof, in the same field order as Python's `setmembership.Proof`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofWire {
    pub commitment: Vec<[u64; D]>,
    pub h: [u64; D],
    pub omega: [u64; D],
    pub challenge: [i64; D],
    pub challenge_prime: [i64; D],
    pub response_prime: Vec<[u64; D]>,
    pub response: Vec<[u64; D]>,
}

impl ProofWire {
    /// The exact byte length for a statement with `commitment_count` commitment
    /// polynomials and a `width`-component response.
    pub fn expected_len(commitment_count: usize, response_prime_count: usize, width: usize) -> usize {
        (commitment_count + 2 + response_prime_count) * POLY_BYTES
            + width * D * 2
            + 2 * CHALLENGE_BYTES
    }

    pub fn decode(
        bytes: &[u8],
        commitment_count: usize,
        response_prime_count: usize,
        width: usize,
    ) -> Result<ProofWire, DecodeError> {
        let expected = Self::expected_len(commitment_count, response_prime_count, width);
        if bytes.len() != expected {
            return Err(DecodeError(format!(
                "proof must be {expected} bytes for this statement, got {}",
                bytes.len()
            )));
        }
        let mut cursor = 0;
        let mut take = |count: usize| -> Result<Vec<[u64; D]>, DecodeError> {
            let mut out = Vec::with_capacity(count);
            for _ in 0..count {
                out.push(decode_poly(bytes, cursor)?);
                cursor += POLY_BYTES;
            }
            Ok(out)
        };
        let commitment = take(commitment_count)?;
        let h = take(1)?[0];
        let omega = take(1)?[0];
        let response_prime = take(response_prime_count)?;
        let mut response = Vec::with_capacity(width);
        for _ in 0..width {
            response.push(decode_bounded_poly(bytes, cursor)?);
            cursor += D * 2;
        }
        let challenge = decode_challenge(bytes, cursor)?;
        cursor += CHALLENGE_BYTES;
        let challenge_prime = decode_challenge(bytes, cursor)?;
        Ok(ProofWire {
            commitment,
            h,
            omega,
            challenge,
            challenge_prime,
            response_prime,
            response,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::expected_len(
            self.commitment.len(),
            self.response_prime.len(),
            self.response.len(),
        ));
        for poly in &self.commitment {
            out.extend_from_slice(&encode_poly(poly));
        }
        out.extend_from_slice(&encode_poly(&self.h));
        out.extend_from_slice(&encode_poly(&self.omega));
        for poly in &self.response_prime {
            out.extend_from_slice(&encode_poly(poly));
        }
        for poly in &self.response {
            out.extend_from_slice(&encode_bounded_poly(poly));
        }
        out.extend_from_slice(&encode_challenge(&self.challenge));
        out.extend_from_slice(&encode_challenge(&self.challenge_prime));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polynomial_encoding_matches_the_python_digest() {
        // python: poly = tuple((i * 7919) % 4294966337 for i in range(128))
        //         shake_256(ring.encode(poly)).hexdigest(16) == 1e86594e26a796356faecf567d5e5529
        let mut poly = [0u64; D];
        for index in 0..D {
            poly[index] = (index as u64 * 7919) % 4_294_966_337;
        }
        let bytes = encode_poly(&poly);
        assert_eq!(bytes.len(), POLY_BYTES);
        let mut digest = [0u8; 16];
        crate::sha3::shake256(&bytes, &mut digest);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "1e86594e26a796356faecf567d5e5529");
        assert_eq!(decode_poly(&bytes, 0).unwrap(), poly);
    }

    #[test]
    fn challenges_are_one_byte_ternary() {
        let mut challenge = [0i64; D];
        challenge[0] = -1;
        challenge[1] = 1;
        let bytes = encode_challenge(&challenge);
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 2);
        assert_eq!(decode_challenge(&bytes, 0).unwrap(), challenge);
    }

    #[test]
    fn a_non_ternary_challenge_byte_is_rejected() {
        let mut bytes = vec![0u8; CHALLENGE_BYTES];
        bytes[3] = 9;
        assert!(decode_challenge(&bytes, 0).is_err());
    }

    #[test]
    fn a_truncated_proof_is_rejected_rather_than_panicking() {
        assert!(ProofWire::decode(&[0u8; 10], 3, 2, 4).is_err());
        assert!(ProofWire::decode(&[], 0, 0, 0).is_err());
    }

    #[test]
    fn a_proof_round_trips_through_the_wire() {
        let commitment = vec![[1u64; D]; 3];
        let proof = ProofWire {
            commitment,
            h: [2u64; D],
            omega: [3u64; D],
            challenge: [1i64; D],
            challenge_prime: [-1i64; D],
            response_prime: vec![[4u64; D]; 2],
            response: vec![[5u64; D]; 4],
        };
        let bytes = proof.encode();
        assert_eq!(bytes.len(), ProofWire::expected_len(3, 2, 4));
        let decoded = ProofWire::decode(&bytes, 3, 2, 4).unwrap();
        assert_eq!(decoded, proof);
    }
}
