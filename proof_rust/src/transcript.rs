//! The Fiat-Shamir transcript, mirroring `radix_core/.../transcript.py`.
//!
//! Absorb-then-squeeze with length-prefixed framing over SHAKE256. Every part is
//! kept and re-hashed on each squeeze, exactly as the Python does, so the two
//! derivations agree byte for byte. That matters more than it sounds: if the
//! prover and verifier derive different challenges the proof simply never verifies,
//! and the failure looks like a maths bug rather than a transcript bug.

use crate::sha3::shake256;

pub const TAG: &[u8] = b"radix/b/lattice/transcript/v1";

#[derive(Clone)]
pub struct Transcript {
    domain: Vec<u8>,
    parts: Vec<u8>,
}

fn frame_into(out: &mut Vec<u8>, label: &[u8], payload: &[u8]) {
    assert!(label.len() <= 255, "labels are limited to 255 bytes");
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

impl Transcript {
    pub fn new(domain: &[u8]) -> Transcript {
        let mut parts = Vec::new();
        parts.extend_from_slice(TAG);
        frame_into(&mut parts, b"domain", domain);
        Transcript {
            domain: domain.to_vec(),
            parts,
        }
    }

    pub fn absorb(&mut self, label: &[u8], payload: &[u8]) -> &mut Self {
        frame_into(&mut self.parts, label, payload);
        self
    }

    pub fn absorb_poly(&mut self, label: &[u8], poly: &[u64]) -> &mut Self {
        let mut payload = Vec::with_capacity(poly.len() * 4);
        for value in poly {
            payload.extend_from_slice(&(*value as u32).to_le_bytes());
        }
        self.absorb(label, &payload)
    }

    pub fn challenge(&mut self, label: &[u8], length: usize) -> Vec<u8> {
        let mut request = Vec::with_capacity(label.len() + 4);
        request.extend_from_slice(label);
        request.extend_from_slice(&(length as u32).to_le_bytes());

        let mut input = self.parts.clone();
        frame_into(&mut input, b"squeeze-request", &request);

        let mut value = vec![0u8; length];
        shake256(&input, &mut value);

        let mut announced = request.clone();
        announced.extend_from_slice(&value);
        frame_into(&mut self.parts, b"squeeze", &announced);
        value
    }

    /// A sparse ternary challenge with exactly `weight` non-zero coefficients.
    pub fn challenge_ternary(&mut self, label: &[u8], degree: usize, weight: usize) -> Vec<i64> {
        assert!(weight >= 1 && weight <= degree, "1 <= weight <= degree");
        let needed = 8 * (2 * weight + 4);
        let mut stream: Vec<u8> = Vec::new();
        while stream.len() < needed {
            stream.extend_from_slice(&self.challenge(label, 64));
        }

        let mut positions: Vec<usize> = (0..degree).collect();
        let mut coefficients = vec![0i64; degree];
        let mut cursor = 0usize;
        for _ in 0..weight {
            let raw = u32::from_le_bytes([
                stream[cursor],
                stream[cursor + 1],
                stream[cursor + 2],
                stream[cursor + 3],
            ]) as usize;
            cursor += 4;
            let index = raw % positions.len();
            let position = positions.remove(index);
            coefficients[position] = if stream[cursor] & 1 == 1 { 1 } else { -1 };
            cursor += 1;
        }
        coefficients
    }

    pub fn domain(&self) -> &[u8] {
        &self.domain
    }
}

#[cfg(test)]
mod tests {
    use super::Transcript;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn challenges_match_the_python_reference() {
        let mut transcript = Transcript::new(b"radix/test");
        transcript.absorb(b"alpha", b"one");
        transcript.absorb(b"beta", b"two");
        let first = transcript.challenge(b"c", 32);
        assert_eq!(
            hex(&first),
            "628b9291e1253d0da8a77e57de19073e501fe26189023025fae49639421ae6e4"
        );
        // the second squeeze must advance, not repeat
        let second = transcript.challenge(b"c", 8);
        assert_eq!(hex(&second), "b427c3e015135639");
    }

    #[test]
    fn ternary_challenges_match_the_python_reference() {
        let mut transcript = Transcript::new(b"d");
        let coefficients = transcript.challenge_ternary(b"g", 16, 3);
        assert_eq!(
            coefficients,
            vec![0, -1, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_different_domain_gives_a_different_challenge() {
        let mut one = Transcript::new(b"one");
        let mut two = Transcript::new(b"two");
        assert_ne!(one.challenge(b"c", 16), two.challenge(b"c", 16));
    }

    #[test]
    fn absorbing_after_a_squeeze_changes_the_stream() {
        let mut transcript = Transcript::new(b"d");
        let first = transcript.challenge(b"c", 16);
        transcript.absorb(b"more", b"data");
        assert_ne!(first, transcript.challenge(b"c", 16));
    }
}
