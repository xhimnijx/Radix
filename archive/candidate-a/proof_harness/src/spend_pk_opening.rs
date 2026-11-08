//! Candidate-A SHAKE256 spend-public-key subrelation.
//!
//! Proves knowledge of a 64-byte spend secret `s` satisfying
//! `pk_s = SHAKE256(Frame("radix/spend-pk/v1"; s), 64)`. The sponge wrapper binds
//! Candidate-A framing, SHAKE256 padding, little-endian absorption and digest bytes around the
//! pinned Plonky3 Keccak-f AIR. This is only one hash subrelation, not a transaction proof.

use core::borrow::Borrow;
use std::{error::Error, fmt, panic::AssertUnwindSafe};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{
    KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows, input_limb,
    output_limb,
};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_uni_stark::{Proof, SubAirBuilder, prove, verify};

use crate::amount_opening::{self, Stark};

type Val = BabyBear;
const DIGEST_BYTES: usize = 64;
const SECRET_BYTES: usize = 64;
const SECRET_BITS: usize = SECRET_BYTES * 8;
const FRAME_BYTES: usize = 95;
const SHAKE_RATE_BYTES: usize = 136;
const SHAKE_RATE_LIMBS: usize = SHAKE_RATE_BYTES / 2;
const NUM_FULL_PERMUTATIONS: usize = 5;
const NUM_PARTIAL_ROUNDS: usize = 8;
const TRACE_ROWS: usize = 128;
const SECRET_OFFSET: usize = NUM_KECCAK_COLS;
const SECRET_BITS_OFFSET: usize = SECRET_OFFSET + SECRET_BYTES;
const TRACE_WIDTH: usize = SECRET_BITS_OFFSET + SECRET_BITS;
const ENVELOPE_MAGIC: &[u8; 8] = b"RDXZSK01";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + DIGEST_BYTES + 4;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_PROOF_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum SpendPkProofError {
    Malformed(&'static str),
    Backend(String),
}

impl fmt::Display for SpendPkProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(formatter, "malformed spend-key proof: {message}"),
            Self::Backend(message) => write!(
                formatter,
                "spend-key proof backend rejected proof: {message}"
            ),
        }
    }
}

impl Error for SpendPkProofError {}

struct SpendPkAir;

impl BaseAir<Val> for SpendPkAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        DIGEST_BYTES / 2
    }
}

impl<AB> Air<AB> for SpendPkAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        {
            let mut sub_builder =
                SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);
            KeccakAir {}.eval(&mut sub_builder);
        }

        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let keccak: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();

        // Secret bytes are explicit witnesses. Boolean decomposition is essential: it ensures
        // each byte is canonical before packing pairs into the Keccak AIR's 16-bit limbs.
        for byte_index in 0..SECRET_BYTES {
            let byte: AB::Expr = row[SECRET_OFFSET + byte_index].into();
            let mut reconstructed = AB::Expr::ZERO;
            for bit_index in 0..8 {
                let bit: AB::Expr = row[SECRET_BITS_OFFSET + byte_index * 8 + bit_index].into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                reconstructed += bit * Val::from_u32(1u32 << bit_index);
            }
            builder.assert_zero(byte - reconstructed);
        }

        // Keep the witness fixed over the full trace, including the partial final permutation.
        for column in SECRET_OFFSET..TRACE_WIDTH {
            builder
                .when_transition()
                .assert_zero(next[column] - row[column]);
        }

        // Bind all 136 SHAKE rate bytes to the exact Candidate-A frame and SHAKE domain padding.
        // The Keccak-f AIR constrains preimage == first-round state and carries it through rounds.
        for limb_index in 0..SHAKE_RATE_LIMBS {
            let byte_index = limb_index * 2;
            let low = frame_and_padding_byte::<AB>(row, byte_index);
            let high = frame_and_padding_byte::<AB>(row, byte_index + 1);
            let expected = low + high * Val::from_u32(256);
            let actual: AB::Expr = row[input_limb(limb_index)].into();
            builder
                .when(keccak.step_flags[0])
                .assert_zero(actual - expected);
        }

        // SHAKE's capacity starts at zero; only the 17 rate lanes absorb the padded message.
        for lane in 17..25 {
            let y = lane / 5;
            let x = lane % 5;
            for limb in 0..4 {
                builder
                    .when(keccak.step_flags[0])
                    .assert_zero(keccak.preimage[y][x][limb]);
            }
        }

        // The first 32 LE u16 words are the first 64 squeezed bytes. Bind each completed
        // Keccak-f permutation's output to canonical u16 public values, not to the unused padding
        // rows or to an assumed final trace row.
        for limb_index in 0..(DIGEST_BYTES / 2) {
            let actual: AB::Expr = row[output_limb(limb_index)].into();
            let expected: AB::Expr = builder.public_values()[limb_index].into();
            builder
                .when(keccak.step_flags[NUM_ROUNDS - 1])
                .assert_zero(actual - expected);
        }
    }
}

fn frame_and_padding_byte<AB>(row: &[AB::Var], offset: usize) -> AB::Expr
where
    AB: AirBuilder<F = Val>,
{
    let constant = |value: u8| AB::Expr::from(Val::from_u32(u32::from(value)));
    match offset {
        0..=4 => constant(b"RADIX"[offset]),
        5 => constant(1),
        6 => constant(17),
        7 => constant(0),
        8..=24 => constant(b"radix/spend-pk/v1"[offset - 8]),
        25 => constant(1),
        26 => constant(0),
        27 => constant(64),
        28..=30 => constant(0),
        31..=94 => row[SECRET_OFFSET + offset - 31].into(),
        95 => constant(0x1f),
        96..=134 => constant(0),
        135 => constant(0x80),
        _ => constant(0),
    }
}

fn padded_shake_state(secret: &[u8; SECRET_BYTES]) -> [u64; 25] {
    let mut frame = [0u8; FRAME_BYTES];
    frame[0..5].copy_from_slice(b"RADIX");
    frame[5] = 1;
    frame[6..8].copy_from_slice(&17u16.to_le_bytes());
    frame[8..25].copy_from_slice(b"radix/spend-pk/v1");
    frame[25..27].copy_from_slice(&1u16.to_le_bytes());
    frame[27..31].copy_from_slice(&(SECRET_BYTES as u32).to_le_bytes());
    frame[31..].copy_from_slice(secret);

    let mut rate = [0u8; SHAKE_RATE_BYTES];
    rate[..FRAME_BYTES].copy_from_slice(&frame);
    rate[FRAME_BYTES] = 0x1f;
    rate[SHAKE_RATE_BYTES - 1] ^= 0x80;

    core::array::from_fn(|lane| {
        if lane < SHAKE_RATE_BYTES / 8 {
            u64::from_le_bytes(rate[lane * 8..lane * 8 + 8].try_into().unwrap())
        } else {
            0
        }
    })
}

fn trace_for(secret: &[u8; SECRET_BYTES]) -> RowMajorMatrix<Val> {
    let state = padded_shake_state(secret);
    let mut permutation_trace = generate_trace_rows::<Val>(vec![state; NUM_FULL_PERMUTATIONS], 0);
    let partial_trace = generate_trace_rows::<Val>(vec![state], 0);
    let full_rows = NUM_FULL_PERMUTATIONS * NUM_ROUNDS;
    debug_assert_eq!(permutation_trace.height(), TRACE_ROWS);
    debug_assert_eq!(full_rows + NUM_PARTIAL_ROUNDS, TRACE_ROWS);
    debug_assert_eq!(partial_trace.height(), 32);
    let padding_start = full_rows * NUM_KECCAK_COLS;
    let partial_end = NUM_PARTIAL_ROUNDS * NUM_KECCAK_COLS;
    permutation_trace.values[padding_start..].copy_from_slice(&partial_trace.values[..partial_end]);

    let mut values = Vec::with_capacity(TRACE_ROWS * TRACE_WIDTH);
    for row_index in 0..TRACE_ROWS {
        let inner_start = row_index * NUM_KECCAK_COLS;
        values.extend_from_slice(
            &permutation_trace.values[inner_start..inner_start + NUM_KECCAK_COLS],
        );
        values.extend(
            secret
                .iter()
                .copied()
                .map(|byte| Val::from_u32(u32::from(byte))),
        );
        for byte in secret {
            for bit_index in 0..8 {
                values.push(Val::from_u32(u32::from((byte >> bit_index) & 1)));
            }
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

fn extract_public_key(trace: &RowMajorMatrix<Val>) -> [u8; DIGEST_BYTES] {
    let final_permutation_row = NUM_FULL_PERMUTATIONS * NUM_ROUNDS - 1;
    let mut digest = [0u8; DIGEST_BYTES];
    for limb_index in 0..(DIGEST_BYTES / 2) {
        let column = output_limb(limb_index);
        let start = final_permutation_row * TRACE_WIDTH + column;
        let limb = trace.values[start].as_canonical_u32() as u16;
        digest[limb_index * 2..limb_index * 2 + 2].copy_from_slice(&limb.to_le_bytes());
    }
    digest
}

fn public_values(public_key: &[u8; DIGEST_BYTES]) -> [Val; DIGEST_BYTES / 2] {
    core::array::from_fn(|index| {
        let word = u16::from_le_bytes([public_key[2 * index], public_key[2 * index + 1]]);
        Val::from_u32(u32::from(word))
    })
}

fn encode_envelope(
    public_key: &[u8; DIGEST_BYTES],
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, SpendPkProofError> {
    let payload = postcard::to_allocvec(proof)
        .map_err(|error| SpendPkProofError::Backend(error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
        return Err(SpendPkProofError::Malformed(
            "proof payload size out of bounds",
        ));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| SpendPkProofError::Malformed("proof payload too large"))?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(ENVELOPE_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    bytes.extend_from_slice(public_key);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_envelope(bytes: &[u8]) -> Result<([u8; DIGEST_BYTES], Proof<Stark>), SpendPkProofError> {
    if bytes.len() < HEADER_BYTES {
        return Err(SpendPkProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(SpendPkProofError::Malformed("envelope exceeds size limit"));
    }
    if &bytes[..8] != ENVELOPE_MAGIC {
        return Err(SpendPkProofError::Malformed("wrong magic"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(SpendPkProofError::Malformed("unsupported envelope version"));
    }
    let public_key: [u8; DIGEST_BYTES] = bytes[10..10 + DIGEST_BYTES].try_into().unwrap();
    let len_start = 10 + DIGEST_BYTES;
    let payload_len =
        u32::from_le_bytes(bytes[len_start..len_start + 4].try_into().unwrap()) as usize;
    if payload_len == 0
        || payload_len > MAX_PROOF_BYTES
        || bytes.len() != HEADER_BYTES + payload_len
    {
        return Err(SpendPkProofError::Malformed(
            "payload length mismatch or trailing bytes",
        ));
    }
    let payload = &bytes[HEADER_BYTES..];
    let decoded = std::panic::catch_unwind(AssertUnwindSafe(|| {
        crate::bounded_postcard::from_proof_bytes(payload)
    }))
    .map_err(|_| SpendPkProofError::Malformed("proof deserializer panicked"))?;
    let proof = decoded.map_err(|_| SpendPkProofError::Malformed("invalid proof serialization"))?;
    let canonical = std::panic::catch_unwind(AssertUnwindSafe(|| {
        postcard::to_extend(
            &proof,
            crate::canonical_postcard::CanonicalBytes::new(payload),
        )
    }))
    .map_err(|_| SpendPkProofError::Malformed("proof serializer panicked"))?
    .map_err(|error| SpendPkProofError::Backend(error.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(SpendPkProofError::Malformed(
            "non-canonical proof serialization",
        ));
    }
    Ok((public_key, proof))
}

/// Prove the Candidate-A spend-public-key hash subrelation for a private 64-byte secret.
pub fn prove_spend_pk(secret: &[u8; SECRET_BYTES]) -> Result<Vec<u8>, SpendPkProofError> {
    prove_spend_pk_with_public_key(secret).map(|(_, proof)| proof)
}

pub(super) fn prove_spend_pk_with_public_key(
    secret: &[u8; SECRET_BYTES],
) -> Result<([u8; DIGEST_BYTES], Vec<u8>), SpendPkProofError> {
    let trace = trace_for(secret);
    let public_key = extract_public_key(&trace);
    // Keep this const explicit: the output is extracted from the last complete permutation.
    debug_assert_eq!(trace.height(), TRACE_ROWS);
    let config = amount_opening::make_config();
    let proof = prove(&config, &SpendPkAir, trace, &public_values(&public_key))
        .map_err(|error| SpendPkProofError::Backend(error.to_string()))?;
    Ok((public_key, encode_envelope(&public_key, &proof)?))
}

/// Verify a proof of knowledge of `s` such that `pk_s = H_spend-pk(s)`.
pub fn verify_spend_pk(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], SpendPkProofError> {
    let (public_key, proof) = decode_envelope(bytes)?;
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify(&config, &SpendPkAir, &proof, &public_values(&public_key))
    }))
    .map_err(|_| SpendPkProofError::Backend("pinned verifier panicked on malformed proof".into()))?
    .map_err(|error| SpendPkProofError::Backend(error.to_string()))?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proves_candidate_a_spend_public_hash_known_answer() {
        let secret = core::array::from_fn(|index| index as u8);
        let proof = prove_spend_pk(&secret).unwrap();
        let public_key = verify_spend_pk(&proof).unwrap();
        assert_eq!(
            public_key,
            hex_array(
                "6790c030ce689c30e5e0f77ecae4cafef32d1babf458e7b2e54d6c1485c8675\
                      76d2b5455f35507e1348e545f4c61f88b65979579d188008690b6e3659ef51559"
            )
        );

        let mut changed_key = proof.clone();
        changed_key[10] ^= 1;
        assert!(verify_spend_pk(&changed_key).is_err());

        let mut changed_proof = proof.clone();
        let midpoint = HEADER_BYTES + (proof.len() - HEADER_BYTES) / 2;
        changed_proof[midpoint] ^= 0x80;
        assert!(verify_spend_pk(&changed_proof).is_err());

        let mut wrong_magic = proof.clone();
        wrong_magic[0] ^= 1;
        assert!(verify_spend_pk(&wrong_magic).is_err());

        let mut wrong_version = proof.clone();
        wrong_version[8] = 2;
        assert!(verify_spend_pk(&wrong_version).is_err());

        assert!(verify_spend_pk(&proof[..proof.len() - 1]).is_err());
        let mut trailing = proof;
        trailing.push(0);
        assert!(verify_spend_pk(&trailing).is_err());
    }

    fn hex_array(text: &str) -> [u8; DIGEST_BYTES] {
        let hex = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap()
        })
    }
}
