//! Candidate-A nullifier hash subrelation over its exact two-block SHAKE256 frame.
//!
//! Proves knowledge of `(spend_secret, kem_shared_secret, rho)` for
//! `nf = SHAKE256(Frame("radix/nullifier/v1", [spend_secret, kem_shared_secret, rho]), 64)`.
//! It does not prove spend-key authorization, KEM decapsulation, note membership, or transaction validity.

use core::borrow::Borrow;
use std::{error::Error, fmt, panic::AssertUnwindSafe};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{
    KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows, output_limb,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, SubAirBuilder, prove, verify};

use crate::amount_opening::{self, Stark};

type Val = BabyBear;
const DIGEST_BYTES: usize = 64;
const PRIVATE_BYTES: usize = 160; // spend_secret64 || kem_shared_secret32 || rho64
const PRIVATE_BITS: usize = PRIVATE_BYTES * 8;
const FRAME_BYTES: usize = 200;
const SHAKE_RATE_BYTES: usize = 136;
const RATE_LIMBS: usize = SHAKE_RATE_BYTES / 2;
const NUM_FULL_PERMUTATIONS: usize = 5;
const NUM_PARTIAL_ROUNDS: usize = 8;
const TRACE_ROWS: usize = 128;
const SECRET_OFFSET: usize = NUM_KECCAK_COLS;
const SECRET_BITS_OFFSET: usize = SECRET_OFFSET + PRIVATE_BYTES;
const OUTPUT_BITS_OFFSET: usize = SECRET_BITS_OFFSET + PRIVATE_BITS;
const OUTPUT_BITS: usize = 25 * 64;
const PHASE_OFFSET: usize = OUTPUT_BITS_OFFSET + OUTPUT_BITS;
const TRACE_WIDTH: usize = PHASE_OFFSET + 1;
const ENVELOPE_MAGIC: &[u8; 8] = b"RDXZNF01";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + DIGEST_BYTES + 4;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_PROOF_BYTES;
const TAG: &[u8] = b"radix/nullifier/v1";

#[derive(Debug, PartialEq, Eq)]
pub enum NullifierProofError {
    Malformed(&'static str),
    Backend(String),
}

impl fmt::Display for NullifierProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => {
                write!(formatter, "malformed nullifier proof: {message}")
            }
            Self::Backend(message) => write!(
                formatter,
                "nullifier proof backend rejected proof: {message}"
            ),
        }
    }
}

impl Error for NullifierProofError {}

struct NullifierAir;

impl BaseAir<Val> for NullifierAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        DIGEST_BYTES
    }
}

impl<AB> Air<AB> for NullifierAir
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
        let next_row = main.next_slice();
        let keccak: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
        let next_keccak: &KeccakCols<AB::Var> = next_row[..NUM_KECCAK_COLS].borrow();
        let phase: AB::Expr = row[PHASE_OFFSET].into();
        let first_step: AB::Expr = keccak.step_flags[0].into();
        let final_step: AB::Expr = keccak.step_flags[NUM_ROUNDS - 1].into();
        let one = AB::Expr::ONE;
        let transition = builder.is_transition();

        builder.assert_zero(phase.clone() * (phase.clone() - one.clone()));

        // Private fields and their byte decompositions are row-invariant.
        for column in SECRET_OFFSET..(SECRET_BITS_OFFSET + PRIVATE_BITS) {
            let current: AB::Expr = row[column].into();
            let following: AB::Expr = next_row[column].into();
            builder
                .when(transition.clone())
                .assert_zero(following - current);
        }
        // Every private byte is range-constrained to 8 bits.
        for byte_index in 0..PRIVATE_BYTES {
            let mut reconstructed = AB::Expr::ZERO;
            for bit_index in 0..8 {
                let bit: AB::Expr = row[SECRET_BITS_OFFSET + byte_index * 8 + bit_index].into();
                builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
                reconstructed += bit * AB::Expr::from_u32(1 << bit_index);
            }
            let byte: AB::Expr = row[SECRET_OFFSET + byte_index].into();
            builder.assert_zero(reconstructed - byte);
        }

        // Decompose every Keccak output lane so the inter-block absorption uses a constrained
        // bitwise XOR rather than field addition.
        for y in 0..5 {
            for x in 0..5 {
                let lane = y * 5 + x;
                for limb in 0..4 {
                    let mut reconstructed = AB::Expr::ZERO;
                    for bit_index in 0..16 {
                        let bit_column = OUTPUT_BITS_OFFSET + lane * 64 + limb * 16 + bit_index;
                        let bit: AB::Expr = row[bit_column].into();
                        builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
                        reconstructed += bit * AB::Expr::from_u32(1 << bit_index);
                    }
                    let output: AB::Expr = keccak.a_prime_prime_prime(y, x, limb).into();
                    builder.assert_zero(reconstructed - output);
                }
            }
        }

        // Toggle the absorption phase exactly at each complete Keccak permutation boundary.
        let next_phase: AB::Expr = next_row[PHASE_OFFSET].into();
        builder
            .when(transition.clone() * (one.clone() - final_step.clone()))
            .assert_zero(next_phase.clone() - phase.clone());
        builder
            .when(transition.clone() * final_step.clone())
            .assert_zero(next_phase - (one.clone() - phase.clone()));

        // First-block permutations all begin from the exact first 136 frame bytes and a zero
        // capacity. The 200-byte frame places suffix/final padding in block two.
        let first_block_start = first_step.clone() * (one.clone() - phase.clone());
        for limb in 0..RATE_LIMBS {
            let low = padded_frame_byte::<AB>(row, limb * 2);
            let high = padded_frame_byte::<AB>(row, limb * 2 + 1);
            let expected = low + high * AB::Expr::from_u32(256);
            builder
                .when(first_block_start.clone())
                .assert_zero(keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4] - expected);
        }
        for y in 0..5 {
            for x in 0..5 {
                for limb in 0..4 {
                    let state_limb = y * 20 + x * 4 + limb;
                    if state_limb >= RATE_LIMBS {
                        builder
                            .when(first_block_start.clone())
                            .assert_zero(keccak.preimage[y][x][limb]);
                    }
                }
            }
        }

        // When a first block ends, bind the next permutation's full 1600-bit preimage to
        // `Keccak(state) XOR padded_second_block`. This covers the full 200-byte state,
        // including the unchanged capacity lanes.
        let second_block_boundary = transition * final_step.clone() * (one.clone() - phase.clone());
        for y in 0..5 {
            for x in 0..5 {
                let lane = y * 5 + x;
                for limb in 0..4 {
                    let mut expected = AB::Expr::ZERO;
                    for bit_index in 0..16 {
                        let output_bit: AB::Expr =
                            row[OUTPUT_BITS_OFFSET + lane * 64 + limb * 16 + bit_index].into();
                        let state_byte = lane * 8 + limb * 2 + bit_index / 8;
                        let block_bit: AB::Expr = padded_frame_bit::<AB>(
                            next_row,
                            SHAKE_RATE_BYTES + state_byte,
                            bit_index % 8,
                        );
                        let xor = output_bit.clone() + block_bit.clone()
                            - output_bit * block_bit * AB::Expr::from_u32(2);
                        expected += xor * AB::Expr::from_u32(1 << bit_index);
                    }
                    builder
                        .when(second_block_boundary.clone())
                        .assert_zero(next_keccak.preimage[y][x][limb] - expected);
                }
            }
        }

        // Bind the 64-byte SHAKE digest after every complete second-block permutation.
        let digest_selector = final_step * phase;
        for limb in 0..(DIGEST_BYTES / 2) {
            let low: AB::Expr = builder.public_values()[limb * 2].into();
            let high: AB::Expr = builder.public_values()[limb * 2 + 1].into();
            let expected = low + high * AB::Expr::from_u32(256);
            let actual: AB::Expr = row[output_limb(limb)].into();
            builder
                .when(digest_selector.clone())
                .assert_zero(actual - expected);
        }
    }
}

fn private_byte_index(frame_offset: usize) -> Option<usize> {
    match frame_offset {
        32..=95 => Some(frame_offset - 32),
        100..=131 => Some(64 + frame_offset - 100),
        136..=199 => Some(96 + frame_offset - 136),
        _ => None,
    }
}

fn constant_frame_byte(frame_offset: usize) -> u8 {
    match frame_offset {
        0..=4 => b"RADIX"[frame_offset],
        5 => 1,
        6 => TAG.len() as u8,
        7 => 0,
        8..=25 => TAG[frame_offset - 8],
        26 => 3,
        27 => 0,
        28 => 64,
        29..=31 => 0,
        96 => 32,
        97..=99 => 0,
        132 => 64,
        133..=135 => 0,
        _ => 0,
    }
}

fn padded_frame_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], offset: usize) -> AB::Expr {
    if offset < FRAME_BYTES {
        if let Some(index) = private_byte_index(offset) {
            row[SECRET_OFFSET + index].into()
        } else {
            AB::Expr::from_u32(u32::from(constant_frame_byte(offset)))
        }
    } else if offset == FRAME_BYTES {
        AB::Expr::from_u32(0x1f)
    } else if offset == 2 * SHAKE_RATE_BYTES - 1 {
        AB::Expr::from_u32(0x80)
    } else {
        AB::Expr::ZERO
    }
}

fn padded_frame_bit<AB: AirBuilder<F = Val>>(
    row: &[AB::Var],
    offset: usize,
    bit_index: usize,
) -> AB::Expr {
    if offset < FRAME_BYTES {
        if let Some(index) = private_byte_index(offset) {
            row[SECRET_BITS_OFFSET + index * 8 + bit_index].into()
        } else {
            AB::Expr::from_u32(u32::from((constant_frame_byte(offset) >> bit_index) & 1))
        }
    } else if offset == FRAME_BYTES {
        AB::Expr::from_u32(u32::from((0x1fu8 >> bit_index) & 1))
    } else if offset == 2 * SHAKE_RATE_BYTES - 1 {
        AB::Expr::from_u32(u32::from((0x80u8 >> bit_index) & 1))
    } else {
        AB::Expr::ZERO
    }
}

pub(super) fn frame_for(
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    rho: &[u8; 64],
) -> [u8; FRAME_BYTES] {
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    frame.extend_from_slice(b"RADIX");
    frame.push(1);
    frame.extend_from_slice(&(TAG.len() as u16).to_le_bytes());
    frame.extend_from_slice(TAG);
    frame.extend_from_slice(&3u16.to_le_bytes());
    for field in [
        spend_secret.as_slice(),
        kem_shared_secret.as_slice(),
        rho.as_slice(),
    ] {
        frame.extend_from_slice(&(field.len() as u32).to_le_bytes());
        frame.extend_from_slice(field);
    }
    frame
        .try_into()
        .expect("Candidate-A nullifier frame has fixed length")
}

pub(super) fn block_state(frame: &[u8; FRAME_BYTES], block_index: usize) -> [u64; 25] {
    let mut block = [0u8; SHAKE_RATE_BYTES];
    let start = block_index * SHAKE_RATE_BYTES;
    for (offset, byte) in block.iter_mut().enumerate() {
        let global = start + offset;
        *byte = if global < FRAME_BYTES {
            frame[global]
        } else if global == FRAME_BYTES {
            0x1f
        } else if global == 2 * SHAKE_RATE_BYTES - 1 {
            0x80
        } else {
            0
        };
    }
    let mut state = [0u64; 25];
    for (lane, chunk) in block.chunks_exact(8).enumerate() {
        state[lane] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    state
}

fn state_after_one_permutation(state: &[u64; 25]) -> [u64; 25] {
    let trace = generate_trace_rows::<Val>(vec![*state], 0);
    let final_row = &trace.values[(NUM_ROUNDS - 1) * NUM_KECCAK_COLS..NUM_ROUNDS * NUM_KECCAK_COLS];
    let cols: &KeccakCols<Val> = final_row.borrow();
    let mut output = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            let lane = y * 5 + x;
            let mut bytes = [0u8; 8];
            for limb in 0..4 {
                let value = u16::try_from(cols.a_prime_prime_prime(y, x, limb).as_canonical_u32())
                    .expect("Keccak output limb is 16-bit");
                bytes[limb * 2..limb * 2 + 2].copy_from_slice(&value.to_le_bytes());
            }
            output[lane] = u64::from_le_bytes(bytes);
        }
    }
    output
}

fn xor_states(left: [u64; 25], right: [u64; 25]) -> [u64; 25] {
    core::array::from_fn(|index| left[index] ^ right[index])
}

fn private_bytes(
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    rho: &[u8; 64],
) -> [u8; PRIVATE_BYTES] {
    let mut bytes = [0u8; PRIVATE_BYTES];
    bytes[..64].copy_from_slice(spend_secret);
    bytes[64..96].copy_from_slice(kem_shared_secret);
    bytes[96..].copy_from_slice(rho);
    bytes
}

fn build_trace(
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    rho: &[u8; 64],
) -> (RowMajorMatrix<Val>, [u8; DIGEST_BYTES]) {
    let frame = frame_for(spend_secret, kem_shared_secret, rho);
    let first_state = block_state(&frame, 0);
    let second_block = block_state(&frame, 1);
    let second_state = xor_states(state_after_one_permutation(&first_state), second_block);
    let permutation_inputs = vec![
        first_state,
        second_state,
        first_state,
        second_state,
        first_state,
    ];
    let full = generate_trace_rows::<Val>(permutation_inputs, 0);
    let partial = generate_trace_rows::<Val>(vec![second_state], 0);
    let mut trace = vec![Val::ZERO; TRACE_ROWS * TRACE_WIDTH];
    for row in 0..(NUM_FULL_PERMUTATIONS * NUM_ROUNDS) {
        let src = row * NUM_KECCAK_COLS;
        let dst = row * TRACE_WIDTH;
        trace[dst..dst + NUM_KECCAK_COLS].copy_from_slice(&full.values[src..src + NUM_KECCAK_COLS]);
    }
    for row in 0..NUM_PARTIAL_ROUNDS {
        let src = row * NUM_KECCAK_COLS;
        let dst = (NUM_FULL_PERMUTATIONS * NUM_ROUNDS + row) * TRACE_WIDTH;
        trace[dst..dst + NUM_KECCAK_COLS]
            .copy_from_slice(&partial.values[src..src + NUM_KECCAK_COLS]);
    }

    let private = private_bytes(spend_secret, kem_shared_secret, rho);
    for row in 0..TRACE_ROWS {
        let row_start = row * TRACE_WIDTH;
        let row_values = &mut trace[row_start..row_start + TRACE_WIDTH];
        for (index, byte) in private.iter().enumerate() {
            row_values[SECRET_OFFSET + index] = Val::from_u32(u32::from(*byte));
            for bit in 0..8 {
                row_values[SECRET_BITS_OFFSET + index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
        let mut output_bit_values = [0u32; OUTPUT_BITS];
        {
            let keccak_cols: &KeccakCols<Val> = row_values[..NUM_KECCAK_COLS].borrow();
            for y in 0..5 {
                for x in 0..5 {
                    let lane = y * 5 + x;
                    for limb in 0..4 {
                        let limb_value = keccak_cols
                            .a_prime_prime_prime(y, x, limb)
                            .as_canonical_u32();
                        for bit in 0..16 {
                            output_bit_values[lane * 64 + limb * 16 + bit] =
                                (limb_value >> bit) & 1;
                        }
                    }
                }
            }
        }
        for (index, bit) in output_bit_values.iter().enumerate() {
            row_values[OUTPUT_BITS_OFFSET + index] = Val::from_u32(*bit);
        }
        row_values[PHASE_OFFSET] = Val::from_u32(((row / NUM_ROUNDS) % 2) as u32);
    }

    let digest_row_index = 3 * NUM_ROUNDS + NUM_ROUNDS - 1;
    let digest_start = digest_row_index * TRACE_WIDTH;
    let digest_cols: &KeccakCols<Val> =
        trace[digest_start..digest_start + NUM_KECCAK_COLS].borrow();
    let mut digest = [0u8; DIGEST_BYTES];
    for limb in 0..(DIGEST_BYTES / 2) {
        let value = u16::try_from(
            digest_cols
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .as_canonical_u32(),
        )
        .expect("digest output limb is 16-bit");
        digest[limb * 2..limb * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    (RowMajorMatrix::new(trace, TRACE_WIDTH), digest)
}

fn encode_envelope(
    digest: &[u8; DIGEST_BYTES],
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, NullifierProofError> {
    let payload = postcard::to_allocvec(proof)
        .map_err(|error| NullifierProofError::Backend(error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
        return Err(NullifierProofError::Malformed("proof size out of bounds"));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| NullifierProofError::Malformed("proof too large"))?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(ENVELOPE_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    bytes.extend_from_slice(digest);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_envelope(
    bytes: &[u8],
) -> Result<([u8; DIGEST_BYTES], Proof<Stark>), NullifierProofError> {
    if bytes.len() < HEADER_BYTES {
        return Err(NullifierProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(NullifierProofError::Malformed(
            "envelope exceeds size limit",
        ));
    }
    if &bytes[..8] != ENVELOPE_MAGIC {
        return Err(NullifierProofError::Malformed("wrong magic"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(NullifierProofError::Malformed("unsupported version"));
    }
    let digest = bytes[10..10 + DIGEST_BYTES].try_into().unwrap();
    let payload_len =
        u32::from_le_bytes(bytes[10 + DIGEST_BYTES..HEADER_BYTES].try_into().unwrap()) as usize;
    if payload_len == 0
        || payload_len > MAX_PROOF_BYTES
        || bytes.len() != HEADER_BYTES + payload_len
    {
        return Err(NullifierProofError::Malformed("proof length mismatch"));
    }
    let payload = &bytes[HEADER_BYTES..];
    let proof: Proof<Stark> = std::panic::catch_unwind(AssertUnwindSafe(|| {
        crate::bounded_postcard::from_proof_bytes(payload)
    }))
    .map_err(|_| NullifierProofError::Malformed("proof deserializer panicked"))?
    .map_err(|_| NullifierProofError::Malformed("invalid proof serialization"))?;
    let canonical = std::panic::catch_unwind(AssertUnwindSafe(|| {
        postcard::to_extend(
            &proof,
            crate::canonical_postcard::CanonicalBytes::new(payload),
        )
    }))
    .map_err(|_| NullifierProofError::Malformed("proof serializer panicked"))?
    .map_err(|error| NullifierProofError::Backend(error.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(NullifierProofError::Malformed(
            "non-canonical proof serialization",
        ));
    }
    Ok((digest, proof))
}

/// Prove knowledge of a Candidate-A nullifier preimage.
pub fn prove_nullifier(
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    rho: &[u8; 64],
) -> Result<Vec<u8>, NullifierProofError> {
    prove_nullifier_with_output(spend_secret, kem_shared_secret, rho).map(|(_, envelope)| envelope)
}

pub(super) fn prove_nullifier_with_output(
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    rho: &[u8; 64],
) -> Result<([u8; DIGEST_BYTES], Vec<u8>), NullifierProofError> {
    let (trace, digest) = build_trace(spend_secret, kem_shared_secret, rho);
    let config = amount_opening::make_config();
    let public_values = digest
        .iter()
        .map(|byte| Val::from_u32(u32::from(*byte)))
        .collect::<Vec<_>>();
    let proof = prove(&config, &NullifierAir, trace, &public_values)
        .map_err(|error| NullifierProofError::Backend(error.to_string()))?;
    Ok((digest, encode_envelope(&digest, &proof)?))
}

/// Verify a fixed two-block Candidate-A nullifier preimage proof and return the nullifier.
pub fn verify_nullifier(bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], NullifierProofError> {
    let (digest, proof) = decode_envelope(bytes)?;
    let config = amount_opening::make_config();
    let public_values = digest
        .iter()
        .map(|byte| Val::from_u32(u32::from(*byte)))
        .collect::<Vec<_>>();
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify(&config, &NullifierAir, &proof, &public_values)
    }))
    .map_err(|_| NullifierProofError::Malformed("proof verifier panicked"))?
    .map_err(|error| NullifierProofError::Backend(error.to_string()))?;
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proves_candidate_a_nullifier_known_answer_and_rejects_tampering() {
        let spend_secret = core::array::from_fn(|index| index as u8);
        let shared_secret = core::array::from_fn(|index| index as u8);
        let rho = core::array::from_fn(|index| index as u8);
        let proof = prove_nullifier(&spend_secret, &shared_secret, &rho).unwrap();
        let expected = hex_array(
            "1667f9f61253f15353231b57c4357c0c16d1397d676a76c9ac2fa297446789c6703ed9babc107c635d07d983b00252725011aa0d58af95bef4b467dce795ac8e",
        );
        assert_eq!(verify_nullifier(&proof).unwrap(), expected);

        let mut changed_statement = proof.clone();
        changed_statement[10] ^= 1;
        assert!(verify_nullifier(&changed_statement).is_err());
        let mut changed_payload = proof.clone();
        changed_payload[HEADER_BYTES + 7] ^= 1;
        assert!(verify_nullifier(&changed_payload).is_err());
        let mut wrong_magic = proof.clone();
        wrong_magic[0] ^= 1;
        assert!(verify_nullifier(&wrong_magic).is_err());
        let mut wrong_version = proof.clone();
        wrong_version[8] = 2;
        assert!(verify_nullifier(&wrong_version).is_err());
        assert!(verify_nullifier(&proof[..HEADER_BYTES - 1]).is_err());
        let mut trailing = proof;
        trailing.push(0);
        assert!(verify_nullifier(&trailing).is_err());
    }

    #[test]
    fn rejects_a_witness_that_mislabels_the_second_absorption_block() {
        let spend_secret = [0x42u8; 64];
        let shared_secret = [0x24u8; 32];
        let rho = [0x81u8; 64];
        let (mut trace, digest) = build_trace(&spend_secret, &shared_secret, &rho);
        // The second permutation begins at row 24. It must be phase 1, following phase 0.
        trace.values[24 * TRACE_WIDTH + PHASE_OFFSET] = Val::ZERO;
        let public_values = digest
            .iter()
            .map(|byte| Val::from_u32(u32::from(*byte)))
            .collect::<Vec<_>>();
        let config = amount_opening::make_config();
        let attempt = std::panic::catch_unwind(AssertUnwindSafe(|| {
            prove(&config, &NullifierAir, trace, &public_values)
        }));
        if let Ok(Ok(proof)) = attempt {
            let verified = std::panic::catch_unwind(AssertUnwindSafe(|| {
                verify(&config, &NullifierAir, &proof, &public_values)
            }));
            assert!(
                !matches!(verified, Ok(Ok(()))),
                "a phase-substitution witness must not verify"
            );
        }
    }

    #[test]
    fn rejects_a_different_well_formed_private_preimage() {
        let spend_secret = [0x42u8; 64];
        let shared_secret = [0x24u8; 32];
        let rho = [0x81u8; 64];
        let (mut trace, digest) = build_trace(&spend_secret, &shared_secret, &rho);
        // Change one private byte consistently across all rows and keep its Boolean
        // decomposition valid. The unchanged public digest must no longer verify.
        for row in 0..TRACE_ROWS {
            let row_start = row * TRACE_WIDTH;
            let old = trace.values[row_start + SECRET_OFFSET].as_canonical_u32() as u8;
            let changed = old ^ 1;
            trace.values[row_start + SECRET_OFFSET] = Val::from_u32(u32::from(changed));
            for bit in 0..8 {
                trace.values[row_start + SECRET_BITS_OFFSET + bit] =
                    Val::from_u32(u32::from((changed >> bit) & 1));
            }
        }
        let public_values = digest
            .iter()
            .map(|byte| Val::from_u32(u32::from(*byte)))
            .collect::<Vec<_>>();
        let config = amount_opening::make_config();
        let attempt = std::panic::catch_unwind(AssertUnwindSafe(|| {
            prove(&config, &NullifierAir, trace, &public_values)
        }));
        if let Ok(Ok(proof)) = attempt {
            let verified = std::panic::catch_unwind(AssertUnwindSafe(|| {
                verify(&config, &NullifierAir, &proof, &public_values)
            }));
            assert!(
                !matches!(verified, Ok(Ok(()))),
                "a different private preimage must not verify against the original digest"
            );
        }
    }

    fn hex_array(text: &str) -> [u8; DIGEST_BYTES] {
        core::array::from_fn(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()
        })
    }
}
