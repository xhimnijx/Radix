//! Candidate-A tree-node hash opening over its exact two-block SHAKE256 frame.
//!
//! Proves knowledge of `(left, right)` for
//! `parent = SHAKE256(Frame("radix/tree-node/v1", [level, left, right]), 64)`.
//! This standalone node hash does not prove a Merkle path or transaction validity.

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
const PRIVATE_BYTES: usize = 129; // level8 || left64 || right64
const PRIVATE_BITS: usize = PRIVATE_BYTES * 8;
const FRAME_BYTES: usize = 169;
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
const ENVELOPE_MAGIC: &[u8; 8] = b"RDXZTN01";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + 1 + DIGEST_BYTES + 4;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_PROOF_BYTES;
const TAG: &[u8] = b"radix/tree-node/v1";

#[derive(Debug, PartialEq, Eq)]
pub enum TreeNodeProofError {
    Malformed(&'static str),
    Backend(String),
}

impl fmt::Display for TreeNodeProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => {
                write!(formatter, "malformed tree-node proof: {message}")
            }
            Self::Backend(message) => write!(
                formatter,
                "tree-node proof backend rejected proof: {message}"
            ),
        }
    }
}

impl Error for TreeNodeProofError {}

struct TreeNodeAir;

impl BaseAir<Val> for TreeNodeAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        DIGEST_BYTES + 1
    }
}

impl<AB> Air<AB> for TreeNodeAir
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

        // Bind the private level byte to the public level and ensure it is a byte via the
        // private-byte range constraints above.
        let public_level: AB::Expr = builder.public_values()[0].into();
        let private_level: AB::Expr = row[SECRET_OFFSET].into();
        builder.assert_zero(private_level - public_level);
        for bit in 6..8 {
            builder.assert_zero(row[SECRET_BITS_OFFSET + bit].into());
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
            let low: AB::Expr = builder.public_values()[1 + limb * 2].into();
            let high: AB::Expr = builder.public_values()[2 + limb * 2].into();
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
        32 => Some(0),
        37..=100 => Some(frame_offset - 36),
        105..=168 => Some(65 + frame_offset - 105),
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
        28 => 1,
        29..=31 => 0,
        33 => 64,
        34..=36 => 0,
        101 => 64,
        102..=104 => 0,
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

fn frame_for(level: u8, left: &[u8; 64], right: &[u8; 64]) -> [u8; FRAME_BYTES] {
    let mut frame = Vec::with_capacity(FRAME_BYTES);
    frame.extend_from_slice(b"RADIX");
    frame.push(1);
    frame.extend_from_slice(&(TAG.len() as u16).to_le_bytes());
    frame.extend_from_slice(TAG);
    frame.extend_from_slice(&3u16.to_le_bytes());
    for field in [&[level][..], left.as_slice(), right.as_slice()] {
        frame.extend_from_slice(&(field.len() as u32).to_le_bytes());
        frame.extend_from_slice(field);
    }
    frame
        .try_into()
        .expect("Candidate-A tree-node frame has fixed length")
}

fn block_state(frame: &[u8; FRAME_BYTES], block_index: usize) -> [u64; 25] {
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

fn private_bytes(level: u8, left: &[u8; 64], right: &[u8; 64]) -> [u8; PRIVATE_BYTES] {
    let mut bytes = [0u8; PRIVATE_BYTES];
    bytes[0] = level;
    bytes[1..65].copy_from_slice(left);
    bytes[65..].copy_from_slice(right);
    bytes
}

fn build_trace(
    level: u8,
    left: &[u8; 64],
    right: &[u8; 64],
) -> (RowMajorMatrix<Val>, [u8; DIGEST_BYTES]) {
    let frame = frame_for(level, left, right);
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

    let private = private_bytes(level, left, right);
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
    level: u8,
    digest: &[u8; DIGEST_BYTES],
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, TreeNodeProofError> {
    let payload = postcard::to_allocvec(proof)
        .map_err(|error| TreeNodeProofError::Backend(error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
        return Err(TreeNodeProofError::Malformed("proof size out of bounds"));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| TreeNodeProofError::Malformed("proof too large"))?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(ENVELOPE_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    bytes.push(level);
    bytes.extend_from_slice(digest);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_envelope(
    bytes: &[u8],
) -> Result<(u8, [u8; DIGEST_BYTES], Proof<Stark>), TreeNodeProofError> {
    if bytes.len() < HEADER_BYTES {
        return Err(TreeNodeProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(TreeNodeProofError::Malformed("envelope exceeds size limit"));
    }
    if &bytes[..8] != ENVELOPE_MAGIC {
        return Err(TreeNodeProofError::Malformed("wrong magic"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(TreeNodeProofError::Malformed("unsupported version"));
    }
    let level = bytes[10];
    if level >= 64 {
        return Err(TreeNodeProofError::Malformed("tree level out of range"));
    }
    let digest = bytes[11..11 + DIGEST_BYTES].try_into().unwrap();
    let payload_len =
        u32::from_le_bytes(bytes[11 + DIGEST_BYTES..HEADER_BYTES].try_into().unwrap()) as usize;
    if payload_len == 0
        || payload_len > MAX_PROOF_BYTES
        || bytes.len() != HEADER_BYTES + payload_len
    {
        return Err(TreeNodeProofError::Malformed("proof length mismatch"));
    }
    let payload = &bytes[HEADER_BYTES..];
    let proof: Proof<Stark> = std::panic::catch_unwind(AssertUnwindSafe(|| {
        crate::bounded_postcard::from_proof_bytes(payload)
    }))
    .map_err(|_| TreeNodeProofError::Malformed("proof deserializer panicked"))?
    .map_err(|_| TreeNodeProofError::Malformed("invalid proof serialization"))?;
    let canonical = std::panic::catch_unwind(AssertUnwindSafe(|| {
        postcard::to_extend(
            &proof,
            crate::canonical_postcard::CanonicalBytes::new(payload),
        )
    }))
    .map_err(|_| TreeNodeProofError::Malformed("proof serializer panicked"))?
    .map_err(|error| TreeNodeProofError::Backend(error.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(TreeNodeProofError::Malformed(
            "non-canonical proof serialization",
        ));
    }
    Ok((level, digest, proof))
}

/// Prove knowledge of two child digests for one Candidate-A Merkle-tree node.
pub fn prove_tree_node(
    level: u8,
    left: &[u8; 64],
    right: &[u8; 64],
) -> Result<Vec<u8>, TreeNodeProofError> {
    prove_tree_node_with_output(level, left, right).map(|(_, envelope)| envelope)
}

pub(super) fn prove_tree_node_with_output(
    level: u8,
    left: &[u8; 64],
    right: &[u8; 64],
) -> Result<([u8; DIGEST_BYTES], Vec<u8>), TreeNodeProofError> {
    if level >= 64 {
        return Err(TreeNodeProofError::Malformed("tree level out of range"));
    }
    let (trace, digest) = build_trace(level, left, right);
    let config = amount_opening::make_config();
    let mut public_values = vec![Val::from_u32(u32::from(level))];
    public_values.extend(digest.iter().map(|byte| Val::from_u32(u32::from(*byte))));
    let proof = prove(&config, &TreeNodeAir, trace, &public_values)
        .map_err(|error| TreeNodeProofError::Backend(error.to_string()))?;
    Ok((digest, encode_envelope(level, &digest, &proof)?))
}

/// Verify one two-block Candidate-A tree-node hash opening.
pub fn verify_tree_node(bytes: &[u8]) -> Result<(u8, [u8; DIGEST_BYTES]), TreeNodeProofError> {
    let (level, digest, proof) = decode_envelope(bytes)?;
    let config = amount_opening::make_config();
    let mut public_values = vec![Val::from_u32(u32::from(level))];
    public_values.extend(digest.iter().map(|byte| Val::from_u32(u32::from(*byte))));
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify(&config, &TreeNodeAir, &proof, &public_values)
    }))
    .map_err(|_| TreeNodeProofError::Malformed("proof verifier panicked"))?
    .map_err(|error| TreeNodeProofError::Backend(error.to_string()))?;
    Ok((level, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_values(level: u8, digest: &[u8; DIGEST_BYTES]) -> Vec<Val> {
        let mut values = vec![Val::from_u32(u32::from(level))];
        values.extend(digest.iter().map(|byte| Val::from_u32(u32::from(*byte))));
        values
    }

    #[test]
    fn proves_candidate_a_tree_node_known_answer_and_rejects_tampering() {
        let level = 7;
        let left = core::array::from_fn(|index| index as u8);
        let right = core::array::from_fn(|index| 255 - index as u8);
        let proof = prove_tree_node(level, &left, &right).unwrap();
        let expected = hex_array(
            "67cc9f0461f75c64da846f4b7b851240d9d21976c627988676d74789bfb58db35409cd8e969dca0dc0de653f8219ecf7df30e79d22d7529246677d98df4d3232",
        );
        assert_eq!(verify_tree_node(&proof).unwrap(), (level, expected));

        let mut changed_level = proof.clone();
        changed_level[10] ^= 1;
        assert!(verify_tree_node(&changed_level).is_err());
        let mut changed_digest = proof.clone();
        changed_digest[11] ^= 1;
        assert!(verify_tree_node(&changed_digest).is_err());
        let mut changed_payload = proof.clone();
        changed_payload[HEADER_BYTES + 7] ^= 1;
        assert!(verify_tree_node(&changed_payload).is_err());
        let mut wrong_magic = proof.clone();
        wrong_magic[0] ^= 1;
        assert!(verify_tree_node(&wrong_magic).is_err());
        let mut wrong_version = proof.clone();
        wrong_version[8] = 2;
        assert!(verify_tree_node(&wrong_version).is_err());
        assert!(verify_tree_node(&proof[..HEADER_BYTES - 1]).is_err());
        let mut trailing = proof;
        trailing.push(0);
        assert!(verify_tree_node(&trailing).is_err());
    }

    #[test]
    fn rejects_a_witness_that_mislabels_the_second_absorption_block() {
        let level = 3;
        let left = [0x42u8; 64];
        let right = [0x24u8; 64];
        let (mut trace, digest) = build_trace(level, &left, &right);
        trace.values[24 * TRACE_WIDTH + PHASE_OFFSET] = Val::ZERO;
        let values = public_values(level, &digest);
        let config = amount_opening::make_config();
        let attempt = std::panic::catch_unwind(AssertUnwindSafe(|| {
            prove(&config, &TreeNodeAir, trace, &values)
        }));
        if let Ok(Ok(proof)) = attempt {
            let verified = std::panic::catch_unwind(AssertUnwindSafe(|| {
                verify(&config, &TreeNodeAir, &proof, &values)
            }));
            assert!(
                !matches!(verified, Ok(Ok(()))),
                "phase substitution must fail"
            );
        }
    }

    #[test]
    fn rejects_a_different_well_formed_private_preimage() {
        let level = 9;
        let left = [0x42u8; 64];
        let right = [0x24u8; 64];
        let (mut trace, digest) = build_trace(level, &left, &right);
        for row in 0..TRACE_ROWS {
            let row_start = row * TRACE_WIDTH;
            let old = trace.values[row_start + SECRET_OFFSET + 1].as_canonical_u32() as u8;
            let changed = old ^ 1;
            trace.values[row_start + SECRET_OFFSET + 1] = Val::from_u32(u32::from(changed));
            for bit in 0..8 {
                trace.values[row_start + SECRET_BITS_OFFSET + 8 + bit] =
                    Val::from_u32(u32::from((changed >> bit) & 1));
            }
        }
        let values = public_values(level, &digest);
        let config = amount_opening::make_config();
        let attempt = std::panic::catch_unwind(AssertUnwindSafe(|| {
            prove(&config, &TreeNodeAir, trace, &values)
        }));
        if let Ok(Ok(proof)) = attempt {
            let verified = std::panic::catch_unwind(AssertUnwindSafe(|| {
                verify(&config, &TreeNodeAir, &proof, &values)
            }));
            assert!(
                !matches!(verified, Ok(Ok(()))),
                "changed children must not verify against the original parent"
            );
        }
    }

    #[test]
    fn rejects_levels_outside_the_depth_64_tree() {
        let child = [0u8; 64];
        assert!(prove_tree_node(64, &child, &child).is_err());
        let mut fake_envelope = Vec::from(ENVELOPE_MAGIC.as_slice());
        fake_envelope.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        fake_envelope.push(64);
        fake_envelope.extend_from_slice(&[0u8; DIGEST_BYTES]);
        fake_envelope.extend_from_slice(&0u32.to_le_bytes());
        assert!(verify_tree_node(&fake_envelope).is_err());
    }

    fn hex_array(text: &str) -> [u8; DIGEST_BYTES] {
        core::array::from_fn(|index| {
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()
        })
    }
}
