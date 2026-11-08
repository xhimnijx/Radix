//! Candidate-A one-time note-owner hash subrelation.
//!
//! Proves knowledge of a 32-byte KEM shared secret `ss` satisfying
//! `owner = SHAKE256(Frame("radix/one-time/v1", [pk_s, ss]), 64)`. This binds the exact
//! Candidate-A one-block frame and SHAKE wrapper around the pinned Plonky3 Keccak-f AIR. It does
//! not prove that `ss` came from ML-KEM decapsulation or that `pk_s` owns a note in the tree.

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
const PUBLIC_BYTES: usize = 64;
const SHARED_SECRET_BYTES: usize = 32;
const FRAME_BYTES: usize = 131;
const SHAKE_RATE_BYTES: usize = 136;
const RATE_LIMBS: usize = SHAKE_RATE_BYTES / 2;
const NUM_FULL_PERMUTATIONS: usize = 5;
const NUM_PARTIAL_ROUNDS: usize = 8;
const TRACE_ROWS: usize = 128;
const SECRET_OFFSET: usize = NUM_KECCAK_COLS;
const SECRET_BITS_OFFSET: usize = SECRET_OFFSET + SHARED_SECRET_BYTES;
const SECRET_BITS: usize = SHARED_SECRET_BYTES * 8;
const TRACE_WIDTH: usize = SECRET_BITS_OFFSET + SECRET_BITS;
const PUBLIC_VALUES: usize = PUBLIC_BYTES * 2;
const ENVELOPE_MAGIC: &[u8; 8] = b"RDXZOW01";
const ENVELOPE_VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + PUBLIC_VALUES + 4;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_PROOF_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum NoteOwnerProofError {
    Malformed(&'static str),
    Backend(String),
}

impl fmt::Display for NoteOwnerProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(formatter, "malformed note-owner proof: {message}"),
            Self::Backend(message) => write!(
                formatter,
                "note-owner proof backend rejected proof: {message}"
            ),
        }
    }
}

impl Error for NoteOwnerProofError {}

struct NoteOwnerAir;

impl BaseAir<Val> for NoteOwnerAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
}

impl<AB> Air<AB> for NoteOwnerAir
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

        // Shared-secret byte range is explicitly constrained by Boolean decomposition.
        for byte_index in 0..SHARED_SECRET_BYTES {
            let byte: AB::Expr = row[SECRET_OFFSET + byte_index].into();
            let mut reconstructed = AB::Expr::ZERO;
            for bit_index in 0..8 {
                let bit: AB::Expr = row[SECRET_BITS_OFFSET + byte_index * 8 + bit_index].into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                reconstructed += bit * Val::from_u32(1u32 << bit_index);
            }
            builder.assert_zero(byte - reconstructed);
        }

        // The private secret and its decomposition are a single witness across all rows.
        for column in SECRET_OFFSET..TRACE_WIDTH {
            builder
                .when_transition()
                .assert_zero(next[column] - row[column]);
        }

        // Bind the complete 131-byte Candidate-A frame plus SHAKE256's one-block padding.
        for limb_index in 0..RATE_LIMBS {
            let byte_index = limb_index * 2;
            let low = frame_and_padding_byte::<AB>(builder, row, byte_index);
            let high = frame_and_padding_byte::<AB>(builder, row, byte_index + 1);
            let expected = low + high * Val::from_u32(256);
            let actual: AB::Expr = row[input_limb(limb_index)].into();
            builder
                .when(keccak.step_flags[0])
                .assert_zero(actual - expected);
        }

        // Keccak-f capacity lanes are not part of the rate block and start at zero.
        for lane in 17..25 {
            let y = lane / 5;
            let x = lane % 5;
            for limb in 0..4 {
                builder
                    .when(keccak.step_flags[0])
                    .assert_zero(keccak.preimage[y][x][limb]);
            }
        }

        // Public values are raw statement bytes: [spend_public_key || owner]. Bind the SHAKE
        // output's first 64 squeezed bytes as little-endian pairs of public byte values.
        for limb_index in 0..32 {
            let actual: AB::Expr = row[output_limb(limb_index)].into();
            let low: AB::Expr = builder.public_values()[PUBLIC_BYTES + limb_index * 2].into();
            let high: AB::Expr = builder.public_values()[PUBLIC_BYTES + limb_index * 2 + 1].into();
            let expected = low + high * Val::from_u32(256);
            builder
                .when(keccak.step_flags[NUM_ROUNDS - 1])
                .assert_zero(actual - expected);
        }
    }
}

fn frame_and_padding_byte<AB>(builder: &AB, row: &[AB::Var], offset: usize) -> AB::Expr
where
    AB: AirBuilder<F = Val>,
{
    let constant = |value: u8| AB::Expr::from(Val::from_u32(u32::from(value)));
    match offset {
        0..=4 => constant(b"RADIX"[offset]),
        5 => constant(1),
        6 => constant(17),
        7 => constant(0),
        8..=24 => constant(b"radix/one-time/v1"[offset - 8]),
        25 => constant(2),
        26 => constant(0),
        27 => constant(64),
        28..=30 => constant(0),
        31..=94 => builder.public_values()[offset - 31].into(),
        95 => constant(32),
        96..=98 => constant(0),
        99..=130 => row[SECRET_OFFSET + offset - 99].into(),
        131 => constant(0x1f),
        132..=134 => constant(0),
        135 => constant(0x80),
        _ => constant(0),
    }
}

fn padded_shake_state(
    spend_public_key: &[u8; PUBLIC_BYTES],
    shared_secret: &[u8; SHARED_SECRET_BYTES],
) -> [u64; 25] {
    let mut frame = [0u8; FRAME_BYTES];
    frame[0..5].copy_from_slice(b"RADIX");
    frame[5] = 1;
    frame[6..8].copy_from_slice(&17u16.to_le_bytes());
    frame[8..25].copy_from_slice(b"radix/one-time/v1");
    frame[25..27].copy_from_slice(&2u16.to_le_bytes());
    frame[27..31].copy_from_slice(&(PUBLIC_BYTES as u32).to_le_bytes());
    frame[31..95].copy_from_slice(spend_public_key);
    frame[95..99].copy_from_slice(&(SHARED_SECRET_BYTES as u32).to_le_bytes());
    frame[99..].copy_from_slice(shared_secret);

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

fn trace_for(
    spend_public_key: &[u8; PUBLIC_BYTES],
    shared_secret: &[u8; SHARED_SECRET_BYTES],
) -> RowMajorMatrix<Val> {
    let state = padded_shake_state(spend_public_key, shared_secret);
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
        let start = row_index * NUM_KECCAK_COLS;
        values.extend_from_slice(&permutation_trace.values[start..start + NUM_KECCAK_COLS]);
        values.extend(
            shared_secret
                .iter()
                .copied()
                .map(|byte| Val::from_u32(u32::from(byte))),
        );
        for byte in shared_secret {
            for bit_index in 0..8 {
                values.push(Val::from_u32(u32::from((byte >> bit_index) & 1)));
            }
        }
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

fn extract_owner(trace: &RowMajorMatrix<Val>) -> [u8; PUBLIC_BYTES] {
    let final_permutation_row = NUM_FULL_PERMUTATIONS * NUM_ROUNDS - 1;
    let mut owner = [0u8; PUBLIC_BYTES];
    for limb_index in 0..32 {
        let start = final_permutation_row * TRACE_WIDTH + output_limb(limb_index);
        let limb = trace.values[start].as_canonical_u32() as u16;
        owner[2 * limb_index..2 * limb_index + 2].copy_from_slice(&limb.to_le_bytes());
    }
    owner
}

fn public_values(
    spend_public_key: &[u8; PUBLIC_BYTES],
    owner: &[u8; PUBLIC_BYTES],
) -> [Val; PUBLIC_VALUES] {
    core::array::from_fn(|index| {
        let byte = if index < PUBLIC_BYTES {
            spend_public_key[index]
        } else {
            owner[index - PUBLIC_BYTES]
        };
        Val::from_u32(u32::from(byte))
    })
}

fn encode_envelope(
    spend_public_key: &[u8; PUBLIC_BYTES],
    owner: &[u8; PUBLIC_BYTES],
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, NoteOwnerProofError> {
    let payload = postcard::to_allocvec(proof)
        .map_err(|error| NoteOwnerProofError::Backend(error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
        return Err(NoteOwnerProofError::Malformed(
            "proof payload size out of bounds",
        ));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| NoteOwnerProofError::Malformed("proof payload too large"))?;
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(ENVELOPE_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    bytes.extend_from_slice(spend_public_key);
    bytes.extend_from_slice(owner);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_envelope(
    bytes: &[u8],
) -> Result<([u8; PUBLIC_BYTES], [u8; PUBLIC_BYTES], Proof<Stark>), NoteOwnerProofError> {
    if bytes.len() < HEADER_BYTES {
        return Err(NoteOwnerProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(NoteOwnerProofError::Malformed(
            "envelope exceeds size limit",
        ));
    }
    if &bytes[..8] != ENVELOPE_MAGIC {
        return Err(NoteOwnerProofError::Malformed("wrong magic"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(NoteOwnerProofError::Malformed(
            "unsupported envelope version",
        ));
    }
    let spend_public_key: [u8; PUBLIC_BYTES] = bytes[10..74].try_into().unwrap();
    let owner: [u8; PUBLIC_BYTES] = bytes[74..138].try_into().unwrap();
    let len_start = 138;
    let payload_len =
        u32::from_le_bytes(bytes[len_start..len_start + 4].try_into().unwrap()) as usize;
    if payload_len == 0
        || payload_len > MAX_PROOF_BYTES
        || bytes.len() != HEADER_BYTES + payload_len
    {
        return Err(NoteOwnerProofError::Malformed(
            "payload length mismatch or trailing bytes",
        ));
    }
    let payload = &bytes[HEADER_BYTES..];
    let decoded = std::panic::catch_unwind(AssertUnwindSafe(|| {
        crate::bounded_postcard::from_proof_bytes(payload)
    }))
    .map_err(|_| NoteOwnerProofError::Malformed("proof deserializer panicked"))?;
    let proof =
        decoded.map_err(|_| NoteOwnerProofError::Malformed("invalid proof serialization"))?;
    let canonical = std::panic::catch_unwind(AssertUnwindSafe(|| {
        postcard::to_extend(
            &proof,
            crate::canonical_postcard::CanonicalBytes::new(payload),
        )
    }))
    .map_err(|_| NoteOwnerProofError::Malformed("proof serializer panicked"))?
    .map_err(|error| NoteOwnerProofError::Backend(error.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(NoteOwnerProofError::Malformed(
            "non-canonical proof serialization",
        ));
    }
    Ok((spend_public_key, owner, proof))
}

/// Prove the one-time owner hash for a public spend key and private 32-byte shared secret.
pub fn prove_note_owner(
    spend_public_key: &[u8; PUBLIC_BYTES],
    shared_secret: &[u8; SHARED_SECRET_BYTES],
) -> Result<Vec<u8>, NoteOwnerProofError> {
    prove_note_owner_with_output(spend_public_key, shared_secret).map(|(_, proof)| proof)
}

pub(super) fn prove_note_owner_with_output(
    spend_public_key: &[u8; PUBLIC_BYTES],
    shared_secret: &[u8; SHARED_SECRET_BYTES],
) -> Result<([u8; PUBLIC_BYTES], Vec<u8>), NoteOwnerProofError> {
    let trace = trace_for(spend_public_key, shared_secret);
    let owner = extract_owner(&trace);
    let config = amount_opening::make_config();
    let proof = prove(
        &config,
        &NoteOwnerAir,
        trace,
        &public_values(spend_public_key, &owner),
    )
    .map_err(|error| NoteOwnerProofError::Backend(error.to_string()))?;
    Ok((owner, encode_envelope(spend_public_key, &owner, &proof)?))
}

/// Verify a one-time owner hash proof and return `(spend_public_key, owner)`.
pub fn verify_note_owner(
    bytes: &[u8],
) -> Result<([u8; PUBLIC_BYTES], [u8; PUBLIC_BYTES]), NoteOwnerProofError> {
    let (spend_public_key, owner, proof) = decode_envelope(bytes)?;
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify(
            &config,
            &NoteOwnerAir,
            &proof,
            &public_values(&spend_public_key, &owner),
        )
    }))
    .map_err(|_| {
        NoteOwnerProofError::Backend("pinned verifier panicked on malformed proof".into())
    })?
    .map_err(|error| NoteOwnerProofError::Backend(error.to_string()))?;
    Ok((spend_public_key, owner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proves_candidate_a_one_time_hash_known_answer_and_rejects_tampering() {
        let spend_public_key = core::array::from_fn(|index| index as u8);
        let shared_secret = core::array::from_fn(|index| index as u8);
        let proof = prove_note_owner(&spend_public_key, &shared_secret).unwrap();
        let (verified_key, owner) = verify_note_owner(&proof).unwrap();
        assert_eq!(verified_key, spend_public_key);
        assert_eq!(
            owner,
            hex_array(
                "7ed2e1cbafb87719e3886cc20cd02137c82039ce6c1ab9a22400049d6beca86e\
                 23fd21d4892e092398f8df9fb9228bab64fa00db913a927e362069ec28342db8"
            )
        );

        let mut changed_key = proof.clone();
        changed_key[10] ^= 1;
        assert!(verify_note_owner(&changed_key).is_err());

        let mut changed_owner = proof.clone();
        changed_owner[74] ^= 1;
        assert!(verify_note_owner(&changed_owner).is_err());

        let mut changed_proof = proof.clone();
        changed_proof[HEADER_BYTES + (proof.len() - HEADER_BYTES) / 2] ^= 0x80;
        assert!(verify_note_owner(&changed_proof).is_err());

        let mut wrong_magic = proof.clone();
        wrong_magic[0] ^= 1;
        assert!(verify_note_owner(&wrong_magic).is_err());

        let mut wrong_version = proof.clone();
        wrong_version[8] ^= 1;
        assert!(verify_note_owner(&wrong_version).is_err());

        assert!(verify_note_owner(&proof[..HEADER_BYTES - 1]).is_err());
        let mut trailing = proof;
        trailing.push(0);
        assert!(verify_note_owner(&trailing).is_err());
    }

    fn hex_array(text: &str) -> [u8; PUBLIC_BYTES] {
        let hex = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap()
        })
    }
}
