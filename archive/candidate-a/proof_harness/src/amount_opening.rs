//! Experimental zero-knowledge proof of a single bounded amount commitment opening.
//!
//! This is intentionally detached from the Candidate-A transaction verifier. It uses a
//! test-only BabyBear/Poseidon2 commitment and proves only knowledge of a non-zero `u64`
//! amount plus a field blinding value. It says nothing about ownership, membership, nullifiers,
//! transaction balance, KEM/AEAD, or the Candidate-A SHAKE commitment.

use core::borrow::Borrow;
use core::fmt;
use std::error::Error;
use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{
    BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS, BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16,
    BABYBEAR_S_BOX_DEGREE, BabyBear, GenericPoseidon2LinearLayersBabyBear, Poseidon2BabyBear,
};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2_air::{
    Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows, num_cols,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, SubAirBuilder, prove, verify};
use rand::rngs::{SmallRng, StdRng};
use rand::{RngExt, SeedableRng};

const AMOUNT_DOMAIN_TAG: u32 = 0x5244_414d;
const PARAMETER_SEED: u64 = 0x5244_585a_4b5f_3031;
const ENVELOPE_MAGIC: &[u8; 8] = b"RDXZAM01";
const ENVELOPE_VERSION: u16 = 1;
const ENVELOPE_HEADER_BYTES: usize = 8 + 2 + 4 + 4;
const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_BYTES: usize = ENVELOPE_HEADER_BYTES + MAX_PROOF_BYTES;
const TRACE_ROWS: usize = 128;
const AMOUNT_LIMBS: usize = 4;
const LIMB_BITS: usize = 16;
const AMOUNT_BITS: usize = AMOUNT_LIMBS * LIMB_BITS;
const LIMBS_OFFSET: usize = 0;
const BITS_OFFSET: usize = AMOUNT_LIMBS;
const INVERSE_OFFSET: usize = BITS_OFFSET + AMOUNT_BITS;
const POSEIDON_OFFSET: usize = INVERSE_OFFSET + 1;
const POSEIDON_WIDTH: usize = 16;
const SBOX_REGISTERS: usize = 1;
const HALF_FULL_ROUNDS: usize = BABYBEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = BABYBEAR_POSEIDON2_PARTIAL_ROUNDS_16;
const POSEIDON_TRACE_WIDTH: usize = num_cols::<
    POSEIDON_WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>();
const TRACE_WIDTH: usize = POSEIDON_OFFSET + POSEIDON_TRACE_WIDTH;

type Val = BabyBear;
type Challenge = p3_field::extension::BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs = MerkleTreeHidingMmcs<
    <Val as Field>::Packing,
    <Val as Field>::Packing,
    Hash,
    Compress,
    StdRng,
    2,
    8,
    4,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
pub(super) type Stark = StarkConfig<Pcs, Challenge, Challenger>;
type AmountPoseidonAir = Poseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    POSEIDON_WIDTH,
    BABYBEAR_S_BOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmountCommitmentStatementV1 {
    /// Canonical BabyBear field encoding of the demo Poseidon2 commitment.
    pub commitment: u32,
}

impl AmountCommitmentStatementV1 {
    fn public_values(self) -> [Val; 1] {
        [Val::from_u32(self.commitment)]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AmountProofError {
    InvalidAmount,
    InvalidBlinding,
    Malformed(&'static str),
    Backend(String),
}

impl fmt::Display for AmountProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAmount => write!(f, "amount must be in 1..=u64::MAX"),
            Self::InvalidBlinding => write!(f, "blinding must be a canonical BabyBear value"),
            Self::Malformed(message) => write!(f, "malformed amount proof: {message}"),
            Self::Backend(message) => write!(f, "amount proof backend rejected proof: {message}"),
        }
    }
}

impl Error for AmountProofError {}

#[derive(Clone)]
struct AmountOpeningAir {
    poseidon: AmountPoseidonAir,
}

impl BaseAir<Val> for AmountOpeningAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB> Air<AB> for AmountOpeningAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        {
            let mut sub_builder = SubAirBuilder::<AB, AmountPoseidonAir, AB::Var>::new(
                builder,
                POSEIDON_OFFSET..TRACE_WIDTH,
            );
            self.poseidon.eval(&mut sub_builder);
        }

        let main = builder.main();
        let row = main.current_slice();
        let mut nonzero_bits = AB::Expr::ZERO;
        for limb in 0..AMOUNT_LIMBS {
            let limb_expr: AB::Expr = row[LIMBS_OFFSET + limb].into();
            let mut reconstructed = AB::Expr::ZERO;
            for bit_index in 0..LIMB_BITS {
                let bit: AB::Expr = row[BITS_OFFSET + limb * LIMB_BITS + bit_index].into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                reconstructed += bit.clone() * Val::from_u32(1u32 << bit_index);
                nonzero_bits += bit;
            }
            builder.assert_zero(limb_expr - reconstructed);
        }
        let inverse: AB::Expr = row[INVERSE_OFFSET].into();
        // The sum is at most 64, strictly below the BabyBear modulus. This excludes zero amount.
        builder.assert_zero(nonzero_bits * inverse - AB::Expr::ONE);

        let poseidon_cols: &Poseidon2Cols<
            AB::Var,
            POSEIDON_WIDTH,
            BABYBEAR_S_BOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = row[POSEIDON_OFFSET..].borrow();
        for limb in 0..AMOUNT_LIMBS {
            let actual: AB::Expr = poseidon_cols.inputs[limb].into();
            let expected: AB::Expr = row[LIMBS_OFFSET + limb].into();
            builder.assert_zero(actual - expected);
        }
        let blind: AB::Expr = poseidon_cols.inputs[AMOUNT_LIMBS].into();
        // The blinding value is unconstrained except to lie in the BabyBear field.
        let domain: AB::Expr = poseidon_cols.inputs[AMOUNT_LIMBS + 1].into();
        builder.assert_zero(domain - Val::from_u32(AMOUNT_DOMAIN_TAG));
        for lane in (AMOUNT_LIMBS + 2)..POSEIDON_WIDTH {
            let unused: AB::Expr = poseidon_cols.inputs[lane].into();
            builder.assert_zero(unused);
        }
        let _ = blind;

        let output: AB::Expr =
            poseidon_cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0].into();
        let public_commitment: AB::Expr = builder.public_values()[0].into();
        builder.assert_zero(output - public_commitment);
    }
}

fn poseidon_constants() -> RoundConstants<Val, POSEIDON_WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    let mut rng = SmallRng::seed_from_u64(PARAMETER_SEED);
    RoundConstants::from_rng(&mut rng)
}

fn fresh_std_rng() -> StdRng {
    let mut thread_rng = rand::rng();
    StdRng::from_rng(&mut thread_rng)
}

pub(super) fn make_config() -> Stark {
    // Hash/commitment parameters are fixed protocol constants. The independent PCS/MMCS RNGs are
    // freshly seeded from the OS for every config and therefore every proof/verifier invocation.
    let mut params_rng = SmallRng::seed_from_u64(PARAMETER_SEED ^ 0x5043_535f_4841_5348);
    let permutation = Perm::new_from_rng_128(&mut params_rng);
    let hash = Hash::new(permutation.clone());
    let compress = Compress::new(permutation.clone());
    let value_mmcs = ValMmcs::new(hash, compress, 0, fresh_std_rng());
    let challenge_mmcs = ChallengeMmcs::new(value_mmcs.clone());
    let fri = FriParameters::new_testing_zk(challenge_mmcs);
    let pcs = Pcs::new(Dft::default(), value_mmcs, fri, 4, fresh_std_rng());
    let challenger = Challenger::new(permutation);
    Stark::new(pcs, challenger)
}

fn amount_trace(amount: u64, blinding: u32) -> (AmountCommitmentStatementV1, RowMajorMatrix<Val>) {
    let constants = poseidon_constants();
    let limbs = amount
        .to_le_bytes()
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    let mut input = [Val::ZERO; POSEIDON_WIDTH];
    for (index, limb) in limbs.iter().enumerate() {
        input[index] = Val::from_u32(u32::from(*limb));
    }
    input[AMOUNT_LIMBS] = Val::from_u32(blinding);
    input[AMOUNT_LIMBS + 1] = Val::from_u32(AMOUNT_DOMAIN_TAG);
    let poseidon_trace = generate_trace_rows::<
        Val,
        GenericPoseidon2LinearLayersBabyBear,
        POSEIDON_WIDTH,
        BABYBEAR_S_BOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(vec![input], &constants, 0);
    let poseidon_row = &poseidon_trace.values[..POSEIDON_TRACE_WIDTH];
    let poseidon_cols: &Poseidon2Cols<
        Val,
        POSEIDON_WIDTH,
        BABYBEAR_S_BOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    > = poseidon_row.borrow();
    let commitment =
        poseidon_cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0].as_canonical_u32();
    let statement = AmountCommitmentStatementV1 { commitment };

    let mut row = vec![Val::ZERO; TRACE_WIDTH];
    for (index, limb) in limbs.iter().enumerate() {
        row[LIMBS_OFFSET + index] = Val::from_u32(u32::from(*limb));
    }
    for bit_index in 0..AMOUNT_BITS {
        row[BITS_OFFSET + bit_index] = Val::from_u32(((amount >> bit_index) & 1) as u32);
    }
    let popcount = amount.count_ones();
    let inverse = Val::from_u32(popcount).inverse();
    row[INVERSE_OFFSET] = inverse;
    row[POSEIDON_OFFSET..].copy_from_slice(poseidon_row);

    let mut trace = Vec::with_capacity(TRACE_ROWS * TRACE_WIDTH);
    for _ in 0..TRACE_ROWS {
        trace.extend_from_slice(&row);
    }
    (statement, RowMajorMatrix::new(trace, TRACE_WIDTH))
}

fn encode_envelope(
    statement: AmountCommitmentStatementV1,
    proof: &p3_uni_stark::Proof<Stark>,
) -> Result<Vec<u8>, AmountProofError> {
    if statement.commitment >= Val::ORDER_U32 {
        return Err(AmountProofError::Malformed("non-canonical commitment"));
    }
    let payload = postcard::to_allocvec(proof)
        .map_err(|error| AmountProofError::Backend(error.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
        return Err(AmountProofError::Malformed(
            "proof payload size out of bounds",
        ));
    }
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| AmountProofError::Malformed("proof payload too large"))?;
    let mut bytes = Vec::with_capacity(ENVELOPE_HEADER_BYTES + payload.len());
    bytes.extend_from_slice(ENVELOPE_MAGIC);
    bytes.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&statement.commitment.to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn decode_envelope(
    bytes: &[u8],
) -> Result<(AmountCommitmentStatementV1, p3_uni_stark::Proof<Stark>), AmountProofError> {
    if bytes.len() < ENVELOPE_HEADER_BYTES {
        return Err(AmountProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > ENVELOPE_HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(AmountProofError::Malformed("envelope exceeds size limit"));
    }
    if &bytes[..8] != ENVELOPE_MAGIC {
        return Err(AmountProofError::Malformed("wrong magic"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(AmountProofError::Malformed("unsupported envelope version"));
    }
    let commitment = u32::from_le_bytes(bytes[10..14].try_into().unwrap());
    if commitment >= Val::ORDER_U32 {
        return Err(AmountProofError::Malformed("non-canonical commitment"));
    }
    let statement = AmountCommitmentStatementV1 { commitment };
    let payload_len = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
    if payload_len == 0 || payload_len > MAX_PROOF_BYTES || bytes.len() != 18 + payload_len {
        return Err(AmountProofError::Malformed(
            "payload length mismatch or trailing bytes",
        ));
    }
    let payload = &bytes[18..];
    let decoded = catch_unwind(AssertUnwindSafe(|| {
        crate::bounded_postcard::from_proof_bytes(payload)
    }))
    .map_err(|_| AmountProofError::Malformed("proof deserializer panicked"))?;
    let proof = decoded.map_err(|_| AmountProofError::Malformed("invalid proof serialization"))?;
    let canonical = catch_unwind(AssertUnwindSafe(|| {
        postcard::to_extend(
            &proof,
            crate::canonical_postcard::CanonicalBytes::new(payload),
        )
    }))
    .map_err(|_| AmountProofError::Malformed("proof serializer panicked"))?
    .map_err(|error| AmountProofError::Backend(error.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(AmountProofError::Malformed(
            "non-canonical proof serialization",
        ));
    }
    Ok((statement, proof))
}

/// Prove that a private non-zero `u64` amount opens a demo Poseidon2 commitment.
///
/// The blinding is generated internally. The public statement is included in the versioned proof
/// envelope. This experimental proof format is not part of Radix's canonical transaction wire.
pub fn prove_amount_opening(amount: u64) -> Result<Vec<u8>, AmountProofError> {
    let mut rng = fresh_std_rng();
    let blinding = rng.random_range(1..Val::ORDER_U32);
    prove_amount_opening_with_blinding(amount, blinding)
}

fn prove_amount_opening_with_blinding(
    amount: u64,
    blinding: u32,
) -> Result<Vec<u8>, AmountProofError> {
    if amount == 0 {
        return Err(AmountProofError::InvalidAmount);
    }
    if blinding == 0 || blinding >= Val::ORDER_U32 {
        return Err(AmountProofError::InvalidBlinding);
    }
    let (statement, trace) = amount_trace(amount, blinding);
    let air = AmountOpeningAir {
        poseidon: AmountPoseidonAir::new(poseidon_constants()),
    };
    let config = make_config();
    let proof = prove(&config, &air, trace, &statement.public_values())
        .map_err(|error| AmountProofError::Backend(error.to_string()))?;
    encode_envelope(statement, &proof)
}

/// Verify a versioned proof of knowledge of a bounded amount commitment opening.
///
/// This verifies only the subrelation documented in this module. It must never be adapted into
/// `TransferVerifier` or passed to `apply_block`.
pub fn verify_amount_opening(
    bytes: &[u8],
) -> Result<AmountCommitmentStatementV1, AmountProofError> {
    let (statement, proof) = decode_envelope(bytes)?;
    let air = AmountOpeningAir {
        poseidon: AmountPoseidonAir::new(poseidon_constants()),
    };
    let config = make_config();
    catch_unwind(AssertUnwindSafe(|| {
        verify(&config, &air, &proof, &statement.public_values())
    }))
    .map_err(|_| {
        AmountProofError::Backend("pinned verifier panicked on malformed proof".to_owned())
    })?
    .map_err(|error| AmountProofError::Backend(error.to_string()))?;
    Ok(statement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proves_private_u64_opening_and_binds_commitment() {
        let proof = prove_amount_opening_with_blinding(0x0123_4567_89ab_cdef, 123_456).unwrap();
        let statement = verify_amount_opening(&proof).unwrap();
        assert!(statement.commitment < Val::ORDER_U32);

        let mut changed_commitment = proof.clone();
        let changed = (statement.commitment + 1) % Val::ORDER_U32;
        changed_commitment[10..14].copy_from_slice(&changed.to_le_bytes());
        assert!(verify_amount_opening(&changed_commitment).is_err());

        let mut changed_proof = proof.clone();
        let last = changed_proof.len() - 1;
        changed_proof[last] ^= 1;
        assert!(verify_amount_opening(&changed_proof).is_err());

        let max_amount = prove_amount_opening_with_blinding(u64::MAX, 654_321).unwrap();
        verify_amount_opening(&max_amount).unwrap();
    }

    #[test]
    fn rejects_zero_amount_and_malformed_envelopes() {
        assert_eq!(
            prove_amount_opening_with_blinding(0, 1).unwrap_err(),
            AmountProofError::InvalidAmount
        );
        let proof = prove_amount_opening_with_blinding(1, 17).unwrap();
        for malformed in [
            proof[..proof.len() - 1].to_vec(),
            [&proof[..], &[0u8]].concat(),
            [&b"BADMAGIC"[..], &proof[8..]].concat(),
        ] {
            assert!(verify_amount_opening(&malformed).is_err());
        }
        let mut unsupported_version = proof.clone();
        unsupported_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(verify_amount_opening(&unsupported_version).is_err());
        let mut noncanonical_commitment = proof;
        noncanonical_commitment[10..14].copy_from_slice(&Val::ORDER_U32.to_le_bytes());
        assert!(verify_amount_opening(&noncanonical_commitment).is_err());
    }

    #[test]
    fn fresh_pcs_randomness_changes_proof_bytes_for_same_statement() {
        let first = prove_amount_opening_with_blinding(55, 7).unwrap();
        let second = prove_amount_opening_with_blinding(55, 7).unwrap();
        assert_eq!(&first[10..14], &second[10..14]);
        assert_ne!(first, second);
        verify_amount_opening(&first).unwrap();
        verify_amount_opening(&second).unwrap();
    }
}
