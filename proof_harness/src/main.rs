#![forbid(unsafe_code)]

//! A non-consensus Plonky3 smoke harness for a public bounded-balance AIR.
//!
//! This is deliberately not a Radix transaction proof: it reveals the three
//! totals, does not bind the canonical Radix transaction statement, does not
//! prove Merkle membership, ML-KEM/AEAD relations, or complete transaction hashes, and does not provide
//! a zero-knowledge claim. Never pass its output to radix_core.state.

mod aes_sbox_air;
mod amount_opening;
#[allow(dead_code)]
mod bounded_postcard;
mod canonical_postcard;
mod depth64_path_opening;
mod note_commitment_opening;
mod note_owner_opening;
mod nullifier_opening;
mod owner_binding_bundle;
mod spend_pk_opening;
pub(crate) mod transaction_statement;
mod tree_node_opening;
mod two_level_path_opening;

use std::{env, error::Error, fmt, io::Read};

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use rand::{SeedableRng, rngs::SmallRng};

const LIMB_BITS: usize = 16;
const LIMB_BASE: u64 = 1 << LIMB_BITS;
const LIMBS_PER_U64: usize = 4;
const PUBLIC_LIMBS: usize = 3 * LIMBS_PER_U64;
const BIT_COLUMNS: usize = PUBLIC_LIMBS * LIMB_BITS;
const CARRY_COLUMNS: usize = LIMBS_PER_U64 + 1;
const TRACE_WIDTH: usize = BIT_COLUMNS + CARRY_COLUMNS;
const TRACE_ROWS: usize = 64;

// Reproducible test-only profile. These are recorded parameters, not a claimed
// soundness level. No full STARK security analysis is supplied by this harness.
const FRI_LOG_BLOWUP: usize = 4;
const FRI_LOG_FINAL_POLY_LEN: usize = 0;
const FRI_MAX_LOG_ARITY: usize = 1;
const FRI_NUM_QUERIES: usize = 32;
const FRI_BATCH_POW_BITS: usize = 0;
const FRI_COMMIT_POW_BITS: usize = 0;
const FRI_QUERY_POW_BITS: usize = 0;
const OOD_POW_BITS: usize = 0;

const ENVELOPE_MAGIC: &[u8; 8] = b"RDXCMP01";
const ENVELOPE_VERSION: u16 = 1;
const STATEMENT_BYTES: usize = 3 * 8;
const ENVELOPE_HEADER_BYTES: usize = 8 + 2 + STATEMENT_BYTES + 4;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BalanceStatement {
    input_total: u64,
    output_total: u64,
    fee: u64,
}

impl BalanceStatement {
    fn is_balanced(self) -> bool {
        self.output_total
            .checked_add(self.fee)
            .is_some_and(|outflow| outflow == self.input_total)
    }

    fn encode(self) -> [u8; STATEMENT_BYTES] {
        let mut bytes = [0u8; STATEMENT_BYTES];
        bytes[0..8].copy_from_slice(&self.input_total.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.output_total.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.fee.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, HarnessError> {
        if bytes.len() != STATEMENT_BYTES {
            return Err(HarnessError::Malformed("wrong statement length"));
        }
        let input_total = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let output_total = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let fee = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        Ok(Self {
            input_total,
            output_total,
            fee,
        })
    }

    fn public_values(self) -> Vec<BabyBear> {
        [self.input_total, self.output_total, self.fee]
            .into_iter()
            .flat_map(u64_limbs)
            .map(BabyBear::from_u64)
            .collect()
    }
}

fn u64_limbs(value: u64) -> [u64; LIMBS_PER_U64] {
    core::array::from_fn(|i| (value >> (i * LIMB_BITS)) & (LIMB_BASE - 1))
}

struct BalanceAir;

impl BaseAir<BabyBear> for BalanceAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        PUBLIC_LIMBS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(2)
    }
}

impl<AB: AirBuilder<F = BabyBear>> Air<AB> for BalanceAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        let public: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|value| (*value).into())
            .collect();

        // Every public 16-bit limb is reconstructed from boolean trace bits.
        // This makes the field representation injective over the stated range.
        for limb_index in 0..PUBLIC_LIMBS {
            let mut reconstructed = AB::Expr::ZERO;
            for bit_index in 0..LIMB_BITS {
                let bit: AB::Expr = row[limb_index * LIMB_BITS + bit_index].into();
                builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));
                reconstructed += bit * AB::Expr::from_u64(1u64 << bit_index);
            }
            let public_limb = public[limb_index].clone();
            builder.assert_zero(reconstructed - public_limb);
        }

        let carry_offset = BIT_COLUMNS;
        for carry_index in 0..CARRY_COLUMNS {
            let carry: AB::Expr = row[carry_offset + carry_index].into();
            builder.assert_zero(carry.clone() * (carry.clone() - AB::Expr::ONE));
        }
        let carry_zero: AB::Expr = row[carry_offset].into();
        builder.assert_zero(carry_zero);
        let final_carry: AB::Expr = row[carry_offset + LIMBS_PER_U64].into();
        builder.assert_zero(final_carry);

        // For each 16-bit limb, output + fee + carry_in = input + 2^16*carry_out.
        // All limbs and carries are range-constrained above, so this is bounded
        // integer addition rather than an unconstrained equality modulo the field.
        for limb_index in 0..LIMBS_PER_U64 {
            let input = public[limb_index].clone();
            let output = public[LIMBS_PER_U64 + limb_index].clone();
            let fee = public[2 * LIMBS_PER_U64 + limb_index].clone();
            let carry_in: AB::Expr = row[carry_offset + limb_index].into();
            let carry_out: AB::Expr = row[carry_offset + limb_index + 1].into();
            builder.assert_zero(
                output + fee + carry_in - input - carry_out * AB::Expr::from_u64(LIMB_BASE),
            );
        }
    }
}

fn trace_for(statement: BalanceStatement) -> RowMajorMatrix<BabyBear> {
    let limbs: Vec<u64> = [statement.input_total, statement.output_total, statement.fee]
        .into_iter()
        .flat_map(u64_limbs)
        .collect();
    let mut row = vec![BabyBear::ZERO; TRACE_WIDTH];

    for (limb_index, limb) in limbs.iter().copied().enumerate() {
        for bit_index in 0..LIMB_BITS {
            let bit = (limb >> bit_index) & 1;
            row[limb_index * LIMB_BITS + bit_index] = BabyBear::from_u64(bit);
        }
    }

    let mut carry = 0u64;
    for limb_index in 0..LIMBS_PER_U64 {
        row[BIT_COLUMNS + limb_index] = BabyBear::from_u64(carry);
        let sum = limbs[LIMBS_PER_U64 + limb_index] + limbs[2 * LIMBS_PER_U64 + limb_index] + carry;
        carry = sum / LIMB_BASE;
    }
    row[BIT_COLUMNS + LIMBS_PER_U64] = BabyBear::from_u64(carry);

    // Repeat a single-row witness to obtain a nontrivial trace domain. AIR
    // constraints are local; no state is accumulated between rows.
    let mut values = Vec::with_capacity(TRACE_ROWS * TRACE_WIDTH);
    for _ in 0..TRACE_ROWS {
        values.extend_from_slice(&row);
    }
    RowMajorMatrix::new(values, TRACE_WIDTH)
}

type Val = BabyBear;
type Perm = Poseidon2BabyBear<16>;
type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 2, 8>;
type Challenge = p3_field::extension::BinomialExtensionField<Val, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Stark = StarkConfig<Pcs, Challenge, Challenger>;

fn make_config() -> Stark {
    let mut rng = SmallRng::seed_from_u64(0x5241_4449_585f_4150);
    let permutation = Perm::new_from_rng_128(&mut rng);
    let hash = Hash::new(permutation.clone());
    let compress = Compress::new(permutation.clone());
    let value_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(value_mmcs.clone());
    let fri = FriParameters {
        log_blowup: FRI_LOG_BLOWUP,
        log_final_poly_len: FRI_LOG_FINAL_POLY_LEN,
        max_log_arity: FRI_MAX_LOG_ARITY,
        num_queries: FRI_NUM_QUERIES,
        batch_proof_of_work_bits: FRI_BATCH_POW_BITS,
        commit_proof_of_work_bits: FRI_COMMIT_POW_BITS,
        query_proof_of_work_bits: FRI_QUERY_POW_BITS,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), value_mmcs, fri);
    let challenger = Challenger::new(permutation);
    Stark::new(pcs, challenger).with_ood_proof_of_work_bits(OOD_POW_BITS)
}

#[derive(Debug, PartialEq, Eq)]
enum HarnessError {
    Malformed(&'static str),
    Unbalanced,
    Backend(String),
}

impl fmt::Display for HarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => write!(f, "malformed component proof: {message}"),
            Self::Unbalanced => write!(f, "public component statement is not balanced"),
            Self::Backend(message) => {
                write!(f, "STARK backend rejected component proof: {message}")
            }
        }
    }
}

impl Error for HarnessError {}

fn encode_envelope(
    statement: BalanceStatement,
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, HarnessError> {
    let proof_bytes =
        postcard::to_allocvec(proof).map_err(|err| HarnessError::Backend(err.to_string()))?;
    if proof_bytes.is_empty() || proof_bytes.len() > MAX_PROOF_BYTES {
        return Err(HarnessError::Malformed("proof payload size out of bounds"));
    }
    let proof_len = u32::try_from(proof_bytes.len())
        .map_err(|_| HarnessError::Malformed("proof payload too large"))?;
    let mut envelope = Vec::with_capacity(ENVELOPE_HEADER_BYTES + proof_bytes.len());
    envelope.extend_from_slice(ENVELOPE_MAGIC);
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_le_bytes());
    envelope.extend_from_slice(&statement.encode());
    envelope.extend_from_slice(&proof_len.to_le_bytes());
    envelope.extend_from_slice(&proof_bytes);
    Ok(envelope)
}

fn decode_envelope(bytes: &[u8]) -> Result<(BalanceStatement, Proof<Stark>), HarnessError> {
    if bytes.len() < ENVELOPE_HEADER_BYTES {
        return Err(HarnessError::Malformed("truncated envelope"));
    }
    if bytes.len() > ENVELOPE_HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(HarnessError::Malformed("envelope exceeds size limit"));
    }
    if &bytes[..8] != ENVELOPE_MAGIC {
        return Err(HarnessError::Malformed("wrong magic"));
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    if version != ENVELOPE_VERSION {
        return Err(HarnessError::Malformed("unsupported envelope version"));
    }
    let statement = BalanceStatement::decode(&bytes[10..10 + STATEMENT_BYTES])?;
    let len_offset = 10 + STATEMENT_BYTES;
    let payload_len =
        u32::from_le_bytes(bytes[len_offset..len_offset + 4].try_into().unwrap()) as usize;
    if payload_len == 0 || payload_len > MAX_PROOF_BYTES {
        return Err(HarnessError::Malformed("proof payload size out of bounds"));
    }
    let payload_offset = len_offset + 4;
    if bytes.len() != payload_offset + payload_len {
        return Err(HarnessError::Malformed(
            "payload length mismatch or trailing bytes",
        ));
    }
    let payload = &bytes[payload_offset..];
    let proof: Proof<Stark> = crate::bounded_postcard::from_proof_bytes(payload)
        .map_err(|_| HarnessError::Malformed("invalid proof serialization"))?;
    let canonical = postcard::to_extend(&proof, canonical_postcard::CanonicalBytes::new(payload))
        .map_err(|err| HarnessError::Backend(err.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(HarnessError::Malformed("non-canonical proof serialization"));
    }
    Ok((statement, proof))
}

fn prove_component(statement: BalanceStatement) -> Result<Vec<u8>, HarnessError> {
    if !statement.is_balanced() {
        return Err(HarnessError::Unbalanced);
    }
    let config = make_config();
    let proof = prove(
        &config,
        &BalanceAir,
        trace_for(statement),
        &statement.public_values(),
    )
    .map_err(|err| HarnessError::Backend(err.to_string()))?;
    encode_envelope(statement, &proof)
}

fn verify_component(bytes: &[u8]) -> Result<(), HarnessError> {
    let (statement, proof) = decode_envelope(bytes)?;
    if !statement.is_balanced() {
        return Err(HarnessError::Unbalanced);
    }
    let config = make_config();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify(&config, &BalanceAir, &proof, &statement.public_values())
    }))
    .map_err(|_| HarnessError::Backend("pinned verifier panicked on malformed proof".to_owned()))?
    .map_err(|err| HarnessError::Backend(err.to_string()))
}

const MAX_CLI_FIXED_INPUT_BYTES: usize = 4168;

fn read_bounded<R: Read>(reader: R, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let read_limit = u64::try_from(max_bytes)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "file-size limit cannot be represented",
            )
        })?;
    let mut bytes = Vec::new();
    reader.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("input file exceeds the {max_bytes}-byte limit"),
        ));
    }
    Ok(bytes)
}

fn read_bounded_file(
    path: impl AsRef<std::path::Path>,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    read_bounded(std::fs::File::open(path)?, max_bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let first_arg = args.next();
    if first_arg.as_deref() == Some("rdxl-resource-report") {
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rdxl-resource-report takes no arguments",
            )
            .into());
        }
        let report = depth64_path_opening::rdxl_resource_report().ok_or_else(|| {
            std::io::Error::other("RDXL static workspace calculation overflowed usize")
        })?;
        let lde_payload_u64 = u64::try_from(report.lde_payload_bytes)
            .map_err(|_| std::io::Error::other("RDXL LDE size exceeds u64"))?;
        let randomized_plus_lde_payload_u64 =
            u64::try_from(report.randomized_plus_lde_payload_bytes)
                .map_err(|_| std::io::Error::other("RDXL matrix-pair size exceeds u64"))?;
        let mib = 1024usize * 1024;
        let mib_u64 = 1024u64 * 1024;
        println!("RDXL static raw workspace dimensions (not a peak bound)");
        println!(
            "trace: {}x{} fields, {} bytes ({} MiB)",
            report.trace_rows,
            report.trace_width,
            report.trace_payload_bytes,
            report.trace_payload_bytes / mib,
        );
        println!(
            "ZK-randomized trace: {}x{} fields, {} bytes ({} MiB)",
            report.randomized_rows,
            report.randomized_width,
            report.randomized_payload_bytes,
            report.randomized_payload_bytes / mib,
        );
        println!(
            "PCS LDE: {}x{} fields, {} bytes ({} MiB)",
            report.lde_rows,
            report.lde_width,
            report.lde_payload_bytes,
            report.lde_payload_bytes / mib,
        );
        println!(
            "desktop process cap: {} bytes; LDE-only headroom: {} bytes",
            report.desktop_process_budget_bytes,
            report
                .desktop_process_budget_bytes
                .saturating_sub(lde_payload_u64),
        );
        println!(
            "mobile process cap: {} bytes; LDE-only excess: {} bytes",
            report.mobile_process_budget_bytes,
            lde_payload_u64.saturating_sub(report.mobile_process_budget_bytes),
        );
        println!(
            "randomized matrix + LDE payload sum (hypothetical coexistence): {} bytes ({} MiB)",
            randomized_plus_lde_payload_u64,
            randomized_plus_lde_payload_u64 / mib_u64,
        );
        println!(
            "if both coexist: desktop cap excess {} bytes; mobile cap excess {} bytes",
            randomized_plus_lde_payload_u64.saturating_sub(report.desktop_process_budget_bytes),
            randomized_plus_lde_payload_u64.saturating_sub(report.mobile_process_budget_bytes),
        );
        println!(
            "This dimension-derived report is not a measured peak or proof-fit guarantee; it does not authorize proving.",
        );
        return Ok(());
    }
    if first_arg.as_deref() == Some("owner-binding-prove") {
        let spend_secret_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness owner-binding-prove <spend-secret-file-64-bytes> <shared-secret-file-32-bytes> <bundle-file>",
            )
        })?;
        let shared_secret_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing shared-secret-file",
            )
        })?;
        let bundle_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing bundle-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many owner-binding-prove arguments",
            )
            .into());
        }
        let spend_secret_bytes = read_bounded_file(&spend_secret_path, 64)?;
        let spend_secret: [u8; 64] = spend_secret_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "spend secret file must contain exactly 64 bytes",
            )
        })?;
        let shared_secret_bytes = read_bounded_file(&shared_secret_path, 32)?;
        let shared_secret: [u8; 32] = shared_secret_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "shared-secret file must contain exactly 32 bytes",
            )
        })?;
        let bundle =
            owner_binding_bundle::prove_owner_binding_bundle(&spend_secret, &shared_secret)?;
        std::fs::write(&bundle_path, &bundle)?;
        println!("wrote a bundle of linked Candidate-A hash proofs");
        println!("bundle file: {bundle_path}; {} bytes", bundle.len());
        println!("The two STARK proofs remain independent; no transaction validity is proved.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("owner-binding-verify") {
        let bundle_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness owner-binding-verify <bundle-file>",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many owner-binding-verify arguments",
            )
            .into());
        }
        let bundle = read_bounded_file(&bundle_path, owner_binding_bundle::MAX_ENVELOPE_BYTES)?;
        let (spend_public_key, owner) = owner_binding_bundle::verify_owner_binding_bundle(&bundle)?;
        let encode_hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        println!("valid bundle: both hash proofs bind the same pk_s");
        println!("public pk_s: {}", encode_hex(&spend_public_key));
        println!("public owner: {}", encode_hex(&owner));
        println!("No ML-KEM, Merkle membership, or transaction validity is proved.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("note-commitment-prove") {
        let opening_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness note-commitment-prove <opening-file-200-bytes> <proof-file>",
            )
        })?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many note-commitment-prove arguments",
            )
            .into());
        }
        let opening = read_bounded_file(&opening_path, MAX_CLI_FIXED_INPUT_BYTES)?;
        let opening: [u8; 200] = opening.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opening file must contain owner64 || value-u64-le || rho64 || randomness64 (200 bytes)",
            )
        })?;
        let owner: [u8; 64] = opening[..64].try_into().unwrap();
        let value = u64::from_le_bytes(opening[64..72].try_into().unwrap());
        let rho: [u8; 64] = opening[72..136].try_into().unwrap();
        let randomness: [u8; 64] = opening[136..].try_into().unwrap();
        let proof =
            note_commitment_opening::prove_note_commitment(&owner, value, &rho, &randomness)?;
        std::fs::write(&proof_path, &proof)?;
        println!("wrote Candidate-A two-block note-commitment hash proof");
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!("The proof only opens a note commitment; it does not prove transaction validity.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("note-commitment-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness note-commitment-verify <proof-file>",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many note-commitment-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(&proof_path, note_commitment_opening::MAX_ENVELOPE_BYTES)?;
        let commitment = note_commitment_opening::verify_note_commitment(&proof)?;
        let encoded = commitment
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("valid Candidate-A note-commitment opening proof");
        println!("public commitment: {encoded}");
        println!("No owner derivation, Merkle membership, or transaction validity is proved.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("tree-node-prove") {
        let opening_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness tree-node-prove <opening-file-129-bytes> <proof-file>",
            )
        })?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many tree-node-prove arguments",
            )
            .into());
        }
        let opening = read_bounded_file(&opening_path, MAX_CLI_FIXED_INPUT_BYTES)?;
        let opening: [u8; 129] = opening.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opening file must contain level8 || left64 || right64 (129 bytes)",
            )
        })?;
        let level = opening[0];
        let left: [u8; 64] = opening[1..65].try_into().unwrap();
        let right: [u8; 64] = opening[65..].try_into().unwrap();
        let proof = tree_node_opening::prove_tree_node(level, &left, &right)?;
        std::fs::write(&proof_path, &proof)?;
        println!("wrote Candidate-A two-block tree-node hash proof");
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!("This proves one node hash opening, not a Merkle path or transaction validity.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("tree-node-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness tree-node-verify <proof-file>",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many tree-node-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(&proof_path, tree_node_opening::MAX_ENVELOPE_BYTES)?;
        let (level, parent) = tree_node_opening::verify_tree_node(&proof)?;
        let encoded = parent
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("valid Candidate-A tree-node hash opening at level {level}");
        println!("public parent digest: {encoded}");
        println!("No Merkle path, input membership, or transaction validity is proved.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("two-level-path-prove") {
        let opening_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness two-level-path-prove <opening-file-194-bytes> <expected-root-file-64-bytes> <proof-file>",
            )
        })?;
        let expected_root_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing expected-root-file",
            )
        })?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many two-level-path-prove arguments",
            )
            .into());
        }
        let opening = read_bounded_file(&opening_path, MAX_CLI_FIXED_INPUT_BYTES)?;
        let opening: [u8; 194] = opening.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opening file must contain leaf64 || sibling0-64 || sibling1-64 || direction0 || direction1 (194 bytes)",
            )
        })?;
        if opening[192] > 1 || opening[193] > 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "direction bytes must each be 0 or 1",
            )
            .into());
        }
        let expected_root_bytes = read_bounded_file(&expected_root_path, 64)?;
        let expected_root: [u8; 64] = expected_root_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "expected-root file must contain exactly 64 bytes",
            )
        })?;
        let leaf: [u8; 64] = opening[..64].try_into().unwrap();
        let sibling0: [u8; 64] = opening[64..128].try_into().unwrap();
        let sibling1: [u8; 64] = opening[128..192].try_into().unwrap();
        let proof = two_level_path_opening::prove_two_level_path(
            &leaf,
            &sibling0,
            &sibling1,
            opening[192] == 1,
            opening[193] == 1,
            &expected_root,
        )?;
        std::fs::write(&proof_path, &proof)?;
        println!("wrote Candidate-A linked two-node path proof");
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!(
            "This proves only a linked depth-2 path relation, not depth-64 membership or transaction validity."
        );
        return Ok(());
    }
    if first_arg.as_deref() == Some("two-level-path-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness two-level-path-verify <proof-file> <expected-root-file-64-bytes>",
            )
        })?;
        let expected_root_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing expected-root-file",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many two-level-path-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(&proof_path, two_level_path_opening::MAX_ENVELOPE_BYTES)?;
        let expected_root_bytes = read_bounded_file(&expected_root_path, 64)?;
        let expected_root: [u8; 64] = expected_root_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "expected-root file must contain exactly 64 bytes",
            )
        })?;
        let statement = two_level_path_opening::verify_two_level_path(&proof, &expected_root)?;
        let encoded = statement
            .root
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("valid Candidate-A linked two-node path proof");
        println!("public root: {encoded}");
        println!("This does not prove depth-64 membership or transaction validity.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("depth64-path-prove") {
        let opening_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness depth64-path-prove <opening-file-4168-bytes> <expected-root-file-64-bytes> <proof-file>",
            )
        })?;
        let expected_root_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing expected-root-file",
            )
        })?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many depth64-path-prove arguments",
            )
            .into());
        }
        let opening = read_bounded_file(&opening_path, MAX_CLI_FIXED_INPUT_BYTES)?;
        let opening: [u8; 4168] = opening.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opening file must contain leaf64 || 64 sibling digests || little-endian path-index-u64 (4168 bytes)",
            )
        })?;
        let leaf: [u8; 64] = opening[..64].try_into().unwrap();
        let siblings: [[u8; 64]; 64] = core::array::from_fn(|level| {
            opening[64 + level * 64..64 + (level + 1) * 64]
                .try_into()
                .unwrap()
        });
        let path_index = u64::from_le_bytes(opening[4160..4168].try_into().unwrap());
        let expected_root_bytes = read_bounded_file(&expected_root_path, 64)?;
        let expected_root: [u8; 64] = expected_root_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "expected-root file must contain exactly 64 bytes",
            )
        })?;
        let proof =
            depth64_path_opening::prove_depth64_path(&leaf, &siblings, path_index, &expected_root)?;
        std::fs::write(&proof_path, &proof)?;
        println!("wrote experimental linked Candidate-A depth-64 path proof");
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!(
            "This proves only the Merkle path relation, not transaction validity or consensus acceptance."
        );
        return Ok(());
    }
    if first_arg.as_deref() == Some("depth64-path-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness depth64-path-verify <proof-file> <expected-root-file-64-bytes>",
            )
        })?;
        let expected_root_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing expected-root-file",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many depth64-path-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(
            &proof_path,
            depth64_path_opening::MAX_DEPTH64_PATH_ENVELOPE_BYTES,
        )?;
        let expected_root_bytes = read_bounded_file(&expected_root_path, 64)?;
        let expected_root: [u8; 64] = expected_root_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "expected-root file must contain exactly 64 bytes",
            )
        })?;
        let statement = depth64_path_opening::verify_depth64_path(&proof, &expected_root)?;
        let encoded = statement
            .root
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("valid experimental Candidate-A depth-64 path proof");
        println!("public root: {encoded}");
        println!(
            "No transaction validity, post-quantum security, or consensus acceptance is proved."
        );
        return Ok(());
    }
    if first_arg.as_deref() == Some("nullifier-prove") {
        let opening_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness nullifier-prove <opening-file-160-bytes> <proof-file>",
            )
        })?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many nullifier-prove arguments",
            )
            .into());
        }
        let opening = read_bounded_file(&opening_path, MAX_CLI_FIXED_INPUT_BYTES)?;
        let opening: [u8; 160] = opening.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "opening file must contain spend-secret64 || kem-shared-secret32 || rho64 (160 bytes)",
            )
        })?;
        let spend_secret: [u8; 64] = opening[..64].try_into().unwrap();
        let shared_secret: [u8; 32] = opening[64..96].try_into().unwrap();
        let rho: [u8; 64] = opening[96..].try_into().unwrap();
        let proof = nullifier_opening::prove_nullifier(&spend_secret, &shared_secret, &rho)?;
        std::fs::write(&proof_path, &proof)?;
        println!("wrote Candidate-A two-block nullifier hash proof");
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!(
            "This proves only the nullifier hash preimage, not spend authorization or transaction validity."
        );
        return Ok(());
    }
    if first_arg.as_deref() == Some("nullifier-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness nullifier-verify <proof-file>",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many nullifier-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(&proof_path, nullifier_opening::MAX_ENVELOPE_BYTES)?;
        let nullifier = nullifier_opening::verify_nullifier(&proof)?;
        let encoded = nullifier
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("valid Candidate-A nullifier hash preimage proof");
        println!("public nullifier: {encoded}");
        println!(
            "No spend authorization, KEM decapsulation, Merkle membership, or transaction validity is proved."
        );
        return Ok(());
    }
    if first_arg.as_deref() == Some("note-owner-prove") {
        let spend_key_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness note-owner-prove <spend-pk-file-64-bytes> <shared-secret-file-32-bytes> <proof-file>",
            )
        })?;
        let shared_secret_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing shared-secret-file",
            )
        })?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many note-owner-prove arguments",
            )
            .into());
        }
        let key_bytes = read_bounded_file(&spend_key_path, 64)?;
        let spend_key: [u8; 64] = key_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "spend public key file must contain exactly 64 bytes",
            )
        })?;
        let secret_bytes = read_bounded_file(&shared_secret_path, 32)?;
        let shared_secret: [u8; 32] = secret_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "shared-secret file must contain exactly 32 bytes",
            )
        })?;
        let proof = note_owner_opening::prove_note_owner(&spend_key, &shared_secret)?;
        std::fs::write(&proof_path, &proof)?;
        println!("wrote Candidate-A one-time note-owner hash proof");
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!("This proves only owner = H_one-time(pk_s, shared_secret).");
        return Ok(());
    }
    if first_arg.as_deref() == Some("note-owner-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness note-owner-verify <proof-file>",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many note-owner-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(&proof_path, note_owner_opening::MAX_ENVELOPE_BYTES)?;
        let (spend_key, owner) = note_owner_opening::verify_note_owner(&proof)?;
        let encode_hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        println!("valid Candidate-A one-time owner hash proof");
        println!("public pk_s: {}", encode_hex(&spend_key));
        println!("public owner: {}", encode_hex(&owner));
        println!("No ML-KEM or transaction validity is proved.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("spend-pk-prove") {
        let secret_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness spend-pk-prove <secret-file-64-bytes> <proof-file>",
            )
        })?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many spend-pk-prove arguments",
            )
            .into());
        }
        let secret_bytes = read_bounded_file(&secret_path, 64)?;
        let secret: [u8; 64] = secret_bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "spend secret file must contain exactly 64 bytes",
            )
        })?;
        let proof = spend_pk_opening::prove_spend_pk(&secret)?;
        std::fs::write(&proof_path, &proof)?;
        println!("wrote Candidate-A spend-public-key hash proof");
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!("This proves only H_spend-pk(s), not a transaction.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("spend-pk-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness spend-pk-verify <proof-file>",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many spend-pk-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(&proof_path, spend_pk_opening::MAX_ENVELOPE_BYTES)?;
        let public_key = spend_pk_opening::verify_spend_pk(&proof)?;
        let public_key_hex = public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!("valid Candidate-A spend-public-key hash proof");
        println!("public pk_s: {public_key_hex}");
        println!("This is not a transaction proof; do not submit to consensus.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("amount-prove") {
        let amount = args
            .next()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "usage: radix-proof-harness amount-prove <private-amount-u64> <proof-file>",
                )
            })?
            .parse::<u64>()?;
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing proof-file")
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many amount-prove arguments",
            )
            .into());
        }
        let proof = amount_opening::prove_amount_opening(amount)?;
        let statement = amount_opening::verify_amount_opening(&proof)?;
        std::fs::write(&proof_path, &proof)?;
        println!("verified experimental amount-opening proof");
        println!("public demo commitment: {}", statement.commitment);
        println!("proof file: {proof_path}; {} bytes", proof.len());
        println!("NOT a Candidate-A transaction proof; do not submit to consensus.");
        return Ok(());
    }
    if first_arg.as_deref() == Some("amount-verify") {
        let proof_path = args.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "usage: radix-proof-harness amount-verify <proof-file>",
            )
        })?;
        if args.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "too many amount-verify arguments",
            )
            .into());
        }
        let proof = read_bounded_file(&proof_path, amount_opening::MAX_ENVELOPE_BYTES)?;
        let statement = amount_opening::verify_amount_opening(&proof)?;
        println!("valid experimental amount-opening proof");
        println!("public demo commitment: {}", statement.commitment);
        println!("NOT a Candidate-A transaction proof; do not submit to consensus.");
        return Ok(());
    }
    let input = first_arg
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(1_200);
    let output = args
        .next()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(1_100);
    let fee = args
        .next()
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(100);
    if args.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: radix-proof-harness [input_total output_total fee]",
        )
        .into());
    }
    let statement = BalanceStatement {
        input_total: input,
        output_total: output,
        fee,
    };
    let bundle = prove_component(statement)?;
    verify_component(&bundle)?;
    println!("verified public bounded-balance component proof");
    println!("statement: input={input}, output={output}, fee={fee}");
    println!("envelope bytes: {}", bundle.len());
    println!(
        "FRI test profile: log_blowup={FRI_LOG_BLOWUP}, log_final_poly_len={FRI_LOG_FINAL_POLY_LEN}, max_log_arity={FRI_MAX_LOG_ARITY}, num_queries={FRI_NUM_QUERIES}, batch_pow={FRI_BATCH_POW_BITS}, commit_pow={FRI_COMMIT_POW_BITS}, query_pow={FRI_QUERY_POW_BITS}; OOD_pow={OOD_POW_BITS}"
    );
    println!("Profile parameters are not a Radix soundness bound or a numeric security claim.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_reader_accepts_exact_limit() {
        assert_eq!(
            read_bounded(Cursor::new([1, 2, 3]), 3).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn bounded_reader_rejects_oversize_after_only_one_extra_byte() {
        let mut input = Cursor::new(vec![0u8; 1024]);
        let error = read_bounded(&mut input, 2).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(input.position(), 3);
    }

    #[test]
    fn proof_round_trips_and_verifies_for_balanced_public_statement() {
        let statement = BalanceStatement {
            input_total: u64::MAX,
            output_total: u64::MAX - 17,
            fee: 17,
        };
        let bytes = prove_component(statement).unwrap();
        assert!(bytes.len() > ENVELOPE_HEADER_BYTES);
        let (decoded_statement, decoded_proof) = decode_envelope(&bytes).unwrap();
        assert_eq!(decoded_statement, statement);
        assert_eq!(
            encode_envelope(decoded_statement, &decoded_proof).unwrap(),
            bytes
        );
        verify_component(&bytes).unwrap();
    }

    #[test]
    fn prover_rejects_unbalanced_public_statement() {
        let statement = BalanceStatement {
            input_total: 99,
            output_total: 90,
            fee: 8,
        };
        assert_eq!(prove_component(statement), Err(HarnessError::Unbalanced));
    }

    #[test]
    fn prover_rejects_u64_addition_overflow() {
        let statement = BalanceStatement {
            input_total: 0,
            output_total: u64::MAX,
            fee: 1,
        };
        assert!(!statement.is_balanced());
        assert_eq!(prove_component(statement), Err(HarnessError::Unbalanced));
    }

    #[test]
    fn verifier_rejects_mutated_statement_and_malformed_envelopes() {
        let statement = BalanceStatement {
            input_total: 1_000,
            output_total: 900,
            fee: 100,
        };
        let bytes = prove_component(statement).unwrap();

        let mut changed_statement = bytes.clone();
        changed_statement[10..18].copy_from_slice(&1_001u64.to_le_bytes());
        changed_statement[18..26].copy_from_slice(&901u64.to_le_bytes());
        // Keep the relation valid: rejection must come from transcript/public-input binding.
        assert!(verify_component(&changed_statement).is_err());

        let mut changed_proof = bytes.clone();
        let proof_middle = ENVELOPE_HEADER_BYTES + (bytes.len() - ENVELOPE_HEADER_BYTES) / 2;
        changed_proof[proof_middle] ^= 0x80;
        assert!(verify_component(&changed_proof).is_err());

        assert!(verify_component(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(verify_component(&trailing).is_err());

        let mut bad_magic = bytes;
        bad_magic[0] ^= 1;
        assert!(verify_component(&bad_magic).is_err());
    }
}
