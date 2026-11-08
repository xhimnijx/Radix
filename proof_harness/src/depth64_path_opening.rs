//! Experimental, single-AIR Candidate-A sparse-Merkle path opening of depth 64.
//!
//! The leaf, sibling digests, and U64 path index are private. The only public
//! statement is the expected root. This does not bind a transaction, output
//! leaf construction, or consensus state transition.
use crate::{
    aes_sbox_air::{self, AES_SBOX_WITNESS_COLUMNS},
    amount_opening::{self, Stark},
    canonical_postcard::CanonicalBytes,
    note_commitment_opening,
    transaction_statement::{
        OutputRecordV1, STATEMENT_OUTPUT_CIPHERTEXT_BYTES_OFFSET,
        STATEMENT_OUTPUT_CIPHERTEXT_LENGTH_PREFIX_OFFSET, STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET,
        STATEMENT_OUTPUT_KEM_CIPHERTEXT_BYTES_OFFSET, STATEMENT_OUTPUT_NONCE_BYTES_OFFSET,
        TransactionStatementV1, output_leaf_absorb_blocks, output_leaf_absorb_blocks_from_frame,
        output_leaf_frame, output_leaf_from_frame,
    },
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_keccak_air::{
    KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows, output_limb,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{Proof, SubAirBuilder, prove, verify};
use std::{error::Error, fmt, panic::AssertUnwindSafe, time::Instant};
type Val = BabyBear;
const DEPTH: usize = 64;
const DIGEST_BYTES: usize = 64;
const FRAME_BYTES: usize = 169;
const SHAKE_RATE_BYTES: usize = 136;
const RATE_LIMBS: usize = SHAKE_RATE_BYTES / 2;
const PERMUTATIONS_PER_NODE: usize = 2;
const ACTIVE_PERMUTATIONS: usize = DEPTH * PERMUTATIONS_PER_NODE;
const ACTIVE_ROWS: usize = ACTIVE_PERMUTATIONS * NUM_ROUNDS;
const SOURCE_CIPHERTEXT_BYTES: usize = 156;
const SOURCE_FRAME_BYTES: usize = 1203 + SOURCE_CIPHERTEXT_BYTES;
const SOURCE_NONCE_FRAME_OFFSET: usize = 1187;
const SOURCE_CIPHERTEXT_FRAME_OFFSET: usize = 1203;
const SOURCE_BLOCKS: usize = (SOURCE_FRAME_BYTES + 1).div_ceil(SHAKE_RATE_BYTES);
const SOURCE_PERMUTATIONS: usize = SOURCE_BLOCKS;
const SOURCE_ROWS: usize = SOURCE_PERMUTATIONS * NUM_ROUNDS;
const SOURCE_BOUND_ACTIVE_ROWS: usize = SOURCE_ROWS + ACTIVE_ROWS;
const NOTE_PERMUTATIONS: usize = 2;
const NOTE_ROWS: usize = NOTE_PERMUTATIONS * NUM_ROUNDS;
const SOURCE_NOTE_ACTIVE_ROWS: usize = SOURCE_BOUND_ACTIVE_ROWS + NOTE_ROWS;
const TRACE_ROWS: usize = ACTIVE_ROWS.next_power_of_two();
// RDXL reserves room for nine 15-row AES-256 CTR blocks; older profiles keep
// the smaller shared trace domain.
const RDXL_TRACE_ROWS: usize = TRACE_ROWS * 2;
const OUTPUT_LIMBS: usize = DIGEST_BYTES / 2;
const CURRENT_BITS: usize = NUM_KECCAK_COLS;
const SIBLING_BITS: usize = CURRENT_BITS + DIGEST_BYTES * 8;
const DIRECTION: usize = SIBLING_BITS + DIGEST_BYTES * 8;
const LEVEL_BITS: usize = DIRECTION + 1;
const PHASE: usize = LEVEL_BITS + 7;
const ACTIVE: usize = PHASE + 1;
const ABSORB_BITS_OFFSET: usize = ACTIVE + 1;
const ABSORB_BYTES: usize = 36; // Keccak state bytes 0..33 and 134..135
const ABSORB_BITS: usize = ABSORB_BYTES * 8;
const TRACE_WIDTH: usize = ABSORB_BITS_OFFSET + ABSORB_BITS;
const SOURCE_BUFFER_BITS: usize = SHAKE_RATE_BYTES * 8;
const SOURCE_BUFFER_BITS_OFFSET: usize = TRACE_WIDTH;
const SOURCE_TRACE_WIDTH: usize = TRACE_WIDTH + SOURCE_BUFFER_BITS;
const NOTE_ACTIVE_OFFSET: usize = SOURCE_TRACE_WIDTH;
const NOTE_INVERSE_OFFSET: usize = NOTE_ACTIVE_OFFSET + 1;
const NOTE_PRIVATE_BITS_OFFSET: usize = NOTE_INVERSE_OFFSET + 1;
const SOURCE_NOTE_TRACE_WIDTH: usize = NOTE_PRIVATE_BITS_OFFSET + 200 * 8;
const SPEND_PK_ACTIVE_OFFSET: usize = SOURCE_NOTE_TRACE_WIDTH;
const NOTE_OWNER_ACTIVE_OFFSET: usize = SPEND_PK_ACTIVE_OFFSET + 1;
const SPEND_OWNER_PRIVATE_OFFSET: usize = NOTE_OWNER_ACTIVE_OFFSET + 1;
const SPEND_OWNER_PRIVATE_BYTES: usize = 64 + 32;
const SPEND_OWNER_PRIVATE_BITS_OFFSET: usize =
    SPEND_OWNER_PRIVATE_OFFSET + SPEND_OWNER_PRIVATE_BYTES;
const SOURCE_KEY_NOTE_TRACE_WIDTH: usize =
    SPEND_OWNER_PRIVATE_BITS_OFFSET + SPEND_OWNER_PRIVATE_BYTES * 8;
const NULLIFIER_ACTIVE_OFFSET: usize = SOURCE_KEY_NOTE_TRACE_WIDTH;
const SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH: usize = NULLIFIER_ACTIVE_OFFSET + 1;
const OUTPUT_NOTE_ACTIVE_OFFSET: usize = SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH;
const INPUT_VALUE_BITS_OFFSET: usize = OUTPUT_NOTE_ACTIVE_OFFSET + 1;
const BALANCE_CARRY_BITS_OFFSET: usize = INPUT_VALUE_BITS_OFFSET + 64;
const OUTPUT_LEAF_ACTIVE_OFFSET: usize = BALANCE_CARRY_BITS_OFFSET + 3;
const OUTPUT_LEAF_INDEX_BITS_OFFSET: usize = OUTPUT_LEAF_ACTIVE_OFFSET + 1;
const OUTPUT_LEAF_BLOCK_BITS_OFFSET: usize = OUTPUT_LEAF_INDEX_BITS_OFFSET + 4;
const OUTPUT_LEAF_BLOCK_SLOTS: usize = 15;
const OUTPUT_LEAF_MAX_BLOCKS: usize = 14;
const OUTPUT_LEAF_PUBLIC_META_VALUES: usize = 1 + 4;
const INPUT_KDF_FRAME_BYTES: usize = 1223;
const INPUT_KDF_BLOCKS: usize = (INPUT_KDF_FRAME_BYTES + 1).div_ceil(SHAKE_RATE_BYTES);
const INPUT_KDF_ROWS: usize = INPUT_KDF_BLOCKS * NUM_ROUNDS;
const INPUT_KDF_SOURCE_BYTES: usize = 64 + 1088;
const OUTPUT_LEAF_PUBLIC_BLOCKS_VALUES: usize = OUTPUT_LEAF_BLOCK_SLOTS * SHAKE_RATE_BYTES;
const OUTPUT_LEAF_PUBLIC_DIGEST_VALUES: usize = DIGEST_BYTES;
const OUTPUT_LEAF_PUBLIC_VALUES: usize = OUTPUT_LEAF_PUBLIC_META_VALUES
    + OUTPUT_LEAF_PUBLIC_BLOCKS_VALUES
    + OUTPUT_LEAF_PUBLIC_DIGEST_VALUES;
const OUTPUT_NOTE_LEAF_TRACE_WIDTH: usize = OUTPUT_LEAF_BLOCK_BITS_OFFSET + SOURCE_BUFFER_BITS;
const INPUT_KDF_ACTIVE_OFFSET: usize = OUTPUT_NOTE_LEAF_TRACE_WIDTH;
const INPUT_KDF_INDEX_BITS_OFFSET: usize = INPUT_KDF_ACTIVE_OFFSET + 1;
const INPUT_KDF_BLOCK_BITS_OFFSET: usize = OUTPUT_LEAF_BLOCK_BITS_OFFSET;
const INPUT_KDF_SOURCE_BYTES_OFFSET: usize = INPUT_KDF_INDEX_BITS_OFFSET + 4;
const INPUT_KDF_KEY_BYTES_OFFSET: usize = INPUT_KDF_SOURCE_BYTES_OFFSET + INPUT_KDF_SOURCE_BYTES;
const SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_TRACE_WIDTH: usize = INPUT_KDF_KEY_BYTES_OFFSET + 32;
const INPUT_AEAD_SOURCE_BYTES: usize = 12 + SOURCE_CIPHERTEXT_BYTES;
const INPUT_AEAD_SOURCE_BYTES_OFFSET: usize = SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_TRACE_WIDTH;
const INPUT_NOTE_RHO_RANDOMNESS_BYTES: usize = 128;
const INPUT_NOTE_RHO_RANDOMNESS_BYTES_OFFSET: usize =
    INPUT_AEAD_SOURCE_BYTES_OFFSET + INPUT_AEAD_SOURCE_BYTES;
const AES256_EXPANDED_KEY_BITS: usize = 240 * 8;
// The expanded AES-256 key schedule occupies one contiguous 1,920-bit bank.
//
// An earlier experiment tried to overlay the first 1,152 bits on the input-KDF
// source-byte bank to save trace width. That split was never made consistent:
// all fourteen access sites kept a single contiguous `BITS_OFFSET + index`
// expression, and the two halves do not share a lifetime (the source bytes are
// still live through the final input-KDF row, while key bits are written from
// the key-schedule row onward). Rather than half-land the optimisation, the
// layout is reverted to a dedicated bank. Reintroduce the overlay only together
// with an accessor, a proven column-lifetime argument, and a test that asserts
// every `(offset, length)` slice is disjoint except for the documented
// mutually-exclusive AES S-box reuse below.
const AES256_KEY_SCHEDULE_TAIL_BITS: usize = AES256_EXPANDED_KEY_BITS;
const AES256_KEY_SCHEDULE_TAIL_OFFSET: usize =
    INPUT_NOTE_RHO_RANDOMNESS_BYTES_OFFSET + INPUT_NOTE_RHO_RANDOMNESS_BYTES;
const AES256_KEY_SCHEDULE_BITS_OFFSET: usize = AES256_KEY_SCHEDULE_TAIL_OFFSET;
const AES256_KEY_SCHEDULE_ACTIVE_OFFSET: usize =
    AES256_KEY_SCHEDULE_TAIL_OFFSET + AES256_KEY_SCHEDULE_TAIL_BITS;
const AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET: usize = AES256_KEY_SCHEDULE_ACTIVE_OFFSET + 1;
const AES256_SBOX_COUNT: usize = 4;
const AES256_KEY_SCHEDULE_ROWS: usize = 13;
const AES256_BLOCK_ACTIVE_OFFSET: usize = AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET + 4;
const AES256_BLOCK_INDEX_BITS_OFFSET: usize = AES256_BLOCK_ACTIVE_OFFSET + 1;
const AES256_BLOCK_NUMBER_BITS_OFFSET: usize = AES256_BLOCK_INDEX_BITS_OFFSET + 4;
const AES256_BLOCK_STATE_INPUT_BITS_OFFSET: usize = AES256_BLOCK_NUMBER_BITS_OFFSET + 4;
const AES256_BLOCK_STATE_OUTPUT_BITS_OFFSET: usize = AES256_BLOCK_STATE_INPUT_BITS_OFFSET + 128;
const AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET: usize = AES256_BLOCK_STATE_OUTPUT_BITS_OFFSET + 128;
const AES256_BLOCK_XTIME_BITS_OFFSET: usize = AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + 128;
const AES256_BLOCK_MUL3_BITS_OFFSET: usize = AES256_BLOCK_XTIME_BITS_OFFSET + 128;
const AES256_BLOCK_MIXED_BITS_OFFSET: usize = AES256_BLOCK_MUL3_BITS_OFFSET + 128;
const AES256_BLOCK_CIPHERTEXT_BITS_OFFSET: usize = AES256_BLOCK_MIXED_BITS_OFFSET + 128;
const AES256_BLOCK_PLAINTEXT_BITS_OFFSET: usize = AES256_BLOCK_CIPHERTEXT_BITS_OFFSET + 128;
const AES256_BLOCK_SBOX_WITNESS_OFFSET: usize = AES256_BLOCK_PLAINTEXT_BITS_OFFSET + 128;
const AES256_BLOCK_SBOX_COUNT: usize = 16;
// Reuse the first four CTR-block S-box input, output, and witness slices for
// key-schedule S-boxes; their stage selectors cannot both be active in one row.
// Key-schedule relations are gated by key_stage, block-state relations by block_active.
const AES256_SBOX_INPUT_BITS_OFFSET: usize = AES256_BLOCK_STATE_INPUT_BITS_OFFSET;
const AES256_SBOX_OUTPUT_BITS_OFFSET: usize = AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET;
// Every S-box constraint is gated by its stage's active selector.
const AES256_SBOX_WITNESS_OFFSET: usize = AES256_BLOCK_SBOX_WITNESS_OFFSET;
const AES256_BLOCKS: usize = 9;
const AES256_BLOCK_ROUNDS: usize = 15;
const AES256_BLOCK_ROWS: usize = AES256_BLOCKS * AES256_BLOCK_ROUNDS;
const OUTPUT_KDF_SECRET_BYTES: usize = 32;
const OUTPUT_KDF_SECRET_BYTES_OFFSET: usize =
    AES256_BLOCK_SBOX_WITNESS_OFFSET + AES256_BLOCK_SBOX_COUNT * AES_SBOX_WITNESS_COLUMNS;
const CRYPTO_OUTPUT_MODE_OFFSET: usize = OUTPUT_KDF_SECRET_BYTES_OFFSET + OUTPUT_KDF_SECRET_BYTES;
const OUTPUT_KDF_SECRET_BITS_OFFSET: usize = CRYPTO_OUTPUT_MODE_OFFSET + 1;
const RDXL_TRACE_WIDTH: usize = OUTPUT_KDF_SECRET_BITS_OFFSET + OUTPUT_KDF_SECRET_BYTES * 8;
const OUTPUT_CIPHERTEXT_BYTES: usize = 156;
const OUTPUT_COMMITMENT_PUBLIC_OFFSET: usize =
    PUBLIC_ROOT_PREFIX_BYTES + STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET;
const OUTPUT_KEM_CIPHERTEXT_PUBLIC_OFFSET: usize =
    PUBLIC_ROOT_PREFIX_BYTES + STATEMENT_OUTPUT_KEM_CIPHERTEXT_BYTES_OFFSET;
const OUTPUT_NONCE_PUBLIC_OFFSET: usize =
    PUBLIC_ROOT_PREFIX_BYTES + STATEMENT_OUTPUT_NONCE_BYTES_OFFSET;
const OUTPUT_CIPHERTEXT_LENGTH_PUBLIC_OFFSET: usize =
    PUBLIC_ROOT_PREFIX_BYTES + STATEMENT_OUTPUT_CIPHERTEXT_LENGTH_PREFIX_OFFSET;
const OUTPUT_CIPHERTEXT_PUBLIC_OFFSET: usize =
    PUBLIC_ROOT_PREFIX_BYTES + STATEMENT_OUTPUT_CIPHERTEXT_BYTES_OFFSET;
const KEY_NOTE_ACTIVE_ROWS: usize = SOURCE_NOTE_ACTIVE_ROWS + 2 * NUM_ROUNDS;
const KEY_NOTE_NULLIFIER_ACTIVE_ROWS: usize = KEY_NOTE_ACTIVE_ROWS + 2 * NUM_ROUNDS;
const KEY_NOTE_NULLIFIER_OUTPUT_ACTIVE_ROWS: usize = KEY_NOTE_NULLIFIER_ACTIVE_ROWS + NOTE_ROWS;
const MAGIC: &[u8; 8] = b"RDXZ64P1";
const STATEMENT_MAGIC: &[u8; 8] = b"RDXT64P1";
const SOURCE_STATEMENT_MAGIC: &[u8; 8] = b"RDXS64P1";
const SOURCE_NOTE_MAGIC: &[u8; 8] = b"RDXI64P1";
const SOURCE_KEY_NOTE_MAGIC: &[u8; 8] = b"RDXJ64P1";
const SOURCE_KEY_NOTE_NULLIFIER_MAGIC: &[u8; 8] = b"RDXK64P1";
const SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC: &[u8; 8] = b"RDXL64P1";
const PUBLIC_ROOT_PREFIX_BYTES: usize = DIGEST_BYTES;

/// Mirrors the pinned `amount_opening::make_config` PCS workspace shape:
/// `new_testing_zk` uses log-blowup 2 and `Pcs::new` adds four ZK codewords.
/// The report includes a hypothetical randomized-matrix + LDE payload sum if
/// both coexist; none of these raw sizes is a complete peak-memory bound.
const PCS_LOG_BLOWUP: usize = 2;
const PCS_ZK_RANDOM_CODEWORDS: usize = 4;
const DESKTOP_PROCESS_BUDGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MOBILE_PROCESS_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RdxlResourceReport {
    pub(super) trace_rows: usize,
    pub(super) trace_width: usize,
    pub(super) trace_payload_bytes: usize,
    pub(super) randomized_rows: usize,
    pub(super) randomized_width: usize,
    pub(super) randomized_payload_bytes: usize,
    pub(super) lde_rows: usize,
    pub(super) lde_width: usize,
    pub(super) lde_payload_bytes: usize,
    pub(super) randomized_plus_lde_payload_bytes: usize,
    pub(super) desktop_process_budget_bytes: u64,
    pub(super) mobile_process_budget_bytes: u64,
}

/// Compute dimension-derived raw allocations without building any trace or proof.
pub(super) fn rdxl_resource_report() -> Option<RdxlResourceReport> {
    let field_bytes = std::mem::size_of::<Val>();
    let trace_rows = RDXL_TRACE_ROWS;
    let trace_width = RDXL_TRACE_WIDTH;
    let trace_payload_bytes = trace_rows
        .checked_mul(trace_width)?
        .checked_mul(field_bytes)?;
    let randomized_rows = trace_rows.checked_mul(2)?;
    let randomized_width = trace_width.checked_add(PCS_ZK_RANDOM_CODEWORDS)?;
    let randomized_payload_bytes = randomized_rows
        .checked_mul(randomized_width)?
        .checked_mul(field_bytes)?;
    let lde_rows = randomized_rows.checked_mul(1usize.checked_shl(PCS_LOG_BLOWUP as u32)?)?;
    let lde_width = randomized_width;
    let lde_payload_bytes = lde_rows.checked_mul(lde_width)?.checked_mul(field_bytes)?;
    let randomized_plus_lde_payload_bytes =
        randomized_payload_bytes.checked_add(lde_payload_bytes)?;
    Some(RdxlResourceReport {
        trace_rows,
        trace_width,
        trace_payload_bytes,
        randomized_rows,
        randomized_width,
        randomized_payload_bytes,
        lde_rows,
        lde_width,
        lde_payload_bytes,
        randomized_plus_lde_payload_bytes,
        desktop_process_budget_bytes: DESKTOP_PROCESS_BUDGET_BYTES,
        mobile_process_budget_bytes: MOBILE_PROCESS_BUDGET_BYTES,
    })
}

/// Fail closed before witness/trace allocation while the conservative raw
/// randomized-matrix + LDE overlap exceeds the smaller declared desktop/mobile
/// process cap. With no target-specific runtime policy, the mobile cap is the
/// cross-target guard. This is a payload preflight, not measured peak RSS.
fn ensure_rdxl_process_budget() -> Result<(), Depth64PathProofError> {
    let report = rdxl_resource_report().ok_or(Depth64PathProofError::ResourceBudgetExceeded {
        estimated_workspace_bytes: u64::MAX,
        process_budget_bytes: DESKTOP_PROCESS_BUDGET_BYTES.min(MOBILE_PROCESS_BUDGET_BYTES),
    })?;
    let estimated_workspace_bytes =
        u64::try_from(report.randomized_plus_lde_payload_bytes).unwrap_or(u64::MAX);
    let conservative_process_budget_bytes = report
        .desktop_process_budget_bytes
        .min(report.mobile_process_budget_bytes);
    if estimated_workspace_bytes > conservative_process_budget_bytes {
        return Err(Depth64PathProofError::ResourceBudgetExceeded {
            estimated_workspace_bytes,
            process_budget_bytes: conservative_process_budget_bytes,
        });
    }
    Ok(())
}
const PUBLIC_NULLIFIER_BYTES_OFFSET: usize =
    PUBLIC_ROOT_PREFIX_BYTES + crate::transaction_statement::STATEMENT_NULLIFIER_BYTES_OFFSET;
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + DIGEST_BYTES + 4;
const STATEMENT_HEADER_BYTES: usize = 8 + 2 + 4 + 4;
const MAX_STATEMENT_BYTES: usize = 4096;
const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_DEPTH64_PATH_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_PROOF_BYTES;
pub(crate) const MAX_STATEMENT_BOUND_ENVELOPE_BYTES: usize =
    STATEMENT_HEADER_BYTES + MAX_STATEMENT_BYTES + MAX_PROOF_BYTES;
const TAG: &[u8] = b"radix/tree-node/v1";
type ValArray = [u8; DIGEST_BYTES];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Depth64PathStatementV1 {
    pub root: ValArray,
}
/// Experimental private opening of the public output-note commitment.
/// This does not derive the owner from the output KEM recipient fields.
/// Intentionally omits `Debug` and `Clone` to discourage accidental witness
/// disclosure in logs and unnecessary copies; this is not a confidentiality boundary.
#[derive(PartialEq, Eq)]
pub struct OutputNoteOpeningV1 {
    pub owner: ValArray,
    pub value: u64,
    pub rho: ValArray,
    pub randomness: ValArray,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Depth64PathProofError {
    RootMismatch,
    StatementMismatch,
    NoteCommitmentMismatch,
    NullifierMismatch,
    OutputNoteCommitmentMismatch,
    UnbalancedValues,
    Malformed(&'static str),
    ResourceBudgetExceeded {
        estimated_workspace_bytes: u64,
        process_budget_bytes: u64,
    },
    Backend(String),
}
impl fmt::Display for Depth64PathProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMismatch => {
                write!(f, "computed depth-64 path root differs from expected root")
            }
            Self::StatementMismatch => write!(f, "embedded transaction statement differs"),
            Self::NoteCommitmentMismatch => {
                write!(f, "private note opening does not match source commitment")
            }
            Self::NullifierMismatch => {
                write!(f, "derived nullifier does not match the public statement")
            }
            Self::OutputNoteCommitmentMismatch => {
                write!(
                    f,
                    "private output note opening does not match public commitment"
                )
            }
            Self::UnbalancedValues => {
                write!(f, "input value does not equal output value plus fee")
            }
            Self::Malformed(message) => write!(f, "malformed depth-64 path proof: {message}"),
            Self::ResourceBudgetExceeded {
                estimated_workspace_bytes,
                process_budget_bytes,
            } => write!(
                f,
                "RDXL proving is disabled: conservative randomized-matrix/LDE payload estimate ({estimated_workspace_bytes} bytes) exceeds the cross-target process cap ({process_budget_bytes} bytes); this estimate is not measured peak RSS"
            ),
            Self::Backend(message) => {
                write!(f, "depth-64 path proof backend rejected proof: {message}")
            }
        }
    }
}
impl Error for Depth64PathProofError {}
struct Depth64PathAir {
    public_value_count: usize,
    source_bound: bool,
    note_bound: bool,
    spend_owner_bound: bool,
    nullifier_bound: bool,
    output_note_balance_bound: bool,
}
impl BaseAir<Val> for Depth64PathAir {
    fn width(&self) -> usize {
        if self.output_note_balance_bound {
            RDXL_TRACE_WIDTH
        } else if self.nullifier_bound {
            SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH
        } else if self.spend_owner_bound {
            SOURCE_KEY_NOTE_TRACE_WIDTH
        } else if self.note_bound {
            SOURCE_NOTE_TRACE_WIDTH
        } else if self.source_bound {
            SOURCE_TRACE_WIDTH
        } else {
            TRACE_WIDTH
        }
    }
    fn num_public_values(&self) -> usize {
        self.public_value_count
    }
}
impl<AB> Air<AB> for Depth64PathAir
where
    AB: AirBuilder<F = Val>,
{
    fn eval(&self, builder: &mut AB) {
        {
            let mut sub = SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);
            KeccakAir {}.eval(&mut sub);
        }
        let main = builder.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let keccak: &KeccakCols<AB::Var> = row[..NUM_KECCAK_COLS].borrow();
        let next_keccak: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
        let transition = builder.is_transition();
        let first_step: AB::Expr = keccak.step_flags[0].into();
        let final_step: AB::Expr = keccak.step_flags[NUM_ROUNDS - 1].into();
        let one = AB::Expr::ONE;
        let active: AB::Expr = row[ACTIVE].into();
        let source_enabled = AB::Expr::from_u32(u32::from(self.source_bound));
        let note_enabled = AB::Expr::from_u32(u32::from(self.note_bound));
        let note_active: AB::Expr = if self.note_bound {
            row[NOTE_ACTIVE_OFFSET].into()
        } else {
            AB::Expr::ZERO
        };
        let note_stage = note_active.clone() * note_enabled.clone();
        let key_enabled = AB::Expr::from_u32(u32::from(self.spend_owner_bound));
        let spend_pk_active: AB::Expr = if self.spend_owner_bound {
            row[SPEND_PK_ACTIVE_OFFSET].into()
        } else {
            AB::Expr::ZERO
        };
        let note_owner_active: AB::Expr = if self.spend_owner_bound {
            row[NOTE_OWNER_ACTIVE_OFFSET].into()
        } else {
            AB::Expr::ZERO
        };
        let spend_pk_stage = spend_pk_active.clone() * key_enabled.clone();
        let note_owner_stage = note_owner_active.clone() * key_enabled.clone();
        let nullifier_active: AB::Expr = if self.nullifier_bound {
            row[NULLIFIER_ACTIVE_OFFSET].into()
        } else {
            AB::Expr::ZERO
        };
        let nullifier_enabled = AB::Expr::from_u32(u32::from(self.nullifier_bound));
        let nullifier_stage = nullifier_active.clone() * nullifier_enabled;
        let output_note_active: AB::Expr = if self.output_note_balance_bound {
            row[OUTPUT_NOTE_ACTIVE_OFFSET].into()
        } else {
            AB::Expr::ZERO
        };
        let output_note_enabled = AB::Expr::from_u32(u32::from(self.output_note_balance_bound));
        let output_note_stage = output_note_active.clone() * output_note_enabled.clone();
        let output_leaf_active: AB::Expr = if self.output_note_balance_bound {
            row[OUTPUT_LEAF_ACTIVE_OFFSET].into()
        } else {
            AB::Expr::ZERO
        };
        let output_leaf_stage = output_leaf_active.clone() * output_note_enabled.clone();
        let input_kdf_active: AB::Expr = if self.output_note_balance_bound {
            row[INPUT_KDF_ACTIVE_OFFSET].into()
        } else {
            AB::Expr::ZERO
        };
        let input_kdf_stage = input_kdf_active.clone() * output_note_enabled.clone();
        let output_leaf_index: [AB::Expr; 4] = core::array::from_fn(|i| {
            if self.output_note_balance_bound {
                row[OUTPUT_LEAF_INDEX_BITS_OFFSET + i].into()
            } else {
                AB::Expr::ZERO
            }
        });
        let source_stage = active.clone() * level_marker::<AB>(row) * source_enabled.clone();
        let path_active = active.clone()
            * (one.clone() - level_marker::<AB>(row) * source_enabled.clone())
            * (one.clone() - note_stage.clone())
            * (one.clone() - spend_pk_stage.clone())
            * (one.clone() - note_owner_stage.clone())
            * (one.clone() - nullifier_stage.clone())
            * (one.clone() - output_note_stage.clone());
        let phase: AB::Expr = row[PHASE].into();
        builder.assert_zero(active.clone() * (active.clone() - one.clone()));
        builder.assert_zero(phase.clone() * (phase.clone() - one.clone()));
        builder.assert_zero(note_active.clone() * (note_active.clone() - one.clone()));
        if self.spend_owner_bound {
            builder.assert_zero(spend_pk_active.clone() * (spend_pk_active.clone() - one.clone()));
            builder
                .assert_zero(note_owner_active.clone() * (note_owner_active.clone() - one.clone()));
            builder.assert_zero(spend_pk_stage.clone() * note_owner_stage.clone());
            builder.assert_zero(spend_pk_stage.clone() * note_stage.clone());
            builder.assert_zero(note_owner_stage.clone() * note_stage.clone());
        }
        if self.nullifier_bound {
            builder
                .assert_zero(nullifier_active.clone() * (nullifier_active.clone() - one.clone()));
            builder.assert_zero(nullifier_stage.clone() * spend_pk_stage.clone());
            builder.assert_zero(nullifier_stage.clone() * note_owner_stage.clone());
            builder.assert_zero(nullifier_stage.clone() * note_stage.clone());
            builder.assert_zero(nullifier_stage.clone() * source_stage.clone());
        }
        if self.output_note_balance_bound {
            builder.assert_zero(
                output_note_active.clone() * (output_note_active.clone() - one.clone()),
            );
            builder.assert_zero(output_note_stage.clone() * active.clone());
            builder.assert_zero(output_note_stage.clone() * note_stage.clone());
            builder.assert_zero(output_note_stage.clone() * spend_pk_stage.clone());
            builder.assert_zero(output_note_stage.clone() * note_owner_stage.clone());
            builder.assert_zero(output_note_stage.clone() * nullifier_stage.clone());
            builder.assert_zero(output_note_stage.clone() * source_stage.clone());
            builder.assert_zero(
                output_leaf_active.clone() * (output_leaf_active.clone() - one.clone()),
            );
            builder.assert_zero(output_leaf_stage.clone() * active.clone());
            builder.assert_zero(output_leaf_stage.clone() * note_stage.clone());
            builder.assert_zero(output_leaf_stage.clone() * spend_pk_stage.clone());
            builder.assert_zero(output_leaf_stage.clone() * note_owner_stage.clone());
            builder.assert_zero(output_leaf_stage.clone() * nullifier_stage.clone());
            builder.assert_zero(output_leaf_stage.clone() * output_note_stage.clone());
            builder.assert_zero(output_leaf_stage.clone() * source_stage.clone());
            builder
                .assert_zero(input_kdf_active.clone() * (input_kdf_active.clone() - one.clone()));
            builder.assert_zero(input_kdf_stage.clone() * active.clone());
            builder.assert_zero(input_kdf_stage.clone() * note_stage.clone());
            builder.assert_zero(input_kdf_stage.clone() * spend_pk_stage.clone());
            builder.assert_zero(input_kdf_stage.clone() * note_owner_stage.clone());
            builder.assert_zero(input_kdf_stage.clone() * nullifier_stage.clone());
            builder.assert_zero(input_kdf_stage.clone() * output_note_stage.clone());
            builder.assert_zero(input_kdf_stage.clone() * output_leaf_stage.clone());
            builder.assert_zero(input_kdf_stage.clone() * source_stage.clone());
            for bit in 0..4 {
                let value = output_leaf_index[bit].clone();
                builder.assert_zero(
                    output_leaf_stage.clone() * value.clone() * (value.clone() - one.clone()),
                );
                builder.assert_zero((one.clone() - output_leaf_stage.clone()) * value);
            }
        }
        let level: [AB::Expr; 7] = core::array::from_fn(|i| row[LEVEL_BITS + i].into());
        for bit in &level {
            builder.assert_zero(bit.clone() * (bit.clone() - one.clone()));
        }
        let direction: AB::Expr = row[DIRECTION].into();
        builder.assert_zero(direction.clone() * (direction.clone() - one.clone()));
        // Current/sibling digest bytes are represented by Boolean bit columns.
        for bits_offset in [CURRENT_BITS, SIBLING_BITS] {
            for index in 0..DIGEST_BYTES {
                for bit in 0..8 {
                    let b: AB::Expr = row[bits_offset + index * 8 + bit].into();
                    builder.assert_zero(b.clone() * (b - one.clone()));
                }
            }
        }
        // The private path has exactly 64 levels: active levels are 0..63,
        // followed by an inactive terminal state encoded as level 64.
        let inactive = one.clone() - active.clone();
        builder.assert_zero(path_active.clone() * level[6].clone());
        builder
            .when(inactive.clone())
            .assert_zero(level[6].clone() - one.clone());
        for bit in 0..6 {
            builder
                .when(inactive.clone())
                .assert_zero(level[bit].clone());
        }
        builder
            .when(inactive.clone() * (one.clone() - output_note_stage.clone()))
            .assert_zero(phase.clone());
        builder
            .when_first_row()
            .assert_zero(active.clone() - one.clone());
        builder.when_first_row().assert_zero(phase.clone());
        for bit in 0..6 {
            builder.when_first_row().assert_zero(level[bit].clone());
        }
        builder.when_first_row().assert_zero(
            level[6].clone()
                - source_enabled.clone()
                    * (one.clone() - note_active.clone() - key_enabled.clone()),
        );
        builder.when_first_row().assert_zero(
            note_active.clone() - note_enabled.clone() * (one.clone() - key_enabled.clone()),
        );
        if self.spend_owner_bound {
            builder
                .when_first_row()
                .assert_zero(spend_pk_active.clone() - key_enabled.clone());
            builder
                .when_first_row()
                .assert_zero(note_owner_active.clone());
        }
        if self.nullifier_bound {
            builder
                .when_first_row()
                .assert_zero(nullifier_active.clone());
        }
        builder.when_last_row().assert_zero(active.clone());
        if self.output_note_balance_bound {
            builder
                .when_first_row()
                .assert_zero(output_note_active.clone());
            builder
                .when_last_row()
                .assert_zero(output_note_active.clone());
            builder
                .when_first_row()
                .assert_zero(output_leaf_active.clone());
            builder
                .when_last_row()
                .assert_zero(output_leaf_active.clone());
        }
        builder
            .when_last_row()
            .assert_zero(level[6].clone() - one.clone());
        for bit in 0..6 {
            builder.when_last_row().assert_zero(level[bit].clone());
        }
        builder.when_last_row().assert_zero(phase.clone());
        let next_active: AB::Expr = next[ACTIVE].into();
        let next_phase: AB::Expr = next[PHASE].into();
        let note_end = note_stage.clone() * final_step.clone() * phase.clone();
        let spend_pk_end = spend_pk_stage.clone() * final_step.clone();
        let note_owner_end = note_owner_stage.clone() * final_step.clone();
        let nullifier_end = nullifier_stage.clone() * final_step.clone() * phase.clone();
        if self.spend_owner_bound {
            let next_spend_pk: AB::Expr = next[SPEND_PK_ACTIVE_OFFSET].into();
            let next_note_owner: AB::Expr = next[NOTE_OWNER_ACTIVE_OFFSET].into();
            builder
                .when(transition.clone())
                .assert_zero(next_spend_pk - (spend_pk_active.clone() - spend_pk_end.clone()));
            builder.when(transition.clone()).assert_zero(
                next_note_owner
                    - (note_owner_active.clone() - note_owner_end.clone() + spend_pk_end.clone()),
            );
        }
        if self.nullifier_bound {
            let next_nullifier: AB::Expr = next[NULLIFIER_ACTIVE_OFFSET].into();
            builder.when(transition.clone()).assert_zero(
                next_nullifier
                    - (nullifier_active.clone() - nullifier_end.clone() + note_owner_end.clone()),
            );
        }
        if self.note_bound {
            let next_note_active: AB::Expr = next[NOTE_ACTIVE_OFFSET].into();
            let note_owner_to_note = if self.nullifier_bound {
                nullifier_end.clone()
            } else if self.spend_owner_bound {
                note_owner_end.clone()
            } else {
                AB::Expr::ZERO
            };
            builder.when(transition.clone()).assert_zero(
                next_note_active - (note_active.clone() - note_end.clone() + note_owner_to_note),
            );
            for bit in 0..7 {
                let current_bit = level[bit].clone();
                let next_bit: AB::Expr = next[LEVEL_BITS + bit].into();
                builder
                    .when(note_stage.clone())
                    .assert_zero(current_bit.clone());
                builder
                    .when(
                        transition.clone() * note_stage.clone() * (one.clone() - note_end.clone()),
                    )
                    .assert_zero(next_bit.clone() - current_bit);
                if bit == 6 {
                    builder
                        .when(transition.clone() * note_end.clone())
                        .assert_zero(next_bit - one.clone());
                } else {
                    builder
                        .when(transition.clone() * note_end.clone())
                        .assert_zero(next_bit);
                }
            }
            for bit in 0..(200 * 8) {
                let current_bit: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + bit].into();
                let next_bit: AB::Expr = next[NOTE_PRIVATE_BITS_OFFSET + bit].into();
                builder.assert_zero(current_bit.clone() * (current_bit.clone() - one.clone()));
                builder
                    .when(
                        transition.clone() * note_stage.clone() * (one.clone() - note_end.clone()),
                    )
                    .assert_zero(next_bit - current_bit);
            }
            let inverse: AB::Expr = row[NOTE_INVERSE_OFFSET].into();
            let next_inverse: AB::Expr = next[NOTE_INVERSE_OFFSET].into();
            builder
                .when(transition.clone() * note_stage.clone() * (one.clone() - note_end.clone()))
                .assert_zero(next_inverse - inverse);
        }
        let increment = path_active.clone() * final_step.clone() * phase.clone();
        let mut level63 = one.clone() - level[6].clone();
        for bit in 0..6 {
            level63 = level63 * level[bit].clone();
        }
        let end_path = path_active.clone() * final_step.clone() * phase.clone() * level63;
        if self.output_note_balance_bound {
            let output_note_end = output_note_stage.clone() * final_step.clone() * phase.clone();
            let next_output_note: AB::Expr = next[OUTPUT_NOTE_ACTIVE_OFFSET].into();
            builder.when(transition.clone()).assert_zero(
                next_output_note
                    - (output_note_active.clone() - output_note_end.clone() + end_path.clone()),
            );
            eval_output_leaf_constraints(
                builder,
                row,
                next,
                keccak,
                next_keccak,
                transition.clone(),
                first_step.clone(),
                final_step.clone(),
                output_note_end,
                output_leaf_stage.clone(),
            );
            eval_input_kdf_constraints(
                builder,
                row,
                next,
                keccak,
                next_keccak,
                transition.clone(),
                first_step.clone(),
                final_step.clone(),
                output_leaf_stage.clone(),
                input_kdf_stage.clone(),
            );
            eval_aes256_key_schedule_constraints(
                builder,
                row,
                next,
                transition.clone(),
                final_step.clone(),
                input_kdf_stage.clone(),
            );
            eval_aes256_ctr_plaintext_constraints(builder, row, next, transition.clone());
            // The output shared secret is an AIR witness, not a public byte array.
            // Decompose it once into persistent bits so KDF frame bytes cannot be
            // represented by arbitrary BabyBear field elements.
            for byte in 0..OUTPUT_KDF_SECRET_BYTES {
                let value: AB::Expr = row[OUTPUT_KDF_SECRET_BYTES_OFFSET + byte].into();
                let mut reconstructed = AB::Expr::ZERO;
                for bit in 0..8 {
                    let offset = OUTPUT_KDF_SECRET_BITS_OFFSET + byte * 8 + bit;
                    let current: AB::Expr = row[offset].into();
                    let following: AB::Expr = next[offset].into();
                    builder.assert_zero(current.clone() * (current.clone() - one.clone()));
                    builder
                        .when(transition.clone())
                        .assert_zero(following - current.clone());
                    reconstructed += current * AB::Expr::from_u32(1 << bit);
                }
                builder.assert_zero(value - reconstructed);
            }
            let key_schedule_live: AB::Expr = row[AES256_KEY_SCHEDULE_ACTIVE_OFFSET].into();
            let aes_block_live: AB::Expr = row[AES256_BLOCK_ACTIVE_OFFSET].into();
            let output_note_private_live = output_note_stage.clone()
                + output_leaf_stage.clone()
                + input_kdf_stage.clone()
                + key_schedule_live
                + aes_block_live;
            for bit in 0..(200 * 8) {
                let current: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + bit].into();
                let following: AB::Expr = next[NOTE_PRIVATE_BITS_OFFSET + bit].into();
                builder.assert_zero(
                    output_note_private_live.clone()
                        * current.clone()
                        * (current.clone() - one.clone()),
                );
                builder
                    .when(transition.clone() * output_note_private_live.clone())
                    .assert_zero(following - current);
            }
            for index in 0..INPUT_KDF_SOURCE_BYTES {
                let offset = INPUT_KDF_SOURCE_BYTES_OFFSET + index;
                let current: AB::Expr = row[offset].into();
                let following: AB::Expr = next[offset].into();
                builder
                    .when(transition.clone())
                    .assert_zero(following - current);
            }
            let crypto_mode: AB::Expr = row[CRYPTO_OUTPUT_MODE_OFFSET].into();
            let block_active: AB::Expr = row[AES256_BLOCK_ACTIVE_OFFSET].into();
            let block_round_bits: [AB::Expr; 4] =
                core::array::from_fn(|bit| row[AES256_BLOCK_INDEX_BITS_OFFSET + bit].into());
            let block_number_bits: [AB::Expr; 4] =
                core::array::from_fn(|bit| row[AES256_BLOCK_NUMBER_BITS_OFFSET + bit].into());
            let last_round = (0..4).fold(AB::Expr::ONE, |selector, bit| {
                selector
                    * if (14 >> bit) & 1 == 1 {
                        block_round_bits[bit].clone()
                    } else {
                        one.clone() - block_round_bits[bit].clone()
                    }
            });
            let last_block = (0..4).fold(AB::Expr::ONE, |selector, bit| {
                selector
                    * if (8 >> bit) & 1 == 1 {
                        block_number_bits[bit].clone()
                    } else {
                        one.clone() - block_number_bits[bit].clone()
                    }
            });
            let input_aes_end =
                block_active * last_round * last_block * (one.clone() - crypto_mode);
            for index in 0..32 {
                let offset = INPUT_KDF_KEY_BYTES_OFFSET + index;
                let current: AB::Expr = row[offset].into();
                let following: AB::Expr = next[offset].into();
                builder
                    .when(transition.clone() * (one.clone() - input_aes_end.clone()))
                    .assert_zero(following - current);
            }
            for (byte_index, frame_offset) in (27..=90).chain(95..=1182).enumerate() {
                let field_column = row[INPUT_KDF_SOURCE_BYTES_OFFSET + byte_index];
                let block = frame_offset / SHAKE_RATE_BYTES;
                let within = frame_offset % SHAKE_RATE_BYTES;
                let selector = source_stage.clone()
                    * first_step.clone()
                    * source_block_selector::<AB>(&level, block);
                let expected = source_buffer_byte::<AB>(row, within);
                let field_expr: AB::Expr = field_column.into();
                builder.when(selector).assert_zero(field_expr - expected);
            }
            // Persist the exact source nonce and authenticated ciphertext/tag as
            // byte values for the subsequent input AEAD relation. These columns
            // are not yet an AES-GCM proof by themselves.
            for byte in 0..INPUT_AEAD_SOURCE_BYTES {
                let offset = INPUT_AEAD_SOURCE_BYTES_OFFSET + byte;
                let current: AB::Expr = row[offset].into();
                let following: AB::Expr = next[offset].into();
                builder
                    .when(transition.clone())
                    .assert_zero(following - current);
            }
            for (byte_index, frame_offset) in (SOURCE_NONCE_FRAME_OFFSET
                ..SOURCE_NONCE_FRAME_OFFSET + 12)
                .chain(
                    SOURCE_CIPHERTEXT_FRAME_OFFSET
                        ..SOURCE_CIPHERTEXT_FRAME_OFFSET + SOURCE_CIPHERTEXT_BYTES,
                )
                .enumerate()
            {
                let block = frame_offset / SHAKE_RATE_BYTES;
                let within = frame_offset % SHAKE_RATE_BYTES;
                let selector = source_stage.clone()
                    * first_step.clone()
                    * source_block_selector::<AB>(&level, block);
                let source_byte: AB::Expr = row[INPUT_AEAD_SOURCE_BYTES_OFFSET + byte_index].into();
                let committed_byte = source_buffer_byte::<AB>(row, within);
                builder
                    .when(selector)
                    .assert_zero(source_byte - committed_byte);
            }
            // Retain rho and randomness for the later decryption relation;
            // these columns do not authenticate the opening against ciphertext.
            let input_note_start =
                note_stage.clone() * first_step.clone() * (one.clone() - phase.clone());
            for byte in 0..INPUT_NOTE_RHO_RANDOMNESS_BYTES {
                let offset = INPUT_NOTE_RHO_RANDOMNESS_BYTES_OFFSET + byte;
                let current: AB::Expr = row[offset].into();
                let following: AB::Expr = next[offset].into();
                builder
                    .when(transition.clone())
                    .assert_zero(following - current.clone());
                let note_byte_index = 72 + byte;
                let expected = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                    let note_bit: AB::Expr =
                        row[NOTE_PRIVATE_BITS_OFFSET + note_byte_index * 8 + bit].into();
                    acc + note_bit * AB::Expr::from_u32(1 << bit)
                });
                builder
                    .when(input_note_start.clone())
                    .assert_zero(current - expected);
            }
        }
        builder
            .when(transition.clone())
            .assert_zero(next_active - (active.clone() - end_path));
        // Increment the 7-bit level counter only after phase 1 of an active
        // node hash. The transition selector is multiplied outside the Boolean
        // carry terms; it is never complemented or treated as a Boolean.
        for bit in 0..7 {
            let mut carry = increment.clone();
            for lower in 0..bit {
                carry = carry * level[lower].clone();
            }
            let next_bit: AB::Expr = next[LEVEL_BITS + bit].into();
            let updated = level[bit].clone() + carry.clone()
                - level[bit].clone() * carry * AB::Expr::from_u32(2);
            builder
                .when(
                    transition.clone()
                        * (one.clone() - source_stage.clone())
                        * (one.clone() - note_stage.clone()),
                )
                .assert_zero(next_bit - updated);
        }
        let round_end = (path_active.clone()
            + note_stage.clone()
            + nullifier_stage.clone()
            + output_note_stage.clone())
            * final_step.clone();
        let phase_updated =
            phase.clone() + round_end.clone() - phase.clone() * round_end * AB::Expr::from_u32(2);
        builder
            .when(transition.clone())
            .assert_zero(next_phase - phase_updated);
        // At each completed node hash, the output digest becomes the next
        // current node. Current/sibling/direction persist at all other rows.
        let hash_end = path_active.clone() * final_step.clone() * phase.clone();
        let boundary = transition.clone() * hash_end.clone();
        let stay = transition.clone() * path_active.clone() * (one.clone() - hash_end.clone());
        for index in 0..DIGEST_BYTES * 8 {
            let current_bit: AB::Expr = row[CURRENT_BITS + index].into();
            let next_current_bit: AB::Expr = next[CURRENT_BITS + index].into();
            builder
                .when(stay.clone())
                .assert_zero(next_current_bit - current_bit);
            let sibling_bit: AB::Expr = row[SIBLING_BITS + index].into();
            let next_sibling_bit: AB::Expr = next[SIBLING_BITS + index].into();
            builder
                .when(stay.clone())
                .assert_zero(next_sibling_bit - sibling_bit);
        }
        let next_direction: AB::Expr = next[DIRECTION].into();
        builder
            .when(stay.clone())
            .assert_zero(next_direction - direction);
        // Reconstruct each output limb from the next-row Boolean digest bits.
        for limb in 0..OUTPUT_LIMBS {
            let actual: AB::Expr = row[output_limb(limb)].into();
            let lo = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                let value: AB::Expr = next[CURRENT_BITS + (limb * 2) * 8 + bit].into();
                acc + value * AB::Expr::from_u32(1 << bit)
            });
            let hi = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                let value: AB::Expr = next[CURRENT_BITS + (limb * 2 + 1) * 8 + bit].into();
                acc + value * AB::Expr::from_u32(1 << bit)
            });
            builder
                .when(boundary.clone())
                .assert_zero(actual - (lo + hi * AB::Expr::from_u32(256)));
        }
        let level_value = (0..7).fold(AB::Expr::ZERO, |acc, bit| {
            acc + level[bit].clone() * AB::Expr::from_u32(1 << bit)
        });
        let first_block_start =
            path_active.clone() * first_step.clone() * (one.clone() - phase.clone());
        for limb in 0..RATE_LIMBS {
            let low = frame_byte64::<AB>(row, limb * 2, level_value.clone());
            let high = frame_byte64::<AB>(row, limb * 2 + 1, level_value.clone());
            let expected = low + high * AB::Expr::from_u32(256);
            builder
                .when(first_block_start.clone())
                .assert_zero(keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4] - expected);
        }
        for y in 0..5 {
            for x in 0..5 {
                for limb in 0..4 {
                    if y * 20 + x * 4 + limb >= RATE_LIMBS {
                        builder
                            .when(first_block_start.clone())
                            .assert_zero(keccak.preimage[y][x][limb]);
                    }
                }
            }
        }
        // Only bytes touched by the second absorption block need a bitwise
        // decomposition: 0..33 contain the tail of the framed node hash and
        // byte 135 contains SHAKE's final 0x80 bit. Every other absorbed byte is
        // zero and can be copied as a whole 16-bit limb.
        for slot in 0..ABSORB_BYTES {
            for bit in 0..8 {
                let value: AB::Expr = row[ABSORB_BITS_OFFSET + slot * 8 + bit].into();
                builder.assert_zero(value.clone() * (value - one.clone()));
            }
        }
        let first_absorption_end =
            path_active.clone() * final_step.clone() * (one.clone() - phase.clone());
        for y in 0..5 {
            for x in 0..5 {
                let lane = y * 5 + x;
                for limb in 0..4 {
                    let global_limb = lane * 4 + limb;
                    let low_slot = absorb_byte_slot(global_limb * 2);
                    let high_slot = absorb_byte_slot(global_limb * 2 + 1);
                    if let (Some(low_slot), Some(high_slot)) = (low_slot, high_slot) {
                        let mut reconstructed = AB::Expr::ZERO;
                        for bit in 0..16 {
                            let slot = if bit < 8 { low_slot } else { high_slot };
                            let in_byte_bit = bit & 7;
                            let b: AB::Expr =
                                row[ABSORB_BITS_OFFSET + slot * 8 + in_byte_bit].into();
                            reconstructed += b * AB::Expr::from_u32(1 << bit);
                        }
                        let actual: AB::Expr = keccak.a_prime_prime_prime(y, x, limb).into();
                        builder
                            .when(first_absorption_end.clone())
                            .assert_zero(actual - reconstructed);
                    }
                }
            }
        }
        let second_block_boundary = transition.clone()
            * path_active.clone()
            * final_step.clone()
            * (one.clone() - phase.clone());
        for y in 0..5 {
            for x in 0..5 {
                let lane = y * 5 + x;
                for limb in 0..4 {
                    let state_byte = lane * 8 + limb * 2;
                    let actual: AB::Expr = keccak.a_prime_prime_prime(y, x, limb).into();
                    let expected = if let (Some(low_slot), Some(high_slot)) = (
                        absorb_byte_slot(state_byte),
                        absorb_byte_slot(state_byte + 1),
                    ) {
                        let mut value = AB::Expr::ZERO;
                        for bit in 0..16 {
                            let slot = if bit < 8 { low_slot } else { high_slot };
                            let in_byte_bit = bit & 7;
                            let output_bit: AB::Expr =
                                row[ABSORB_BITS_OFFSET + slot * 8 + in_byte_bit].into();
                            let block_bit: AB::Expr = frame_bit64::<AB>(
                                next,
                                SHAKE_RATE_BYTES + state_byte + bit / 8,
                                in_byte_bit,
                            );
                            let xor = output_bit.clone() + block_bit.clone()
                                - output_bit * block_bit * AB::Expr::from_u32(2);
                            value += xor * AB::Expr::from_u32(1 << bit);
                        }
                        value
                    } else {
                        actual.clone()
                    };
                    builder
                        .when(second_block_boundary.clone())
                        .assert_zero(next_keccak.preimage[y][x][limb] - expected);
                }
            }
        }
        // The public root is bound only to the final (level 63, phase 1) hash.
        let mut root_selector = hash_end * (one.clone() - level[6].clone());
        for bit in 0..6 {
            root_selector = root_selector * level[bit].clone();
        }
        for limb in 0..OUTPUT_LIMBS {
            let lo: AB::Expr = builder.public_values()[limb * 2].into();
            let hi: AB::Expr = builder.public_values()[limb * 2 + 1].into();
            let actual: AB::Expr = row[output_limb(limb)].into();
            builder
                .when(root_selector.clone())
                .assert_zero(actual - (lo + hi * AB::Expr::from_u32(256)));
        }
        if self.source_bound {
            eval_fixed_source156_constraints(
                builder,
                row,
                next,
                keccak,
                next_keccak,
                transition.clone(),
                first_step.clone(),
                final_step.clone(),
                source_stage.clone(),
                level.clone(),
                phase.clone(),
                one.clone(),
                note_end.clone(),
            );
        }
        if self.note_bound {
            eval_note_commitment_constraints(
                builder,
                row,
                next,
                keccak,
                next_keccak,
                transition.clone(),
                first_step.clone(),
                final_step.clone(),
                note_stage.clone(),
                phase.clone(),
                one.clone(),
                None,
            );
            if self.output_note_balance_bound {
                eval_note_commitment_constraints(
                    builder,
                    row,
                    next,
                    keccak,
                    next_keccak,
                    transition.clone(),
                    first_step.clone(),
                    final_step.clone(),
                    output_note_stage.clone(),
                    phase.clone(),
                    one.clone(),
                    Some(
                        PUBLIC_ROOT_PREFIX_BYTES
                            + crate::transaction_statement::STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET,
                    ),
                );
                eval_output_value_balance_constraints(
                    builder,
                    row,
                    output_note_stage.clone(),
                    first_step.clone(),
                );
                let input_note_start =
                    note_stage.clone() * first_step.clone() * (one.clone() - phase.clone());
                for bit in 0..64 {
                    let saved: AB::Expr = row[INPUT_VALUE_BITS_OFFSET + bit].into();
                    builder.assert_zero(saved.clone() * (saved.clone() - one.clone()));
                    let next_saved: AB::Expr = next[INPUT_VALUE_BITS_OFFSET + bit].into();
                    builder
                        .when(transition.clone())
                        .assert_zero(next_saved - saved.clone());
                    let note_bit: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + 64 * 8 + bit].into();
                    builder
                        .when(input_note_start.clone())
                        .assert_zero(saved - note_bit);
                }
                let output_end = output_note_stage.clone() * final_step.clone() * phase.clone();
                let output_hold =
                    transition.clone() * output_note_stage.clone() * (one.clone() - output_end);
                for bit in 0..(200 * 8) {
                    let current: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + bit].into();
                    let following: AB::Expr = next[NOTE_PRIVATE_BITS_OFFSET + bit].into();
                    builder
                        .when(output_hold.clone())
                        .assert_zero(following - current);
                }
                let inverse: AB::Expr = row[NOTE_INVERSE_OFFSET].into();
                let next_inverse: AB::Expr = next[NOTE_INVERSE_OFFSET].into();
                builder
                    .when(output_hold.clone())
                    .assert_zero(next_inverse - inverse);
                for carry in 0..3 {
                    let current: AB::Expr = row[BALANCE_CARRY_BITS_OFFSET + carry].into();
                    let following: AB::Expr = next[BALANCE_CARRY_BITS_OFFSET + carry].into();
                    builder.assert_zero(
                        output_note_stage.clone()
                            * current.clone()
                            * (current.clone() - one.clone()),
                    );
                    builder
                        .when(output_hold.clone())
                        .assert_zero(following - current);
                }
            }
            for bit in 0..SOURCE_BUFFER_BITS {
                let value: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
                builder.assert_zero(note_stage.clone() * value.clone() * (value - one.clone()));
            }
            let source_start =
                source_stage.clone() * first_step.clone() * source_block_selector::<AB>(&level, 0);
            for byte in 0..DIGEST_BYTES {
                let source_commitment_byte = source_buffer_byte::<AB>(row, 27 + byte);
                let sibling_byte = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                    let value: AB::Expr = row[SIBLING_BITS + byte * 8 + bit].into();
                    acc + value * AB::Expr::from_u32(1 << bit)
                });
                builder
                    .when(source_start.clone())
                    .assert_zero(source_commitment_byte - sibling_byte);
            }
            let source_end = source_stage.clone()
                * final_step.clone()
                * source_block_selector::<AB>(&level, SOURCE_BLOCKS - 1);
            let sibling_hold = transition.clone()
                * (note_stage.clone() + source_stage.clone() * (one.clone() - source_end));
            for bit in 0..DIGEST_BYTES * 8 {
                let current: AB::Expr = row[SIBLING_BITS + bit].into();
                let following: AB::Expr = next[SIBLING_BITS + bit].into();
                builder
                    .when(sibling_hold.clone())
                    .assert_zero(following - current);
            }
        }
        if self.spend_owner_bound {
            eval_spend_owner_constraints(
                builder,
                row,
                next,
                keccak,
                next_keccak,
                transition.clone(),
                first_step.clone(),
                final_step.clone(),
                spend_pk_stage,
                note_owner_stage,
                nullifier_stage.clone(),
                one.clone(),
            );
        }
        if self.nullifier_bound {
            eval_nullifier_constraints(
                builder,
                row,
                next,
                keccak,
                next_keccak,
                transition,
                first_step,
                final_step,
                nullifier_stage,
                phase,
            );
        }
    }
}
fn spend_owner_private_byte<AB: AirBuilder<F = Val>>(
    row: &[AB::Var],
    byte_index: usize,
) -> AB::Expr {
    (0..8).fold(AB::Expr::ZERO, |value, bit| {
        let b: AB::Expr = row[SPEND_OWNER_PRIVATE_BITS_OFFSET + byte_index * 8 + bit].into();
        value + b * AB::Expr::from_u32(1 << bit)
    })
}
fn spend_pk_frame_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], offset: usize) -> AB::Expr
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
        31..=94 => spend_owner_private_byte::<AB>(row, offset - 31),
        95 => constant(0x1f),
        135 => constant(0x80),
        _ => constant(0),
    }
}
fn note_owner_frame_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], offset: usize) -> AB::Expr
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
        31..=94 => source_buffer_byte::<AB>(row, offset - 31),
        95 => constant(32),
        96..=98 => constant(0),
        99..=130 => spend_owner_private_byte::<AB>(row, 64 + offset - 99),
        131 => constant(0x1f),
        135 => constant(0x80),
        _ => constant(0),
    }
}
fn nullifier_frame_constant(offset: usize) -> u8 {
    const TAG: &[u8] = b"radix/nullifier/v1";
    match offset {
        0..=4 => b"RADIX"[offset],
        5 => 1,
        6 => TAG.len() as u8,
        7 => 0,
        8..=25 => TAG[offset - 8],
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
fn nullifier_padded_frame_bit<AB: AirBuilder<F = Val>>(
    row: &[AB::Var],
    offset: usize,
    bit_index: usize,
) -> AB::Expr {
    if offset < 200 {
        let private_bit = match offset {
            32..=95 => Some(SPEND_OWNER_PRIVATE_BITS_OFFSET + (offset - 32) * 8 + bit_index),
            100..=131 => {
                Some(SPEND_OWNER_PRIVATE_BITS_OFFSET + (64 + offset - 100) * 8 + bit_index)
            }
            136..=199 => Some(NOTE_PRIVATE_BITS_OFFSET + (72 + offset - 136) * 8 + bit_index),
            _ => None,
        };
        if let Some(index) = private_bit {
            row[index].into()
        } else {
            AB::Expr::from_u32(u32::from(
                (nullifier_frame_constant(offset) >> bit_index) & 1,
            ))
        }
    } else if offset == 200 {
        AB::Expr::from_u32(u32::from((0x1fu8 >> bit_index) & 1))
    } else if offset == 271 {
        AB::Expr::from_u32(u32::from((0x80u8 >> bit_index) & 1))
    } else {
        AB::Expr::ZERO
    }
}
fn eval_nullifier_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    keccak: &KeccakCols<AB::Var>,
    next_keccak: &KeccakCols<AB::Var>,
    transition: AB::Expr,
    first_step: AB::Expr,
    final_step: AB::Expr,
    nullifier_stage: AB::Expr,
    phase: AB::Expr,
) {
    let one = AB::Expr::ONE;
    let first_absorption_end = transition.clone()
        * nullifier_stage.clone()
        * final_step.clone()
        * (one.clone() - phase.clone());
    for bit in 0..SOURCE_BUFFER_BITS {
        let value: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder
            .assert_zero(nullifier_stage.clone() * value.clone() * (value.clone() - one.clone()));
    }
    let first_block_start = nullifier_stage.clone() * first_step * (one.clone() - phase.clone());
    for limb in 0..RATE_LIMBS {
        let mut expected = AB::Expr::ZERO;
        for bit in 0..16 {
            let frame_bit = nullifier_padded_frame_bit::<AB>(row, limb * 2 + bit / 8, bit % 8);
            expected += frame_bit * AB::Expr::from_u32(1 << bit);
        }
        builder
            .when(first_block_start.clone())
            .assert_zero(keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4] - expected);
    }
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                if y * 20 + x * 4 + limb >= RATE_LIMBS {
                    builder
                        .when(first_block_start.clone())
                        .assert_zero(keccak.preimage[y][x][limb]);
                }
            }
        }
    }

    // Preserve the first block's rate output in the reused 136-byte source buffer.
    for limb in 0..RATE_LIMBS {
        let mut reconstructed = AB::Expr::ZERO;
        for bit in 0..16 {
            let value: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + limb * 16 + bit].into();
            reconstructed += value * AB::Expr::from_u32(1 << bit);
        }
        let actual: AB::Expr = keccak
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .into();
        builder
            .when(first_absorption_end.clone())
            .assert_zero(actual - reconstructed);
    }

    // The second-block rate is Keccak(state) XOR padded rho/domain bytes; capacity is unchanged.
    let second_block_boundary = transition.clone()
        * nullifier_stage.clone()
        * final_step.clone()
        * (one.clone() - phase.clone());
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                let lane_limb = y * 20 + x * 4 + limb;
                let expected = if lane_limb < RATE_LIMBS {
                    let mut value = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let state_byte = (y * 5 + x) * 8 + limb * 2 + bit / 8;
                        let state_bit: AB::Expr =
                            next[SOURCE_BUFFER_BITS_OFFSET + state_byte * 8 + bit % 8].into();
                        let block_bit = nullifier_padded_frame_bit::<AB>(
                            next,
                            SHAKE_RATE_BYTES + state_byte,
                            bit % 8,
                        );
                        let xor = state_bit.clone() + block_bit.clone()
                            - state_bit * block_bit * AB::Expr::from_u32(2);
                        value += xor * AB::Expr::from_u32(1 << bit);
                    }
                    value
                } else {
                    keccak.a_prime_prime_prime(y, x, limb).into()
                };
                builder
                    .when(second_block_boundary.clone())
                    .assert_zero(next_keccak.preimage[y][x][limb] - expected);
            }
        }
    }

    let nullifier_end = nullifier_stage.clone() * final_step.clone() * phase;
    // On active transitions, the carried buffer is unchanged except at each block's final row.
    let buffer_hold = transition * nullifier_stage * (one - final_step);
    for bit in 0..SOURCE_BUFFER_BITS {
        let current: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        let following: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder
            .when(buffer_hold.clone())
            .assert_zero(following - current);
    }
    let digest_selector = nullifier_end;
    for limb in 0..OUTPUT_LIMBS {
        let lo: AB::Expr = builder.public_values()[PUBLIC_NULLIFIER_BYTES_OFFSET + limb * 2].into();
        let hi: AB::Expr =
            builder.public_values()[PUBLIC_NULLIFIER_BYTES_OFFSET + 1 + limb * 2].into();
        let actual: AB::Expr = row[output_limb(limb)].into();
        builder
            .when(digest_selector.clone())
            .assert_zero(actual - (lo + hi * AB::Expr::from_u32(256)));
    }
}
fn eval_spend_owner_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    keccak: &KeccakCols<AB::Var>,
    _next_keccak: &KeccakCols<AB::Var>,
    transition: AB::Expr,
    first_step: AB::Expr,
    final_step: AB::Expr,
    spend_pk_stage: AB::Expr,
    note_owner_stage: AB::Expr,
    nullifier_stage: AB::Expr,
    one: AB::Expr,
) {
    // These byte witnesses are shared by both hash stages and remain fixed over the full trace.
    for byte in 0..SPEND_OWNER_PRIVATE_BYTES {
        let value: AB::Expr = row[SPEND_OWNER_PRIVATE_OFFSET + byte].into();
        let reconstructed = spend_owner_private_byte::<AB>(row, byte);
        builder.assert_zero(value - reconstructed);
    }
    for bit in 0..(SPEND_OWNER_PRIVATE_BYTES * 8) {
        let value: AB::Expr = row[SPEND_OWNER_PRIVATE_BITS_OFFSET + bit].into();
        builder.assert_zero(value.clone() * (value.clone() - one.clone()));
        let following: AB::Expr = next[SPEND_OWNER_PRIVATE_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone())
            .assert_zero(following - value);
    }
    // Keep the note witness selected by the owner stage identical at the note-stage boundary.
    for bit in 0..(200 * 8) {
        let current: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + bit].into();
        let following: AB::Expr = next[NOTE_PRIVATE_BITS_OFFSET + bit].into();
        builder
            .when(
                transition.clone()
                    * (spend_pk_stage.clone() + note_owner_stage.clone() + nullifier_stage.clone()),
            )
            .assert_zero(following - current);
    }
    for byte in 0..SPEND_OWNER_PRIVATE_BYTES {
        let value: AB::Expr = row[SPEND_OWNER_PRIVATE_OFFSET + byte].into();
        let following: AB::Expr = next[SPEND_OWNER_PRIVATE_OFFSET + byte].into();
        builder
            .when(transition.clone())
            .assert_zero(following - value);
    }

    let spend_pk_start = spend_pk_stage.clone() * first_step.clone();
    let owner_start = note_owner_stage.clone() * first_step;
    for limb in 0..RATE_LIMBS {
        let low = spend_pk_frame_byte::<AB>(row, limb * 2);
        let high = spend_pk_frame_byte::<AB>(row, limb * 2 + 1);
        let expected = low + high * Val::from_u32(256);
        builder
            .when(spend_pk_start.clone())
            .assert_zero(keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4] - expected);
        let owner_low = note_owner_frame_byte::<AB>(row, limb * 2);
        let owner_high = note_owner_frame_byte::<AB>(row, limb * 2 + 1);
        let owner_expected = owner_low + owner_high * Val::from_u32(256);
        builder
            .when(owner_start.clone())
            .assert_zero(keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4] - owner_expected);
    }
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                if y * 20 + x * 4 + limb >= RATE_LIMBS {
                    builder
                        .when(spend_pk_start.clone())
                        .assert_zero(keccak.preimage[y][x][limb]);
                    builder
                        .when(owner_start.clone())
                        .assert_zero(keccak.preimage[y][x][limb]);
                }
            }
        }
    }

    // The spend-key hash output is the private pk input to the immediately following owner hash.
    let spend_pk_end = transition * spend_pk_stage.clone() * final_step.clone();
    for limb in 0..(DIGEST_BYTES / 2) {
        let low = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
            let value: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + limb * 16 + bit].into();
            acc + value * AB::Expr::from_u32(1 << bit)
        });
        let high = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
            let value: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + limb * 16 + 8 + bit].into();
            acc + value * AB::Expr::from_u32(1 << bit)
        });
        let output: AB::Expr = keccak
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .into();
        builder
            .when(spend_pk_end.clone())
            .assert_zero(output - (low + high * AB::Expr::from_u32(256)));
    }
    for bit in 0..(DIGEST_BYTES * 8) {
        let value: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder
            .when(note_owner_stage.clone())
            .assert_zero(value.clone() * (value - one.clone()));
    }

    // The owner hash must equal the owner in the same private note opening consumed by RDXI.
    let owner_end = note_owner_stage * final_step;
    for limb in 0..(DIGEST_BYTES / 2) {
        let low = note_private_byte::<AB>(row, limb * 2);
        let high = note_private_byte::<AB>(row, limb * 2 + 1);
        let output: AB::Expr = keccak
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .into();
        builder
            .when(owner_end.clone())
            .assert_zero(output - (low + high * AB::Expr::from_u32(256)));
    }
}
fn eval_output_leaf_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    keccak: &KeccakCols<AB::Var>,
    next_keccak: &KeccakCols<AB::Var>,
    transition: AB::Expr,
    first_step: AB::Expr,
    final_step: AB::Expr,
    output_note_end: AB::Expr,
    output_leaf_stage: AB::Expr,
) {
    let one = AB::Expr::ONE;
    let public_offset = builder.public_values().len() - OUTPUT_LEAF_PUBLIC_VALUES;
    let block_count: AB::Expr = builder.public_values()[public_offset].into();
    let mut public_last_index = AB::Expr::ZERO;
    for bit in 0..4 {
        let value: AB::Expr = builder.public_values()[public_offset + 1 + bit].into();
        builder.assert_zero(value.clone() * (value.clone() - one.clone()));
        public_last_index += value * AB::Expr::from_u32(1 << bit);
    }
    builder.assert_zero(block_count.clone() - public_last_index.clone() - one.clone());
    let mut valid_count = AB::Expr::ONE;
    for count in 10..=14 {
        valid_count *= block_count.clone() - AB::Expr::from_u32(count);
    }
    builder.assert_zero(valid_count);

    let last_selector = output_leaf_last_selector(builder, row, public_offset);
    let leaf_end = output_leaf_stage.clone() * final_step.clone() * last_selector.clone();
    let nonfinal_block_end =
        output_leaf_stage.clone() * final_step.clone() * (one.clone() - last_selector.clone());
    let next_leaf: AB::Expr = next[OUTPUT_LEAF_ACTIVE_OFFSET].into();
    builder.when(transition.clone()).assert_zero(
        next_leaf - (output_leaf_stage.clone() - leaf_end.clone() + output_note_end.clone()),
    );

    let block_public_offset = public_offset + OUTPUT_LEAF_PUBLIC_META_VALUES;
    let mut slot_selectors = Vec::with_capacity(OUTPUT_LEAF_BLOCK_SLOTS);
    let mut selector_sum = AB::Expr::ZERO;
    for slot in 0..OUTPUT_LEAF_BLOCK_SLOTS {
        let selector: AB::Expr = output_leaf_slot_selector::<AB>(row, slot);
        selector_sum += selector.clone();
        slot_selectors.push(selector);
    }
    builder.assert_zero(output_leaf_stage.clone() * (selector_sum - one.clone()));

    for bit in 0..4 {
        let current = row[OUTPUT_LEAF_INDEX_BITS_OFFSET + bit];
        let current_expr: AB::Expr = current.into();
        let next_expr: AB::Expr = next[OUTPUT_LEAF_INDEX_BITS_OFFSET + bit].into();
        let mut carry = nonfinal_block_end.clone();
        for lower in 0..bit {
            carry = carry * (row[OUTPUT_LEAF_INDEX_BITS_OFFSET + lower]).into();
        }
        let updated =
            current_expr.clone() + carry.clone() - current_expr * carry * AB::Expr::from_u32(2);
        builder
            .when(transition.clone() * (one.clone() - leaf_end.clone()))
            .assert_zero(next_expr.clone() - updated);
        builder
            .when(transition.clone() * leaf_end.clone())
            .assert_zero(next_expr);
    }

    for bit in 0..SOURCE_BUFFER_BITS {
        let state_bit: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        let block_bit: AB::Expr = row[OUTPUT_LEAF_BLOCK_BITS_OFFSET + bit].into();
        builder.assert_zero(
            output_leaf_stage.clone() * state_bit.clone() * (state_bit.clone() - one.clone()),
        );
        builder.assert_zero(
            output_leaf_stage.clone() * block_bit.clone() * (block_bit.clone() - one.clone()),
        );
        let next_state_bit: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder
            .when(
                transition.clone() * output_leaf_stage.clone() * (one.clone() - final_step.clone()),
            )
            .assert_zero(next_state_bit - state_bit);
    }
    for byte in 0..SHAKE_RATE_BYTES {
        let mut witnessed = AB::Expr::ZERO;
        for bit in 0..8 {
            let value: AB::Expr = row[OUTPUT_LEAF_BLOCK_BITS_OFFSET + byte * 8 + bit].into();
            witnessed += value * AB::Expr::from_u32(1 << bit);
        }
        let expected =
            slot_selectors
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (slot, selector)| {
                    let value: AB::Expr = builder.public_values()
                        [block_public_offset + slot * SHAKE_RATE_BYTES + byte]
                        .into();
                    sum + selector.clone() * value
                });
        builder
            .when(output_leaf_stage.clone())
            .assert_zero(witnessed - expected);
    }

    let first_block_start: AB::Expr =
        output_leaf_stage.clone() * first_step * output_leaf_slot_selector::<AB>(row, 0);
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                let lane_limb = y * 20 + x * 4 + limb;
                let expected = if lane_limb < RATE_LIMBS {
                    let byte = lane_limb * 2;
                    let mut value = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let block_bit: AB::Expr = row
                            [OUTPUT_LEAF_BLOCK_BITS_OFFSET + (byte + bit / 8) * 8 + bit % 8]
                            .into();
                        value += block_bit * AB::Expr::from_u32(1 << bit);
                    }
                    value
                } else {
                    AB::Expr::ZERO
                };
                builder
                    .when(first_block_start.clone())
                    .assert_zero(keccak.preimage[y][x][limb] - expected);
            }
        }
    }

    let block_boundary = transition.clone()
        * output_leaf_stage.clone()
        * final_step.clone()
        * (one.clone() - last_selector.clone());
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                let lane_limb = y * 20 + x * 4 + limb;
                let actual: AB::Expr = keccak.a_prime_prime_prime(y, x, limb).into();
                if lane_limb < RATE_LIMBS {
                    let byte = lane_limb * 2;
                    let mut reconstructed = AB::Expr::ZERO;
                    let mut absorbed = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let state_bit: AB::Expr =
                            next[SOURCE_BUFFER_BITS_OFFSET + byte * 8 + bit].into();
                        reconstructed += state_bit.clone() * AB::Expr::from_u32(1 << bit);
                        let block_bit: AB::Expr = next
                            [OUTPUT_LEAF_BLOCK_BITS_OFFSET + (byte + bit / 8) * 8 + bit % 8]
                            .into();
                        let xor = state_bit.clone() + block_bit.clone()
                            - state_bit * block_bit * AB::Expr::from_u32(2);
                        absorbed += xor * AB::Expr::from_u32(1 << bit);
                    }
                    builder
                        .when(block_boundary.clone())
                        .assert_zero(actual.clone() - reconstructed);
                    builder
                        .when(block_boundary.clone())
                        .assert_zero(next_keccak.preimage[y][x][limb] - absorbed);
                } else {
                    builder
                        .when(block_boundary.clone())
                        .assert_zero(next_keccak.preimage[y][x][limb] - actual);
                }
            }
        }
    }
    for bit in 0..SOURCE_BUFFER_BITS {
        let next_bit: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone() * output_note_end.clone())
            .assert_zero(next_bit.clone());
        builder
            .when(transition.clone() * leaf_end.clone())
            .assert_zero(next_bit);
    }
    let digest_offset = block_public_offset + OUTPUT_LEAF_PUBLIC_BLOCKS_VALUES;
    for limb in 0..(DIGEST_BYTES / 2) {
        let low: AB::Expr = builder.public_values()[digest_offset + limb * 2].into();
        let high: AB::Expr = builder.public_values()[digest_offset + limb * 2 + 1].into();
        let actual: AB::Expr = row[output_limb(limb)].into();
        builder
            .when(leaf_end.clone())
            .assert_zero(actual - (low + high * AB::Expr::from_u32(256)));
    }
}
fn eval_input_kdf_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    keccak: &KeccakCols<AB::Var>,
    next_keccak: &KeccakCols<AB::Var>,
    transition: AB::Expr,
    first_step: AB::Expr,
    final_step: AB::Expr,
    output_leaf_stage: AB::Expr,
    input_kdf_stage: AB::Expr,
) {
    let one = AB::Expr::ONE;
    let public_offset = builder.public_values().len() - OUTPUT_LEAF_PUBLIC_VALUES;
    let output_last_selector = output_leaf_last_selector(builder, row, public_offset);
    let output_leaf_end = output_leaf_stage.clone() * final_step.clone() * output_last_selector;
    let final_kdf_selector = input_kdf_block_selector::<AB>(row, INPUT_KDF_BLOCKS - 1);
    let kdf_end = input_kdf_stage.clone() * final_step.clone() * final_kdf_selector.clone();
    let kdf_end_transition = transition.clone() * kdf_end.clone();
    let output_mode: AB::Expr = row[CRYPTO_OUTPUT_MODE_OFFSET].into();
    let block_active: AB::Expr = row[AES256_BLOCK_ACTIVE_OFFSET].into();
    let block_round_bits: [AB::Expr; 4] =
        core::array::from_fn(|bit| row[AES256_BLOCK_INDEX_BITS_OFFSET + bit].into());
    let block_number_bits: [AB::Expr; 4] =
        core::array::from_fn(|bit| row[AES256_BLOCK_NUMBER_BITS_OFFSET + bit].into());
    let round_14 = (0..4).fold(AB::Expr::ONE, |selector, bit| {
        selector
            * if (14 >> bit) & 1 == 1 {
                block_round_bits[bit].clone()
            } else {
                one.clone() - block_round_bits[bit].clone()
            }
    });
    let block_8 = (0..4).fold(AB::Expr::ONE, |selector, bit| {
        selector
            * if (8 >> bit) & 1 == 1 {
                block_number_bits[bit].clone()
            } else {
                one.clone() - block_number_bits[bit].clone()
            }
    });
    let input_aes_end = block_active * round_14 * block_8 * (one.clone() - output_mode.clone());
    let next_active: AB::Expr = next[INPUT_KDF_ACTIVE_OFFSET].into();
    builder.when(transition.clone()).assert_zero(
        next_active
            - (input_kdf_stage.clone() - kdf_end.clone()
                + output_leaf_end.clone()
                + input_aes_end.clone()),
    );
    builder.assert_zero(input_kdf_stage.clone() * (input_kdf_stage.clone() - one.clone()));
    builder.assert_zero(input_kdf_stage.clone() * output_leaf_stage.clone());
    for (byte_index, expected) in [OUTPUT_CIPHERTEXT_BYTES as u8, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        let actual: AB::Expr =
            builder.public_values()[OUTPUT_CIPHERTEXT_LENGTH_PUBLIC_OFFSET + byte_index].into();
        builder
            .when(input_kdf_stage.clone() * output_mode.clone())
            .assert_zero(actual - AB::Expr::from_u32(u32::from(expected)));
    }

    let mut selectors = Vec::with_capacity(INPUT_KDF_BLOCKS);
    let mut selector_sum = AB::Expr::ZERO;
    for block in 0..INPUT_KDF_BLOCKS {
        let selector = input_kdf_block_selector::<AB>(row, block);
        selector_sum += selector.clone();
        selectors.push(selector);
    }
    builder.assert_zero(input_kdf_stage.clone() * (selector_sum - one.clone()));
    for bit in 0..4 {
        let current: AB::Expr = row[INPUT_KDF_INDEX_BITS_OFFSET + bit].into();
        let next_bit: AB::Expr = next[INPUT_KDF_INDEX_BITS_OFFSET + bit].into();
        builder.assert_zero(current.clone() * (current.clone() - one.clone()));
        builder.assert_zero((one.clone() - input_kdf_stage.clone()) * current.clone());
        let mut carry = input_kdf_stage.clone()
            * final_step.clone()
            * (one.clone() - final_kdf_selector.clone());
        for lower in 0..bit {
            let lower_bit: AB::Expr = row[INPUT_KDF_INDEX_BITS_OFFSET + lower].into();
            carry = carry * lower_bit;
        }
        let updated = current.clone() + carry.clone() - current * carry * AB::Expr::from_u32(2);
        builder
            .when(transition.clone() * (one.clone() - kdf_end.clone()))
            .assert_zero(next_bit.clone() - updated);
        builder
            .when(kdf_end_transition.clone())
            .assert_zero(next_bit.clone());
        builder
            .when(transition.clone() * output_leaf_end.clone())
            .assert_zero(next_bit.clone());
        builder
            .when(transition.clone() * input_aes_end.clone())
            .assert_zero(next_bit);
    }

    // Reuse the transient rate-block bit columns in this mutually exclusive
    // stage; the output-leaf counter and selectors remain independent.
    for byte in 0..SHAKE_RATE_BYTES {
        let mut witnessed = AB::Expr::ZERO;
        for bit in 0..8 {
            let value: AB::Expr = row[INPUT_KDF_BLOCK_BITS_OFFSET + byte * 8 + bit].into();
            builder.assert_zero(
                input_kdf_stage.clone() * value.clone() * (value.clone() - one.clone()),
            );
            witnessed += value * AB::Expr::from_u32(1 << bit);
        }
        let expected =
            selectors
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (block, selector)| {
                    let offset = block * SHAKE_RATE_BYTES + byte;
                    let input_frame = input_kdf_frame_byte::<AB>(row, offset);
                    let output_frame = output_kdf_frame_byte::<AB>(builder, row, offset);
                    let frame = input_frame * (one.clone() - output_mode.clone())
                        + output_frame * output_mode.clone();
                    sum + selector.clone() * frame
                });
        builder
            .when(input_kdf_stage.clone())
            .assert_zero(witnessed - expected);
    }

    for bit in 0..SOURCE_BUFFER_BITS {
        let state_bit: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder.assert_zero(
            input_kdf_stage.clone() * state_bit.clone() * (state_bit.clone() - one.clone()),
        );
        let next_bit: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone() * input_kdf_stage.clone() * (one.clone() - final_step.clone()))
            .assert_zero(next_bit - state_bit);
    }

    let first_block_start =
        input_kdf_stage.clone() * first_step * input_kdf_block_selector::<AB>(row, 0);
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                let lane_limb = y * 20 + x * 4 + limb;
                let expected = if lane_limb < RATE_LIMBS {
                    let byte = lane_limb * 2;
                    (0..16).fold(AB::Expr::ZERO, |value, bit| {
                        let block_bit: AB::Expr = row
                            [INPUT_KDF_BLOCK_BITS_OFFSET + (byte + bit / 8) * 8 + bit % 8]
                            .into();
                        value + block_bit * AB::Expr::from_u32(1 << bit)
                    })
                } else {
                    AB::Expr::ZERO
                };
                let preimage: AB::Expr = keccak.preimage[y][x][limb].into();
                builder
                    .when(first_block_start.clone())
                    .assert_zero(preimage - expected);
            }
        }
    }

    let block_boundary = transition.clone()
        * input_kdf_stage.clone()
        * final_step.clone()
        * (one.clone() - final_kdf_selector.clone());
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                let lane_limb = y * 20 + x * 4 + limb;
                let actual: AB::Expr = keccak.a_prime_prime_prime(y, x, limb).into();
                if lane_limb < RATE_LIMBS {
                    let byte = lane_limb * 2;
                    let mut reconstructed = AB::Expr::ZERO;
                    let mut absorbed = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let state_bit: AB::Expr =
                            next[SOURCE_BUFFER_BITS_OFFSET + byte * 8 + bit].into();
                        let output_state_gate = block_boundary.clone() + kdf_end_transition.clone();
                        builder.assert_zero(
                            output_state_gate
                                * state_bit.clone()
                                * (state_bit.clone() - one.clone()),
                        );
                        reconstructed += state_bit.clone() * AB::Expr::from_u32(1 << bit);
                        let block_bit: AB::Expr = next
                            [INPUT_KDF_BLOCK_BITS_OFFSET + (byte + bit / 8) * 8 + bit % 8]
                            .into();
                        let xor = state_bit.clone() + block_bit.clone()
                            - state_bit * block_bit * AB::Expr::from_u32(2);
                        absorbed += xor * AB::Expr::from_u32(1 << bit);
                    }
                    builder
                        .when(block_boundary.clone() + kdf_end_transition.clone())
                        .assert_zero(actual.clone() - reconstructed);
                    builder
                        .when(block_boundary.clone())
                        .assert_zero(next_keccak.preimage[y][x][limb] - absorbed);
                    for byte_in_limb in 0..2 {
                        if lane_limb * 2 + byte_in_limb < 32 {
                            let byte_bits = (0..8).fold(AB::Expr::ZERO, |value, bit| {
                                let output_bit: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET
                                    + (lane_limb * 2 + byte_in_limb) * 8
                                    + bit]
                                    .into();
                                value + output_bit * AB::Expr::from_u32(1 << bit)
                            });
                            let key: AB::Expr = row
                                [INPUT_KDF_KEY_BYTES_OFFSET + lane_limb * 2 + byte_in_limb]
                                .into();
                            builder
                                .when(kdf_end_transition.clone())
                                .assert_zero(key - byte_bits);
                        }
                    }
                } else {
                    builder
                        .when(block_boundary.clone())
                        .assert_zero(next_keccak.preimage[y][x][limb] - actual.clone());
                }
            }
        }
    }
}
fn eval_aes256_key_schedule_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    transition: AB::Expr,
    final_step: AB::Expr,
    input_kdf_stage: AB::Expr,
) {
    let one = AB::Expr::ONE;
    let two = AB::Expr::from_u32(2);
    let key_stage: AB::Expr = row[AES256_KEY_SCHEDULE_ACTIVE_OFFSET].into();
    let next_key_stage: AB::Expr = next[AES256_KEY_SCHEDULE_ACTIVE_OFFSET].into();
    let block_stage: AB::Expr = row[AES256_BLOCK_ACTIVE_OFFSET].into();
    let block_index: [AB::Expr; 4] =
        core::array::from_fn(|bit| row[AES256_BLOCK_INDEX_BITS_OFFSET + bit].into());
    let block_round_14 = (0..4).fold(AB::Expr::ONE, |selector, bit| {
        let literal = if (14 >> bit) & 1 == 1 {
            block_index[bit].clone()
        } else {
            one.clone() - block_index[bit].clone()
        };
        selector * literal
    });
    let block_end = block_stage.clone() * block_round_14;
    let schedule_live = key_stage.clone() + block_stage.clone();
    builder.assert_zero(key_stage.clone() * block_stage);
    builder.assert_zero(key_stage.clone() * (key_stage.clone() - one.clone()));
    builder.when_first_row().assert_zero(key_stage.clone());
    builder.when_last_row().assert_zero(key_stage.clone());

    let index_bits: [AB::Expr; 4] =
        core::array::from_fn(|bit| row[AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET + bit].into());
    for bit in 0..4 {
        builder.assert_zero(
            key_stage.clone() * index_bits[bit].clone() * (index_bits[bit].clone() - one.clone()),
        );
        builder.assert_zero((one.clone() - key_stage.clone()) * index_bits[bit].clone());
    }
    let selectors: Vec<AB::Expr> = (0..16)
        .map(|index| {
            (0..4).fold(AB::Expr::ONE, |selector, bit| {
                let literal = if (index >> bit) & 1 == 1 {
                    index_bits[bit].clone()
                } else {
                    one.clone() - index_bits[bit].clone()
                };
                selector * literal
            })
        })
        .collect();
    for selector in &selectors[AES256_KEY_SCHEDULE_ROWS..] {
        builder.assert_zero(key_stage.clone() * selector.clone());
    }
    let key_end = key_stage.clone() * selectors[AES256_KEY_SCHEDULE_ROWS - 1].clone();
    let kdf_end = input_kdf_stage.clone()
        * final_step.clone()
        * input_kdf_block_selector::<AB>(row, INPUT_KDF_BLOCKS - 1);
    builder.assert_zero(key_stage.clone() * kdf_end.clone());
    builder
        .when(transition.clone())
        .assert_zero(next_key_stage.clone() - (key_stage.clone() - key_end.clone() + kdf_end));
    for bit in 0..4 {
        let mut carry = key_stage.clone();
        for lower in 0..bit {
            carry = carry * index_bits[lower].clone();
        }
        let incremented =
            index_bits[bit].clone() + carry.clone() - index_bits[bit].clone() * carry * two.clone();
        let expected = (key_stage.clone() - key_end.clone()) * incremented;
        let next_bit: AB::Expr = next[AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone())
            .assert_zero(next_bit - expected);
    }

    for bit in 0..AES256_EXPANDED_KEY_BITS {
        let current: AB::Expr = row[AES256_KEY_SCHEDULE_BITS_OFFSET + bit].into();
        let following: AB::Expr = next[AES256_KEY_SCHEDULE_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone() * (schedule_live.clone() - block_end.clone()))
            .assert_zero(following - current.clone());
        builder.assert_zero(schedule_live.clone() * current.clone() * (current - one.clone()));
    }
    for byte in 0..32 {
        let expanded_key_byte = (0..8).fold(AB::Expr::ZERO, |value, bit| {
            let key_bit: AB::Expr = row[AES256_KEY_SCHEDULE_BITS_OFFSET + byte * 8 + bit].into();
            value + key_bit * AB::Expr::from_u32(1 << bit)
        });
        let kdf_key_byte: AB::Expr = row[INPUT_KDF_KEY_BYTES_OFFSET + byte].into();
        builder
            .when(key_stage.clone() * selectors[0].clone())
            .assert_zero(expanded_key_byte - kdf_key_byte);
    }

    for sbox_index in 0..AES256_SBOX_COUNT {
        let input_offset = AES256_SBOX_INPUT_BITS_OFFSET + sbox_index * 8;
        let output_offset = AES256_SBOX_OUTPUT_BITS_OFFSET + sbox_index * 8;
        let witness_offset = AES256_SBOX_WITNESS_OFFSET + sbox_index * AES_SBOX_WITNESS_COLUMNS;
        aes_sbox_air::eval_constraints(
            builder,
            row,
            input_offset,
            output_offset,
            witness_offset,
            witness_offset + 16,
            witness_offset + 32,
            key_stage.clone(),
        );
        for bit in 0..8 {
            let witnessed_input: AB::Expr = row[input_offset + bit].into();
            let selected_key_input =
                (0..AES256_KEY_SCHEDULE_ROWS).fold(AB::Expr::ZERO, |sum, group| {
                    let word = 8 + group * 4;
                    let source_byte = if word % 8 == 0 {
                        (sbox_index + 1) % 4
                    } else {
                        sbox_index
                    };
                    let key_index = (word - 1) * 32 + source_byte * 8 + bit;
                    let key_bit: AB::Expr = row[AES256_KEY_SCHEDULE_BITS_OFFSET + key_index].into();
                    sum + selectors[group].clone() * key_bit
                });
            builder
                .when(key_stage.clone())
                .assert_zero(witnessed_input - selected_key_input);
        }
    }

    for group in 0..AES256_KEY_SCHEDULE_ROWS {
        let word = 8 + group * 4;
        let row_selector = key_stage.clone() * selectors[group].clone();
        let rcon = if word % 8 == 0 { 1u8 << (group / 2) } else { 0 };
        for byte in 0..4 {
            for bit in 0..8 {
                let base_index = (word - 8) * 32 + byte * 8 + bit;
                let base: AB::Expr = row[AES256_KEY_SCHEDULE_BITS_OFFSET + base_index].into();
                let substituted: AB::Expr =
                    row[AES256_SBOX_OUTPUT_BITS_OFFSET + byte * 8 + bit].into();
                let mut expected =
                    base.clone() + substituted.clone() - base * substituted * two.clone();
                if byte == 0 && (rcon >> bit) & 1 == 1 {
                    expected = one.clone() - expected;
                }
                let target_index = word * 32 + byte * 8 + bit;
                let target: AB::Expr = row[AES256_KEY_SCHEDULE_BITS_OFFSET + target_index].into();
                builder
                    .when(row_selector.clone())
                    .assert_zero(target - expected);
            }
        }
        for delta in 1..4 {
            for byte in 0..4 {
                for bit in 0..8 {
                    let left_index = (word + delta - 8) * 32 + byte * 8 + bit;
                    let right_index = (word + delta - 1) * 32 + byte * 8 + bit;
                    let target_index = (word + delta) * 32 + byte * 8 + bit;
                    let left: AB::Expr = row[AES256_KEY_SCHEDULE_BITS_OFFSET + left_index].into();
                    let right: AB::Expr = row[AES256_KEY_SCHEDULE_BITS_OFFSET + right_index].into();
                    let target: AB::Expr =
                        row[AES256_KEY_SCHEDULE_BITS_OFFSET + target_index].into();
                    let expected = left.clone() + right.clone() - left * right * two.clone();
                    builder
                        .when(row_selector.clone())
                        .assert_zero(target - expected);
                }
            }
        }
    }
}

fn aes_xor<AB: AirBuilder<F = Val>>(left: AB::Expr, right: AB::Expr) -> AB::Expr {
    left.clone() + right.clone() - left * right * AB::Expr::from_u32(2)
}

fn eval_aes256_ctr_plaintext_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    transition: AB::Expr,
) {
    let one = AB::Expr::ONE;
    let two = AB::Expr::from_u32(2);
    let key_stage: AB::Expr = row[AES256_KEY_SCHEDULE_ACTIVE_OFFSET].into();
    let key_index: [AB::Expr; 4] =
        core::array::from_fn(|bit| row[AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET + bit].into());
    let key_index_12 = (0..4).fold(AB::Expr::ONE, |selector, bit| {
        let literal = if (12 >> bit) & 1 == 1 {
            key_index[bit].clone()
        } else {
            one.clone() - key_index[bit].clone()
        };
        selector * literal
    });
    let key_end = key_stage * key_index_12;

    let block_active: AB::Expr = row[AES256_BLOCK_ACTIVE_OFFSET].into();
    let next_block_active: AB::Expr = next[AES256_BLOCK_ACTIVE_OFFSET].into();
    builder.assert_zero(block_active.clone() * (block_active.clone() - one.clone()));
    builder.when_first_row().assert_zero(block_active.clone());
    builder.when_last_row().assert_zero(block_active.clone());
    builder.assert_zero(block_active.clone() * row[AES256_KEY_SCHEDULE_ACTIVE_OFFSET].into());
    let index_bits: [AB::Expr; 4] =
        core::array::from_fn(|bit| row[AES256_BLOCK_INDEX_BITS_OFFSET + bit].into());
    let number_bits: [AB::Expr; 4] =
        core::array::from_fn(|bit| row[AES256_BLOCK_NUMBER_BITS_OFFSET + bit].into());
    for bit in 0..4 {
        builder.assert_zero(
            block_active.clone()
                * index_bits[bit].clone()
                * (index_bits[bit].clone() - one.clone()),
        );
        builder.assert_zero((one.clone() - block_active.clone()) * index_bits[bit].clone());
        builder.assert_zero(
            block_active.clone()
                * number_bits[bit].clone()
                * (number_bits[bit].clone() - one.clone()),
        );
        builder.assert_zero((one.clone() - block_active.clone()) * number_bits[bit].clone());
    }
    let selectors: Vec<AB::Expr> = (0..16)
        .map(|index| {
            (0..4).fold(AB::Expr::ONE, |selector, bit| {
                let literal = if (index >> bit) & 1 == 1 {
                    index_bits[bit].clone()
                } else {
                    one.clone() - index_bits[bit].clone()
                };
                selector * literal
            })
        })
        .collect();
    builder.assert_zero(block_active.clone() * selectors[15].clone());
    let number_selectors: Vec<AB::Expr> = (0..16)
        .map(|index| {
            (0..4).fold(AB::Expr::ONE, |selector, bit| {
                let literal = if (index >> bit) & 1 == 1 {
                    number_bits[bit].clone()
                } else {
                    one.clone() - number_bits[bit].clone()
                };
                selector * literal
            })
        })
        .collect();
    for selector in number_selectors.iter().skip(AES256_BLOCKS) {
        builder.assert_zero(block_active.clone() * selector.clone());
    }
    let round_end = block_active.clone() * selectors[14].clone();
    let block_end = round_end.clone() * number_selectors[AES256_BLOCKS - 1].clone();
    let output_mode: AB::Expr = row[CRYPTO_OUTPUT_MODE_OFFSET].into();
    let input_aes_end = block_end.clone() * (one.clone() - output_mode.clone());
    let output_aes_end = block_end.clone() * output_mode.clone();
    let next_mode: AB::Expr = next[CRYPTO_OUTPUT_MODE_OFFSET].into();
    builder.assert_zero(output_mode.clone() * (output_mode.clone() - one.clone()));
    builder.when_first_row().assert_zero(output_mode.clone());
    builder.when_last_row().assert_zero(output_mode.clone());
    builder.when(transition.clone()).assert_zero(
        next_mode - (output_mode.clone() + input_aes_end.clone() - output_aes_end.clone()),
    );
    builder.when(transition.clone()).assert_zero(
        next_block_active.clone() - (block_active.clone() - block_end.clone() + key_end),
    );
    for bit in 0..4 {
        let mut carry = block_active.clone();
        for lower in 0..bit {
            carry = carry * index_bits[lower].clone();
        }
        let incremented =
            index_bits[bit].clone() + carry.clone() - index_bits[bit].clone() * carry * two.clone();
        let expected = (block_active.clone() - round_end.clone()) * incremented;
        let next_bit: AB::Expr = next[AES256_BLOCK_INDEX_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone())
            .assert_zero(next_bit - expected);

        let mut number_carry = round_end.clone();
        for lower in 0..bit {
            number_carry = number_carry * number_bits[lower].clone();
        }
        let number_incremented = number_bits[bit].clone() + number_carry.clone()
            - number_bits[bit].clone() * number_carry * two.clone();
        let number_expected = (block_active.clone() - round_end.clone()) * number_bits[bit].clone()
            + (round_end.clone() - block_end.clone()) * number_incremented;
        let next_number_bit: AB::Expr = next[AES256_BLOCK_NUMBER_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone())
            .assert_zero(next_number_bit - number_expected);
    }

    let initial_round = block_active.clone() * selectors[0].clone();
    let final_round = round_end.clone();
    let crypto_round = block_active.clone() * (one.clone() - selectors[0].clone());
    let mixed_round =
        block_active.clone() * (one.clone() - selectors[0].clone() - selectors[14].clone());
    let counter_value = (0..4).fold(AB::Expr::from_u32(2), |value, bit| {
        value + number_bits[bit].clone() * AB::Expr::from_u32(1 << bit)
    });

    for byte in 0..16 {
        let input_byte = (0..8).fold(AB::Expr::ZERO, |value, bit| {
            let input: AB::Expr = row[AES256_BLOCK_STATE_INPUT_BITS_OFFSET + byte * 8 + bit].into();
            value + input * AB::Expr::from_u32(1 << bit)
        });
        let expected = match byte {
            0..=11 => {
                let input_nonce: AB::Expr = row[INPUT_AEAD_SOURCE_BYTES_OFFSET + byte].into();
                let output_nonce: AB::Expr =
                    builder.public_values()[OUTPUT_NONCE_PUBLIC_OFFSET + byte].into();
                input_nonce * (one.clone() - output_mode.clone())
                    + output_nonce * output_mode.clone()
            }
            12..=14 => AB::Expr::ZERO,
            15 => counter_value.clone(),
            _ => unreachable!(),
        };
        builder
            .when(initial_round.clone())
            .assert_zero(input_byte - expected);
    }

    for bit in 0..128 {
        let state_in: AB::Expr = row[AES256_BLOCK_STATE_INPUT_BITS_OFFSET + bit].into();
        let state_out: AB::Expr = row[AES256_BLOCK_STATE_OUTPUT_BITS_OFFSET + bit].into();
        builder.assert_zero(block_active.clone() * state_in.clone() * (state_in - one.clone()));
        builder.assert_zero(
            block_active.clone() * state_out.clone() * (state_out.clone() - one.clone()),
        );
        let following: AB::Expr = next[AES256_BLOCK_STATE_INPUT_BITS_OFFSET + bit].into();
        builder
            .when(transition.clone() * (block_active.clone() - round_end.clone()))
            .assert_zero(following - state_out);
    }

    for sbox_index in 0..AES256_BLOCK_SBOX_COUNT {
        let input_offset = AES256_BLOCK_STATE_INPUT_BITS_OFFSET + sbox_index * 8;
        let output_offset = AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + sbox_index * 8;
        let witness_offset =
            AES256_BLOCK_SBOX_WITNESS_OFFSET + sbox_index * AES_SBOX_WITNESS_COLUMNS;
        aes_sbox_air::eval_constraints(
            builder,
            row,
            input_offset,
            output_offset,
            witness_offset,
            witness_offset + 16,
            witness_offset + 32,
            crypto_round.clone(),
        );
    }

    for byte in 0..16 {
        let state_row = byte % 4;
        let state_column = byte / 4;
        let shifted_source = state_row + 4 * ((state_column + state_row) % 4);
        for bit in 0..8 {
            let shifted: AB::Expr =
                row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + bit].into();
            let xtime_offset = AES256_BLOCK_XTIME_BITS_OFFSET + byte * 8 + bit;
            let xtime: AB::Expr = row[xtime_offset].into();
            let mul3_offset = AES256_BLOCK_MUL3_BITS_OFFSET + byte * 8 + bit;
            let mul3: AB::Expr = row[mul3_offset].into();
            builder
                .assert_zero(mixed_round.clone() * xtime.clone() * (xtime.clone() - one.clone()));
            builder.assert_zero(mixed_round.clone() * mul3.clone() * (mul3.clone() - one.clone()));
            let doubled = match bit {
                0 => row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 7].into(),
                1 => aes_xor::<AB>(
                    row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8].into(),
                    row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 7].into(),
                ),
                2 => row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 1].into(),
                3 => aes_xor::<AB>(
                    row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 2].into(),
                    row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 7].into(),
                ),
                4 => aes_xor::<AB>(
                    row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 3].into(),
                    row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 7].into(),
                ),
                5 => row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 4].into(),
                6 => row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 5].into(),
                7 => row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + 6].into(),
                _ => unreachable!(),
            };
            builder
                .when(mixed_round.clone())
                .assert_zero(xtime - doubled);
            builder.when(mixed_round.clone()).assert_zero(
                mul3 - aes_xor::<AB>(
                    row[AES256_BLOCK_XTIME_BITS_OFFSET + byte * 8 + bit].into(),
                    shifted,
                ),
            );
        }
    }

    const MIX_COEFFICIENTS: [[u8; 4]; 4] = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
    for column in 0..4 {
        for output_row in 0..4 {
            let output_byte = output_row + 4 * column;
            for bit in 0..8 {
                let mut terms = Vec::with_capacity(4);
                for source_row in 0..4 {
                    let source_byte = source_row + 4 * column;
                    let shifted_source = source_row + 4 * ((column + source_row) % 4);
                    let term: AB::Expr = match MIX_COEFFICIENTS[output_row][source_row] {
                        1 => row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + bit]
                            .into(),
                        2 => row[AES256_BLOCK_XTIME_BITS_OFFSET + source_byte * 8 + bit].into(),
                        3 => row[AES256_BLOCK_MUL3_BITS_OFFSET + source_byte * 8 + bit].into(),
                        _ => unreachable!(),
                    };
                    terms.push(term);
                }
                let mixed = terms
                    .into_iter()
                    .reduce(aes_xor::<AB>)
                    .expect("four MixColumns terms");
                let witness: AB::Expr =
                    row[AES256_BLOCK_MIXED_BITS_OFFSET + output_byte * 8 + bit].into();
                builder.assert_zero(
                    mixed_round.clone() * witness.clone() * (witness.clone() - one.clone()),
                );
                builder
                    .when(mixed_round.clone())
                    .assert_zero(witness - mixed);
            }
        }
    }

    for byte in 0..16 {
        let state_row = byte % 4;
        let state_column = byte / 4;
        let shifted_source = state_row + 4 * ((state_column + state_row) % 4);
        for bit in 0..8 {
            let state_out: AB::Expr =
                row[AES256_BLOCK_STATE_OUTPUT_BITS_OFFSET + byte * 8 + bit].into();
            let key_bit = (0..15).fold(AB::Expr::ZERO, |sum, round| {
                let key_index = (round * 16 + byte) * 8 + bit;
                let schedule_bit: AB::Expr =
                    row[AES256_KEY_SCHEDULE_BITS_OFFSET + key_index].into();
                sum + selectors[round].clone() * schedule_bit
            });
            let initial: AB::Expr =
                row[AES256_BLOCK_STATE_INPUT_BITS_OFFSET + byte * 8 + bit].into();
            let initial_output = aes_xor::<AB>(initial, key_bit.clone());
            builder
                .when(initial_round.clone())
                .assert_zero(state_out.clone() - initial_output);

            let normal_mix: AB::Expr = row[AES256_BLOCK_MIXED_BITS_OFFSET + byte * 8 + bit].into();
            let normal_output = aes_xor::<AB>(normal_mix, key_bit.clone());
            builder
                .when(mixed_round.clone())
                .assert_zero(state_out.clone() - normal_output);

            let final_sub: AB::Expr =
                row[AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + shifted_source * 8 + bit].into();
            let final_output = aes_xor::<AB>(final_sub, key_bit);
            builder
                .when(final_round.clone())
                .assert_zero(state_out - final_output);
        }
    }

    for byte in 0..16 {
        let byte_valid = (0..AES256_BLOCKS).fold(AB::Expr::ZERO, |sum, chunk| {
            if chunk * 16 + byte < 140 {
                sum + number_selectors[chunk].clone()
            } else {
                sum
            }
        });
        let source_ciphertext = (0..AES256_BLOCKS).fold(AB::Expr::ZERO, |sum, chunk| {
            let plaintext_index = chunk * 16 + byte;
            if plaintext_index < 140 {
                let input_cipher: AB::Expr =
                    row[INPUT_AEAD_SOURCE_BYTES_OFFSET + 12 + plaintext_index].into();
                let output_cipher: AB::Expr = builder.public_values()
                    [OUTPUT_CIPHERTEXT_PUBLIC_OFFSET + plaintext_index]
                    .into();
                let selected_cipher = input_cipher * (one.clone() - output_mode.clone())
                    + output_cipher * output_mode.clone();
                sum + number_selectors[chunk].clone() * selected_cipher
            } else {
                sum
            }
        });
        let expected_plaintext = (0..AES256_BLOCKS).fold(AB::Expr::ZERO, |sum, chunk| {
            let plaintext_index = chunk * 16 + byte;
            let input_plaintext = match plaintext_index {
                0..=7 => (0..8).fold(AB::Expr::ZERO, |value, bit| {
                    value
                        + row[INPUT_VALUE_BITS_OFFSET + plaintext_index * 8 + bit]
                            * AB::Expr::from_u32(1 << bit)
                }),
                8..=135 => row[INPUT_NOTE_RHO_RANDOMNESS_BYTES_OFFSET + plaintext_index - 8].into(),
                136..=139 => AB::Expr::ZERO,
                _ => AB::Expr::ZERO,
            };
            let output_plaintext = output_note_plaintext_byte::<AB>(row, plaintext_index);
            let selected_plaintext = input_plaintext * (one.clone() - output_mode.clone())
                + output_plaintext * output_mode.clone();
            sum + number_selectors[chunk].clone() * selected_plaintext
        });
        let cipher_byte = (0..8).fold(AB::Expr::ZERO, |value, bit| {
            let cipher_bit: AB::Expr =
                row[AES256_BLOCK_CIPHERTEXT_BITS_OFFSET + byte * 8 + bit].into();
            builder.assert_zero(
                final_round.clone()
                    * byte_valid.clone()
                    * cipher_bit.clone()
                    * (cipher_bit.clone() - one.clone()),
            );
            value + cipher_bit * AB::Expr::from_u32(1 << bit)
        });
        let plaintext_byte = (0..8).fold(AB::Expr::ZERO, |value, bit| {
            let plaintext_bit: AB::Expr =
                row[AES256_BLOCK_PLAINTEXT_BITS_OFFSET + byte * 8 + bit].into();
            builder.assert_zero(
                final_round.clone()
                    * byte_valid.clone()
                    * plaintext_bit.clone()
                    * (plaintext_bit.clone() - one.clone()),
            );
            value + plaintext_bit * AB::Expr::from_u32(1 << bit)
        });
        let final_byte = final_round.clone() * byte_valid;
        builder
            .when(final_byte.clone())
            .assert_zero(cipher_byte - source_ciphertext);
        builder
            .when(final_byte.clone())
            .assert_zero(plaintext_byte - expected_plaintext);
        for bit in 0..8 {
            let cipher_bit: AB::Expr =
                row[AES256_BLOCK_CIPHERTEXT_BITS_OFFSET + byte * 8 + bit].into();
            let stream_bit: AB::Expr =
                row[AES256_BLOCK_STATE_OUTPUT_BITS_OFFSET + byte * 8 + bit].into();
            let plaintext_bit: AB::Expr =
                row[AES256_BLOCK_PLAINTEXT_BITS_OFFSET + byte * 8 + bit].into();
            builder
                .when(final_byte.clone())
                .assert_zero(aes_xor::<AB>(cipher_bit, stream_bit) - plaintext_bit);
        }
    }
}

fn level_marker<AB: AirBuilder<F = Val>>(row: &[AB::Var]) -> AB::Expr {
    row[LEVEL_BITS + 6].into()
}
fn output_leaf_slot_selector<AB: AirBuilder<F = Val>>(row: &[AB::Var], slot: usize) -> AB::Expr {
    (0..4).fold(AB::Expr::ONE, |selector, bit| {
        let value: AB::Expr = row[OUTPUT_LEAF_INDEX_BITS_OFFSET + bit].into();
        if (slot >> bit) & 1 == 1 {
            selector * value
        } else {
            selector * (AB::Expr::ONE - value)
        }
    })
}
fn output_leaf_last_selector<AB: AirBuilder<F = Val>>(
    builder: &AB,
    row: &[AB::Var],
    public_offset: usize,
) -> AB::Expr {
    (0..4).fold(AB::Expr::ONE, |selector, bit| {
        let current: AB::Expr = row[OUTPUT_LEAF_INDEX_BITS_OFFSET + bit].into();
        let expected: AB::Expr = builder.public_values()[public_offset + 1 + bit].into();
        selector
            * (AB::Expr::ONE - current.clone() - expected.clone()
                + current * expected * AB::Expr::from_u32(2))
    })
}
fn source_block_selector<AB: AirBuilder<F = Val>>(level: &[AB::Expr; 7], block: usize) -> AB::Expr {
    (0..4).fold(AB::Expr::ONE, |selector, bit| {
        let value = level[bit].clone();
        if (block >> bit) & 1 == 1 {
            selector * value
        } else {
            selector * (AB::Expr::ONE - value)
        }
    })
}
fn source_buffer_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], byte: usize) -> AB::Expr {
    (0..8).fold(AB::Expr::ZERO, |value, bit| {
        let b: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + byte * 8 + bit].into();
        value + b * AB::Expr::from_u32(1 << bit)
    })
}
fn input_kdf_frame_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], offset: usize) -> AB::Expr {
    match offset {
        0..=4 => AB::Expr::from_u32(u32::from(b"RADIX"[offset])),
        5 => AB::Expr::from_u32(1),
        6 => AB::Expr::from_u32(17),
        7 => AB::Expr::ZERO,
        8..=24 => AB::Expr::from_u32(u32::from(b"radix/note-kdf/v1"[offset - 8])),
        25 => AB::Expr::from_u32(3),
        26 => AB::Expr::ZERO,
        27 => AB::Expr::from_u32(32),
        28..=30 => AB::Expr::ZERO,
        31..=62 => spend_owner_private_byte::<AB>(row, 64 + offset - 31),
        63 => AB::Expr::from_u32(0x40),
        64 => AB::Expr::from_u32(0x04),
        65..=66 => AB::Expr::ZERO,
        67..=1154 => row[INPUT_KDF_SOURCE_BYTES_OFFSET + 64 + offset - 67].into(),
        1155 => AB::Expr::from_u32(64),
        1156..=1158 => AB::Expr::ZERO,
        1159..=1222 => row[INPUT_KDF_SOURCE_BYTES_OFFSET + offset - 1159].into(),
        1223 => AB::Expr::from_u32(0x9f),
        _ => AB::Expr::ZERO,
    }
}
fn output_kdf_secret_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], byte: usize) -> AB::Expr {
    row[OUTPUT_KDF_SECRET_BYTES_OFFSET + byte].into()
}
fn output_note_private_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], byte: usize) -> AB::Expr {
    (0..8).fold(AB::Expr::ZERO, |value, bit| {
        let note_bit: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + byte * 8 + bit].into();
        value + note_bit * AB::Expr::from_u32(1 << bit)
    })
}
fn output_note_plaintext_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], byte: usize) -> AB::Expr {
    match byte {
        0..=7 => output_note_private_byte::<AB>(row, 64 + byte),
        8..=71 => output_note_private_byte::<AB>(row, 72 + byte - 8),
        72..=135 => output_note_private_byte::<AB>(row, 136 + byte - 72),
        _ => AB::Expr::ZERO,
    }
}
fn output_kdf_frame_byte<AB: AirBuilder<F = Val>>(
    builder: &AB,
    row: &[AB::Var],
    offset: usize,
) -> AB::Expr {
    match offset {
        0..=4 => AB::Expr::from_u32(u32::from(b"RADIX"[offset])),
        5 => AB::Expr::from_u32(1),
        6 => AB::Expr::from_u32(17),
        7 => AB::Expr::ZERO,
        8..=24 => AB::Expr::from_u32(u32::from(b"radix/note-kdf/v1"[offset - 8])),
        25 => AB::Expr::from_u32(3),
        26 => AB::Expr::ZERO,
        27 => AB::Expr::from_u32(32),
        28..=30 => AB::Expr::ZERO,
        31..=62 => output_kdf_secret_byte::<AB>(row, offset - 31),
        63 => AB::Expr::from_u32(0x40),
        64 => AB::Expr::from_u32(0x04),
        65..=66 => AB::Expr::ZERO,
        67..=1154 => {
            builder.public_values()[OUTPUT_KEM_CIPHERTEXT_PUBLIC_OFFSET + offset - 67].into()
        }
        1155 => AB::Expr::from_u32(64),
        1156..=1158 => AB::Expr::ZERO,
        1159..=1222 => {
            builder.public_values()[OUTPUT_COMMITMENT_PUBLIC_OFFSET + offset - 1159].into()
        }
        1223 => AB::Expr::from_u32(0x9f),
        _ => AB::Expr::ZERO,
    }
}
fn input_kdf_block_selector<AB: AirBuilder<F = Val>>(row: &[AB::Var], block: usize) -> AB::Expr {
    (0..4).fold(AB::Expr::ONE, |selector, bit| {
        let value: AB::Expr = row[INPUT_KDF_INDEX_BITS_OFFSET + bit].into();
        if (block >> bit) & 1 == 1 {
            selector * value
        } else {
            selector * (AB::Expr::ONE - value)
        }
    })
}
fn populate_sbox_air_witness(
    row: &mut [Val],
    input: u8,
    input_offset: usize,
    output_offset: usize,
    witness_offset: usize,
) {
    let output = aes_sbox_air::sbox(input);
    for bit in 0..8 {
        row[input_offset + bit] = Val::from_u32(u32::from((input >> bit) & 1));
        row[output_offset + bit] = Val::from_u32(u32::from((output >> bit) & 1));
    }
    let high_nibble = usize::from(input >> 4);
    let low_nibble = usize::from(input & 0x0f);
    for nibble in 0..16 {
        row[witness_offset + nibble] = Val::from_u32(u32::from(nibble == high_nibble));
        row[witness_offset + 16 + nibble] = Val::from_u32(u32::from(nibble == low_nibble));
        row[witness_offset + 32 + nibble] =
            Val::from_u32(u32::from(aes_sbox_air::AES_SBOX[high_nibble * 16 + nibble]));
    }
}

fn note_private_byte_index(frame_offset: usize) -> Option<usize> {
    match frame_offset {
        27..=90 => Some(frame_offset - 27),
        95..=102 => Some(64 + frame_offset - 95),
        107..=170 => Some(72 + frame_offset - 107),
        175..=238 => Some(136 + frame_offset - 175),
        _ => None,
    }
}
fn note_private_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], index: usize) -> AB::Expr {
    (0..8).fold(AB::Expr::ZERO, |value, bit| {
        let b: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + index * 8 + bit].into();
        value + b * AB::Expr::from_u32(1 << bit)
    })
}
fn note_frame_constant(offset: usize) -> u8 {
    match offset {
        0..=4 => b"RADIX"[offset],
        5 => 1,
        6 => b"radix/note/v1".len() as u8,
        7 => 0,
        8..=20 => b"radix/note/v1"[offset - 8],
        21 => 4,
        22 => 0,
        23 => 64,
        24..=26 => 0,
        91 => 8,
        92..=94 => 0,
        103 => 64,
        104..=106 => 0,
        171 => 64,
        172..=174 => 0,
        _ => 0,
    }
}
fn note_padded_frame_byte<AB: AirBuilder<F = Val>>(row: &[AB::Var], offset: usize) -> AB::Expr {
    if offset < 239 {
        if let Some(index) = note_private_byte_index(offset) {
            note_private_byte::<AB>(row, index)
        } else {
            AB::Expr::from_u32(u32::from(note_frame_constant(offset)))
        }
    } else if offset == 239 {
        AB::Expr::from_u32(0x1f)
    } else if offset == 271 {
        AB::Expr::from_u32(0x80)
    } else {
        AB::Expr::ZERO
    }
}
fn note_padded_frame_bit<AB: AirBuilder<F = Val>>(
    row: &[AB::Var],
    offset: usize,
    bit_index: usize,
) -> AB::Expr {
    if offset < 239 {
        if let Some(index) = note_private_byte_index(offset) {
            row[NOTE_PRIVATE_BITS_OFFSET + index * 8 + bit_index].into()
        } else {
            AB::Expr::from_u32(u32::from((note_frame_constant(offset) >> bit_index) & 1))
        }
    } else if offset == 239 {
        AB::Expr::from_u32(u32::from((0x1fu8 >> bit_index) & 1))
    } else if offset == 271 {
        AB::Expr::from_u32(u32::from((0x80u8 >> bit_index) & 1))
    } else {
        AB::Expr::ZERO
    }
}
fn eval_note_commitment_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    keccak: &KeccakCols<AB::Var>,
    next_keccak: &KeccakCols<AB::Var>,
    transition: AB::Expr,
    first_step: AB::Expr,
    final_step: AB::Expr,
    note_stage: AB::Expr,
    phase: AB::Expr,
    one: AB::Expr,
    digest_public_value_offset: Option<usize>,
) {
    let first_block_start = note_stage.clone() * first_step * (one.clone() - phase.clone());
    // The sum of 64 boolean value bits is in [0, 64], so its field inverse proves
    // the note value is nonzero without introducing a 64-bit comparator here.
    let mut value_bits = AB::Expr::ZERO;
    for bit in 0..64 {
        value_bits += row[NOTE_PRIVATE_BITS_OFFSET + 64 * 8 + bit].into();
    }
    let inverse: AB::Expr = row[NOTE_INVERSE_OFFSET].into();
    builder
        .when(first_block_start.clone())
        .assert_zero(value_bits * inverse - one.clone());

    for limb in 0..RATE_LIMBS {
        let low = note_padded_frame_byte::<AB>(row, limb * 2);
        let high = note_padded_frame_byte::<AB>(row, limb * 2 + 1);
        let expected = low + high * AB::Expr::from_u32(256);
        builder
            .when(first_block_start.clone())
            .assert_zero(keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4] - expected);
    }
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                if y * 20 + x * 4 + limb >= RATE_LIMBS {
                    builder
                        .when(first_block_start.clone())
                        .assert_zero(keccak.preimage[y][x][limb]);
                }
            }
        }
    }

    let first_absorption_end =
        note_stage.clone() * final_step.clone() * (one.clone() - phase.clone());
    for limb in 0..RATE_LIMBS {
        let mut reconstructed = AB::Expr::ZERO;
        for bit in 0..16 {
            let output_bit: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + limb * 16 + bit].into();
            reconstructed += output_bit * AB::Expr::from_u32(1 << bit);
        }
        let actual: AB::Expr = keccak
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .into();
        builder
            .when(first_absorption_end.clone())
            .assert_zero(actual - reconstructed);
    }

    let second_block_boundary =
        transition * note_stage.clone() * final_step.clone() * (one.clone() - phase.clone());
    for y in 0..5 {
        for x in 0..5 {
            let lane = y * 5 + x;
            for limb in 0..4 {
                let global_limb = lane * 4 + limb;
                let state_byte = global_limb * 2;
                let actual: AB::Expr = keccak.a_prime_prime_prime(y, x, limb).into();
                let expected = if global_limb < RATE_LIMBS {
                    let mut value = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let output_bit: AB::Expr =
                            row[SOURCE_BUFFER_BITS_OFFSET + global_limb * 16 + bit].into();
                        let block_bit = note_padded_frame_bit::<AB>(
                            next,
                            SHAKE_RATE_BYTES + state_byte + bit / 8,
                            bit % 8,
                        );
                        let xor = output_bit.clone() + block_bit.clone()
                            - output_bit * block_bit * AB::Expr::from_u32(2);
                        value += xor * AB::Expr::from_u32(1 << bit);
                    }
                    value
                } else {
                    actual.clone()
                };
                builder
                    .when(second_block_boundary.clone())
                    .assert_zero(next_keccak.preimage[y][x][limb] - expected);
            }
        }
    }

    let digest_selector = note_stage * final_step * phase;
    for limb in 0..(DIGEST_BYTES / 2) {
        let expected = if let Some(public_start) = digest_public_value_offset {
            let low: AB::Expr = builder.public_values()[public_start + limb * 2].into();
            let high: AB::Expr = builder.public_values()[public_start + limb * 2 + 1].into();
            low + high * AB::Expr::from_u32(256)
        } else {
            let low = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                let value: AB::Expr = row[SIBLING_BITS + (limb * 2) * 8 + bit].into();
                acc + value * AB::Expr::from_u32(1 << bit)
            });
            let high = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                let value: AB::Expr = row[SIBLING_BITS + (limb * 2 + 1) * 8 + bit].into();
                acc + value * AB::Expr::from_u32(1 << bit)
            });
            low + high * AB::Expr::from_u32(256)
        };
        let actual: AB::Expr = keccak
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .into();
        builder
            .when(digest_selector.clone())
            .assert_zero(actual - expected);
    }
}
fn eval_output_value_balance_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    output_note_stage: AB::Expr,
    first_step: AB::Expr,
) {
    let output_start = output_note_stage.clone() * first_step;
    let fee_start =
        PUBLIC_ROOT_PREFIX_BYTES + crate::transaction_statement::STATEMENT_FEE_BYTES_OFFSET;
    for carry in 0..3 {
        let value: AB::Expr = row[BALANCE_CARRY_BITS_OFFSET + carry].into();
        builder.assert_zero(output_note_stage.clone() * value.clone() * (value - AB::Expr::ONE));
    }
    for limb in 0..4 {
        let input = (0..16).fold(AB::Expr::ZERO, |acc, bit| {
            let value: AB::Expr = row[INPUT_VALUE_BITS_OFFSET + limb * 16 + bit].into();
            acc + value * AB::Expr::from_u32(1 << bit)
        });
        let output = (0..16).fold(AB::Expr::ZERO, |acc, bit| {
            let value: AB::Expr = row[NOTE_PRIVATE_BITS_OFFSET + 64 * 8 + limb * 16 + bit].into();
            acc + value * AB::Expr::from_u32(1 << bit)
        });
        let fee_low: AB::Expr = builder.public_values()[fee_start + limb * 2].into();
        let fee_high: AB::Expr = builder.public_values()[fee_start + limb * 2 + 1].into();
        let fee = fee_low + fee_high * AB::Expr::from_u32(256);
        let carry_in = if limb == 0 {
            AB::Expr::ZERO
        } else {
            row[BALANCE_CARRY_BITS_OFFSET + limb - 1].into()
        };
        let carry_out = if limb == 3 {
            AB::Expr::ZERO
        } else {
            row[BALANCE_CARRY_BITS_OFFSET + limb].into()
        };
        builder
            .when(output_start.clone())
            .assert_zero(output + fee + carry_in - input - carry_out * AB::Expr::from_u32(1 << 16));
    }
}
fn source_frame_constant(offset: usize) -> Option<u8> {
    Some(match offset {
        0..=4 => b"RADIX"[offset],
        5 => 1,
        6 => b"radix/leaf/v1".len() as u8,
        7 => 0,
        8..=20 => b"radix/leaf/v1"[offset - 8],
        21 => 4,
        22 => 0,
        23 => 64,
        24..=26 => 0,
        27..=90 => return None,
        91 => 64,
        92 => 4,
        93..=94 => 0,
        95..=1182 => return None,
        1183 => 12,
        1184..=1186 => 0,
        1187..=1198 => return None,
        1199 => SOURCE_CIPHERTEXT_BYTES as u8,
        1200..=1202 => 0,
        1203..=1358 => return None,
        1359 => 0x9f,
        _ => return None,
    })
}
fn eval_fixed_source156_constraints<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    row: &[AB::Var],
    next: &[AB::Var],
    keccak: &KeccakCols<AB::Var>,
    next_keccak: &KeccakCols<AB::Var>,
    transition: AB::Expr,
    first_step: AB::Expr,
    final_step: AB::Expr,
    source_stage: AB::Expr,
    level: [AB::Expr; 7],
    phase: AB::Expr,
    one: AB::Expr,
    note_end: AB::Expr,
) {
    builder
        .when(source_stage.clone())
        .assert_zero(phase.clone());
    builder
        .when(source_stage.clone())
        .assert_zero(row[DIRECTION]);
    builder
        .when(source_stage.clone())
        .assert_zero(level[4].clone());
    builder
        .when(source_stage.clone())
        .assert_zero(level[5].clone());
    let source_permutation_end_gate = source_stage.clone() * final_step.clone();
    let next_final_step: AB::Expr = next_keccak.step_flags[NUM_ROUNDS - 1].into();
    for bit in 0..SOURCE_BUFFER_BITS {
        let value: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder.assert_zero(source_stage.clone() * value.clone() * (value - one.clone()));
    }
    let last_block = source_block_selector::<AB>(&level, SOURCE_BLOCKS - 1);
    let source_permutation_end = source_stage.clone() * final_step.clone();
    let source_to_path = source_permutation_end.clone() * last_block.clone();
    let source_advance = source_permutation_end.clone() * (one.clone() - last_block.clone());
    let next_level: [AB::Expr; 7] = core::array::from_fn(|bit| next[LEVEL_BITS + bit].into());
    for bit in 0..4 {
        let mut carry = source_advance.clone();
        for lower in 0..bit {
            carry = carry * level[lower].clone();
        }
        let incremented =
            level[bit].clone() + carry.clone() - level[bit].clone() * carry * AB::Expr::from_u32(2);
        let expected = incremented * (one.clone() - source_to_path.clone());
        builder
            .when(transition.clone() * source_stage.clone())
            .assert_zero(next_level[bit].clone() - expected);
    }
    for bit in 4..6 {
        builder
            .when(transition.clone() * source_stage.clone())
            .assert_zero(next_level[bit].clone());
    }
    builder
        .when(transition.clone() * source_stage.clone())
        .assert_zero(next_level[6].clone() - (one.clone() - source_to_path.clone()));
    let source_final_selector = source_stage.clone() * final_step.clone() * last_block.clone();
    let next_active: AB::Expr = next[ACTIVE].into();
    let next_source_stage = next_active * next_level[6].clone();
    // In the composite profile, the final note row hands directly into this
    // source stage; ordinary source-only profiles have note_end = 0.
    builder.when(transition.clone()).assert_zero(
        next_source_stage - (source_stage.clone() - source_final_selector.clone() + note_end),
    );
    builder
        .when(transition.clone() * source_to_path.clone())
        .assert_zero(next[PHASE]);
    // The single rate buffer holds the absorb block through the penultimate
    // round, becomes the output rate on the final row, and is reloaded with
    // the next block at the permutation boundary. Permit changes only on those
    // two boundary transitions; all interior rows must retain the same bytes.
    let source_inside_permutation = transition.clone()
        * source_stage.clone()
        * (one.clone() - final_step.clone())
        * (one.clone() - next_final_step.clone());
    for bit in 0..SHAKE_RATE_BYTES * 8 {
        let current: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        let following: AB::Expr = next[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        builder
            .when(source_inside_permutation.clone())
            .assert_zero(following - current);
    }
    // Fixed 156-byte OutputRecordV1 frame constants and the exact 0x9f
    // coincident SHAKE padding byte are checked on each block's first row.
    for offset in 0..=SOURCE_FRAME_BYTES {
        if let Some(expected) = source_frame_constant(offset) {
            let block = offset / SHAKE_RATE_BYTES;
            let within = offset % SHAKE_RATE_BYTES;
            let selector = source_stage.clone()
                * first_step.clone()
                * source_block_selector::<AB>(&level, block);
            builder.when(selector).assert_zero(
                source_buffer_byte::<AB>(row, within) - AB::Expr::from_u32(expected as u32),
            );
        }
    }
    // First SHAKE absorption starts from the rate block with zero capacity.
    let first_block_start =
        source_stage.clone() * first_step.clone() * source_block_selector::<AB>(&level, 0);
    for limb in 0..RATE_LIMBS {
        let low = source_buffer_byte::<AB>(row, limb * 2);
        let high = source_buffer_byte::<AB>(row, limb * 2 + 1);
        let expected = low + high * AB::Expr::from_u32(256);
        builder
            .when(first_block_start.clone())
            .assert_zero(keccak.preimage[limb / 20][(limb / 4) % 5][limb % 4] - expected);
    }
    for y in 0..5 {
        for x in 0..5 {
            for limb in 0..4 {
                if y * 20 + x * 4 + limb >= RATE_LIMBS {
                    builder
                        .when(first_block_start.clone())
                        .assert_zero(keccak.preimage[y][x][limb]);
                }
            }
        }
    }
    // Decompose the entire output rate back into the shared rate buffer on
    // the final row. The absorb block is not needed after that permutation.
    for limb in 0..RATE_LIMBS {
        let reconstructed = (0..16).fold(AB::Expr::ZERO, |value, bit| {
            let output_bit: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + limb * 16 + bit].into();
            value + output_bit * AB::Expr::from_u32(1 << bit)
        });
        let actual: AB::Expr = keccak
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .into();
        builder
            .when(source_permutation_end_gate.clone())
            .assert_zero(actual - reconstructed);
    }
    // Subsequent SHAKE blocks absorb by XORing the next private padded block
    // into the previous output rate; capacity lanes remain unchanged.
    let next_source_block = transition.clone()
        * source_stage.clone()
        * final_step.clone()
        * (one.clone() - last_block.clone());
    for y in 0..5 {
        for x in 0..5 {
            let lane = y * 5 + x;
            for limb in 0..4 {
                let global_limb = lane * 4 + limb;
                let expected = if global_limb < RATE_LIMBS {
                    let mut value = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let byte = global_limb * 2 + bit / 8;
                        let in_byte_bit = bit & 7;
                        let output_bit: AB::Expr =
                            row[SOURCE_BUFFER_BITS_OFFSET + byte * 8 + in_byte_bit].into();
                        let block_bit: AB::Expr =
                            next[SOURCE_BUFFER_BITS_OFFSET + byte * 8 + in_byte_bit].into();
                        let xor = output_bit.clone() + block_bit.clone()
                            - output_bit * block_bit * AB::Expr::from_u32(2);
                        value += xor * AB::Expr::from_u32(1 << bit);
                    }
                    value
                } else {
                    keccak.a_prime_prime_prime(y, x, limb).into()
                };
                builder
                    .when(next_source_block.clone())
                    .assert_zero(next_keccak.preimage[y][x][limb] - expected);
            }
        }
    }
    // The final SHAKE256-512 digest remains private and is the first path current.
    let leaf_to_path = transition * source_final_selector;
    for bit in 0..DIGEST_BYTES * 8 {
        let output_bit: AB::Expr = row[SOURCE_BUFFER_BITS_OFFSET + bit].into();
        let path_bit: AB::Expr = next[CURRENT_BITS + bit].into();
        builder
            .when(leaf_to_path.clone())
            .assert_zero(output_bit - path_bit);
    }
}
fn absorb_byte_slot(state_byte: usize) -> Option<usize> {
    match state_byte {
        0..=33 => Some(state_byte),
        134 => Some(34),
        135 => Some(35),
        _ => None,
    }
}
fn frame_byte64<AB: AirBuilder<F = Val>>(
    row: &[AB::Var],
    offset: usize,
    level: AB::Expr,
) -> AB::Expr {
    if offset < FRAME_BYTES {
        match offset {
            32 => level,
            37..=100 => {
                let index = offset - 37;
                let cur = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                    let value: AB::Expr = row[CURRENT_BITS + index * 8 + bit].into();
                    acc + value * AB::Expr::from_u32(1 << bit)
                });
                let sib = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                    let value: AB::Expr = row[SIBLING_BITS + index * 8 + bit].into();
                    acc + value * AB::Expr::from_u32(1 << bit)
                });
                let dir: AB::Expr = row[DIRECTION].into();
                cur.clone() + dir * (sib - cur)
            }
            105..=168 => {
                let index = offset - 105;
                let cur = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                    let value: AB::Expr = row[CURRENT_BITS + index * 8 + bit].into();
                    acc + value * AB::Expr::from_u32(1 << bit)
                });
                let sib = (0..8).fold(AB::Expr::ZERO, |acc, bit| {
                    let value: AB::Expr = row[SIBLING_BITS + index * 8 + bit].into();
                    acc + value * AB::Expr::from_u32(1 << bit)
                });
                let dir: AB::Expr = row[DIRECTION].into();
                sib.clone() + dir * (cur - sib)
            }
            _ => AB::Expr::from_u32(u32::from(constant_frame_byte(offset))),
        }
    } else if offset == FRAME_BYTES {
        AB::Expr::from_u32(0x1f)
    } else if offset == 2 * SHAKE_RATE_BYTES - 1 {
        AB::Expr::from_u32(0x80)
    } else {
        AB::Expr::ZERO
    }
}
fn frame_bit64<AB: AirBuilder<F = Val>>(row: &[AB::Var], offset: usize, bit: usize) -> AB::Expr {
    if offset < FRAME_BYTES {
        match offset {
            32 => {
                if bit < 7 {
                    row[LEVEL_BITS + bit].into()
                } else {
                    AB::Expr::ZERO
                }
            }
            37..=100 => {
                let index = offset - 37;
                let cur: AB::Expr = row[CURRENT_BITS + index * 8 + bit].into();
                let sib: AB::Expr = row[SIBLING_BITS + index * 8 + bit].into();
                let dir: AB::Expr = row[DIRECTION].into();
                cur.clone() + dir * (sib - cur)
            }
            105..=168 => {
                let index = offset - 105;
                let cur: AB::Expr = row[CURRENT_BITS + index * 8 + bit].into();
                let sib: AB::Expr = row[SIBLING_BITS + index * 8 + bit].into();
                let dir: AB::Expr = row[DIRECTION].into();
                sib.clone() + dir * (cur - sib)
            }
            _ => AB::Expr::from_u32(u32::from((constant_frame_byte(offset) >> bit) & 1)),
        }
    } else if offset == FRAME_BYTES {
        AB::Expr::from_u32(u32::from((0x1fu8 >> bit) & 1))
    } else if offset == 2 * SHAKE_RATE_BYTES - 1 {
        AB::Expr::from_u32(u32::from((0x80u8 >> bit) & 1))
    } else {
        AB::Expr::ZERO
    }
}
fn constant_frame_byte(offset: usize) -> u8 {
    match offset {
        0..=4 => b"RADIX"[offset],
        5 => 1,
        6 => TAG.len() as u8,
        7 => 0,
        8..=25 => TAG[offset - 8],
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
fn candidate_frame(level: u8, left: &ValArray, right: &ValArray) -> [u8; FRAME_BYTES] {
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
    frame.try_into().expect("fixed Candidate-A tree-node frame")
}
fn block_state(frame: &[u8; FRAME_BYTES], block_index: usize) -> [u64; 25] {
    let mut state = [0u64; 25];
    for i in 0..SHAKE_RATE_BYTES {
        let at = block_index * SHAKE_RATE_BYTES + i;
        let byte = if at < FRAME_BYTES {
            frame[at]
        } else if at == FRAME_BYTES {
            0x1f
        } else if at == 2 * SHAKE_RATE_BYTES - 1 {
            0x80
        } else {
            0
        };
        state[i / 8] |= u64::from(byte) << ((i % 8) * 8);
    }
    state
}
fn state_after_one(state: &[u64; 25]) -> [u64; 25] {
    let trace = generate_trace_rows::<Val>(vec![*state], 0);
    let row = &trace.values[(NUM_ROUNDS - 1) * NUM_KECCAK_COLS..NUM_ROUNDS * NUM_KECCAK_COLS];
    let cols: &KeccakCols<Val> = row.borrow();
    core::array::from_fn(|lane| {
        let y = lane / 5;
        let x = lane % 5;
        let mut bytes = [0u8; 8];
        for limb in 0..4 {
            let v = u16::try_from(cols.a_prime_prime_prime(y, x, limb).as_canonical_u32()).unwrap();
            bytes[limb * 2..limb * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        u64::from_le_bytes(bytes)
    })
}
fn xor_states(a: [u64; 25], b: [u64; 25]) -> [u64; 25] {
    core::array::from_fn(|i| a[i] ^ b[i])
}
fn state_digest(state: &[u64; 25]) -> ValArray {
    core::array::from_fn(|i| state[i / 8].to_le_bytes()[i % 8])
}
fn shake_rate_bytes(state: &[u64; 25]) -> [u8; SHAKE_RATE_BYTES] {
    core::array::from_fn(|i| state[i / 8].to_le_bytes()[i % 8])
}
fn shake_absorb_rate_block(state: &[u64; 25], block: &[u8; SHAKE_RATE_BYTES]) -> [u64; 25] {
    let mut absorbed = *state;
    for (index, byte) in block.iter().copied().enumerate() {
        absorbed[index / 8] ^= u64::from(byte) << ((index % 8) * 8);
    }
    absorbed
}
fn populate_path_row(
    row: &mut [Val],
    current: &ValArray,
    sibling: &ValArray,
    direction: bool,
    level: usize,
    phase: bool,
    active: bool,
) {
    for i in 0..DIGEST_BYTES {
        for bit in 0..8 {
            row[CURRENT_BITS + i * 8 + bit] = Val::from_u32(u32::from((current[i] >> bit) & 1));
            row[SIBLING_BITS + i * 8 + bit] = Val::from_u32(u32::from((sibling[i] >> bit) & 1));
        }
    }
    row[DIRECTION] = Val::from_u32(u32::from(direction));
    for bit in 0..7 {
        row[LEVEL_BITS + bit] = Val::from_u32(((level >> bit) & 1) as u32);
    }
    row[PHASE] = Val::from_u32(u32::from(phase));
    row[ACTIVE] = Val::from_u32(u32::from(active));
}
fn build_trace(
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
) -> (RowMajorMatrix<Val>, ValArray) {
    let mut path_currents = Vec::with_capacity(DEPTH);
    let mut current = *leaf;
    let mut permutations = Vec::with_capacity(ACTIVE_PERMUTATIONS);
    for level in 0..DEPTH {
        path_currents.push(current);
        let direction = ((path_index >> level) & 1) != 0;
        let (left, right) = if direction {
            (&siblings[level], &current)
        } else {
            (&current, &siblings[level])
        };
        let frame = candidate_frame(level as u8, left, right);
        let first = block_state(&frame, 0);
        let second = xor_states(state_after_one(&first), block_state(&frame, 1));
        current = state_digest(&state_after_one(&second));
        permutations.push(first);
        permutations.push(second);
    }
    let root = current;
    assert_eq!(permutations.len(), ACTIVE_PERMUTATIONS);
    let keccak_trace = generate_trace_rows::<Val>(permutations, 0);
    assert_eq!(keccak_trace.values.len(), TRACE_ROWS * NUM_KECCAK_COLS);
    let mut trace = vec![Val::ZERO; TRACE_ROWS * TRACE_WIDTH];
    for row_index in 0..TRACE_ROWS {
        let start = row_index * TRACE_WIDTH;
        trace[start..start + NUM_KECCAK_COLS].copy_from_slice(
            &keccak_trace.values[row_index * NUM_KECCAK_COLS..(row_index + 1) * NUM_KECCAK_COLS],
        );
        let row = &mut trace[start..start + TRACE_WIDTH];
        if row_index < ACTIVE_ROWS {
            let level = row_index / (PERMUTATIONS_PER_NODE * NUM_ROUNDS);
            let phase = ((row_index / NUM_ROUNDS) & 1) != 0;
            let direction = ((path_index >> level) & 1) != 0;
            populate_path_row(
                row,
                &path_currents[level],
                &siblings[level],
                direction,
                level,
                phase,
                true,
            );
        } else {
            populate_path_row(row, &root, &[0; DIGEST_BYTES], false, DEPTH, false, false);
        }
        for (slot, state_byte) in (0..34).chain([134, 135]).enumerate() {
            let byte = {
                let cols: &KeccakCols<Val> = row[..NUM_KECCAK_COLS].borrow();
                let linear_limb = state_byte / 2;
                let lane = linear_limb / 4;
                let limb = linear_limb % 4;
                let value = cols
                    .a_prime_prime_prime(lane / 5, lane % 5, limb)
                    .as_canonical_u32() as u16;
                value.to_le_bytes()[state_byte % 2]
            };
            for bit in 0..8 {
                row[ABSORB_BITS_OFFSET + slot * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    (RowMajorMatrix::new(trace, TRACE_WIDTH), root)
}
fn populate_source_row(row: &mut [Val], block_index: usize, block: &[u8; SHAKE_RATE_BYTES]) {
    for (byte_index, byte) in block.iter().copied().enumerate() {
        for bit in 0..8 {
            row[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                Val::from_u32(u32::from((byte >> bit) & 1));
        }
    }
    for bit in 0..7 {
        row[LEVEL_BITS + bit] = Val::from_u32(((64 + block_index) >> bit & 1) as u32);
    }
    row[DIRECTION] = Val::ZERO;
    row[PHASE] = Val::ZERO;
    row[ACTIVE] = Val::ONE;
}
fn rate_bytes_from_keccak_row(row: &[Val]) -> [u8; SHAKE_RATE_BYTES] {
    let cols: &KeccakCols<Val> = row[..NUM_KECCAK_COLS].borrow();
    core::array::from_fn(|state_byte| {
        let linear_limb = state_byte / 2;
        let lane = linear_limb / 4;
        let limb = linear_limb % 4;
        let value = cols
            .a_prime_prime_prime(lane / 5, lane % 5, limb)
            .as_canonical_u32() as u16;
        value.to_le_bytes()[state_byte % 2]
    })
}
fn source_block_state(block: &[u8; SHAKE_RATE_BYTES]) -> [u64; 25] {
    let mut state = [0u64; 25];
    for (i, byte) in block.iter().copied().enumerate() {
        state[i / 8] |= u64::from(byte) << ((i % 8) * 8);
    }
    state
}
fn build_source_bound_trace(
    source_blocks: &[[u8; SHAKE_RATE_BYTES]],
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
) -> (RowMajorMatrix<Val>, ValArray) {
    let mut trace = vec![Val::ZERO; TRACE_ROWS * SOURCE_TRACE_WIDTH];
    let root = populate_source_bound_trace(
        &mut trace,
        SOURCE_TRACE_WIDTH,
        0,
        TRACE_ROWS,
        source_blocks,
        leaf,
        siblings,
        path_index,
        None,
    );
    (RowMajorMatrix::new(trace, SOURCE_TRACE_WIDTH), root)
}
fn populate_source_bound_trace(
    trace: &mut [Val],
    trace_width: usize,
    row_offset: usize,
    row_count: usize,
    source_blocks: &[[u8; SHAKE_RATE_BYTES]],
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    source_commitment: Option<&ValArray>,
) -> ValArray {
    assert_eq!(source_blocks.len(), SOURCE_BLOCKS);
    assert!(trace_width >= SOURCE_TRACE_WIDTH);
    assert!(row_offset + row_count <= trace.len() / trace_width);
    let mut permutations = Vec::with_capacity(SOURCE_PERMUTATIONS + ACTIVE_PERMUTATIONS);
    let mut source_state_after = [0u64; 25];
    for (block_index, block) in source_blocks.iter().enumerate() {
        let absorbed = source_block_state(block);
        let state = if block_index == 0 {
            absorbed
        } else {
            xor_states(source_state_after, absorbed)
        };
        permutations.push(state);
        source_state_after = state_after_one(&state);
    }
    let mut path_currents = Vec::with_capacity(DEPTH);
    let mut current = *leaf;
    for level in 0..DEPTH {
        path_currents.push(current);
        let direction = ((path_index >> level) & 1) != 0;
        let (left, right) = if direction {
            (&siblings[level], &current)
        } else {
            (&current, &siblings[level])
        };
        let frame = candidate_frame(level as u8, left, right);
        let first = block_state(&frame, 0);
        let second = xor_states(state_after_one(&first), block_state(&frame, 1));
        current = state_digest(&state_after_one(&second));
        permutations.push(first);
        permutations.push(second);
    }
    let root = current;
    assert_eq!(
        permutations.len(),
        SOURCE_PERMUTATIONS + ACTIVE_PERMUTATIONS
    );
    let keccak_trace = generate_trace_rows::<Val>(permutations, 0);
    assert_eq!(keccak_trace.values.len(), TRACE_ROWS * NUM_KECCAK_COLS);
    for row_index in 0..row_count {
        let start = (row_offset + row_index) * trace_width;
        trace[start..start + NUM_KECCAK_COLS].copy_from_slice(
            &keccak_trace.values[row_index * NUM_KECCAK_COLS..(row_index + 1) * NUM_KECCAK_COLS],
        );
        let row = &mut trace[start..start + SOURCE_TRACE_WIDTH];
        if row_index < SOURCE_ROWS {
            let block_index = row_index / NUM_ROUNDS;
            let round = row_index % NUM_ROUNDS;
            populate_source_row(row, block_index, &source_blocks[block_index]);
            if round == NUM_ROUNDS - 1 {
                let output = rate_bytes_from_keccak_row(row);
                for (byte_index, byte) in output.into_iter().enumerate() {
                    for bit in 0..8 {
                        row[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                            Val::from_u32(u32::from((byte >> bit) & 1));
                    }
                }
            }
            if let Some(commitment) = source_commitment {
                for (byte_index, byte) in commitment.iter().copied().enumerate() {
                    for bit in 0..8 {
                        row[SIBLING_BITS + byte_index * 8 + bit] =
                            Val::from_u32(u32::from((byte >> bit) & 1));
                    }
                }
            }
        } else if row_index < SOURCE_BOUND_ACTIVE_ROWS {
            let path_row = row_index - SOURCE_ROWS;
            let level = path_row / (PERMUTATIONS_PER_NODE * NUM_ROUNDS);
            let phase = ((path_row / NUM_ROUNDS) & 1) != 0;
            let direction = ((path_index >> level) & 1) != 0;
            populate_path_row(
                row,
                &path_currents[level],
                &siblings[level],
                direction,
                level,
                phase,
                true,
            );
        } else {
            populate_path_row(row, &root, &[0; DIGEST_BYTES], false, DEPTH, false, false);
        }
        if row_index >= SOURCE_ROWS {
            for (slot, state_byte) in (0..34).chain([134, 135]).enumerate() {
                let byte = rate_bytes_from_keccak_row(row)[state_byte];
                for bit in 0..8 {
                    row[ABSORB_BITS_OFFSET + slot * 8 + bit] =
                        Val::from_u32(u32::from((byte >> bit) & 1));
                }
            }
        }
    }
    root
}
fn build_source_note_trace(
    source_blocks: &[[u8; SHAKE_RATE_BYTES]],
    source_commitment: &ValArray,
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    note_trace: &RowMajorMatrix<Val>,
) -> (RowMajorMatrix<Val>, ValArray) {
    build_source_note_trace_with_width(
        source_blocks,
        source_commitment,
        leaf,
        siblings,
        path_index,
        note_trace,
        SOURCE_NOTE_TRACE_WIDTH,
        TRACE_ROWS,
    )
}
fn build_source_note_trace_with_width(
    source_blocks: &[[u8; SHAKE_RATE_BYTES]],
    source_commitment: &ValArray,
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    note_trace: &RowMajorMatrix<Val>,
    trace_width: usize,
    trace_rows: usize,
) -> (RowMajorMatrix<Val>, ValArray) {
    assert_eq!(note_trace.width, note_commitment_opening::NOTE_TRACE_WIDTH);
    assert!(trace_width >= SOURCE_NOTE_TRACE_WIDTH);
    assert!(trace_rows == TRACE_ROWS || trace_rows == RDXL_TRACE_ROWS);
    let mut values = vec![Val::ZERO; trace_rows * trace_width];

    for note_row_index in 0..NOTE_ROWS {
        let note_source = note_row_index * note_commitment_opening::NOTE_TRACE_WIDTH;
        let target_start = note_row_index * trace_width;
        let row = &mut values[target_start..target_start + SOURCE_NOTE_TRACE_WIDTH];
        row[..NUM_KECCAK_COLS]
            .copy_from_slice(&note_trace.values[note_source..note_source + NUM_KECCAK_COLS]);
        for bit in 0..SOURCE_BUFFER_BITS {
            row[SOURCE_BUFFER_BITS_OFFSET + bit] =
                note_trace.values[note_source + note_commitment_opening::OUTPUT_BITS_OFFSET + bit];
        }
        row[ACTIVE] = Val::ONE;
        row[PHASE] = Val::from_u32((note_row_index / NUM_ROUNDS) as u32);
        row[NOTE_ACTIVE_OFFSET] = Val::ONE;
        row[NOTE_INVERSE_OFFSET] =
            note_trace.values[note_source + note_commitment_opening::VALUE_INVERSE_OFFSET];
        for bit in 0..(200 * 8) {
            row[NOTE_PRIVATE_BITS_OFFSET + bit] =
                note_trace.values[note_source + note_commitment_opening::SECRET_BITS_OFFSET + bit];
        }
        for (byte_index, byte) in source_commitment.iter().copied().enumerate() {
            for bit in 0..8 {
                row[SIBLING_BITS + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }

    // Populate source/path rows directly at their final offset: avoid retaining a
    // separate SOURCE_TRACE_WIDTH matrix while the wider composed trace is live.
    let root = populate_source_bound_trace(
        &mut values,
        trace_width,
        NOTE_ROWS,
        TRACE_ROWS - NOTE_ROWS,
        source_blocks,
        leaf,
        siblings,
        path_index,
        Some(source_commitment),
    );
    (RowMajorMatrix::new(values, trace_width), root)
}
fn candidate_hash_frame_state(tag: &[u8], fields: &[&[u8]]) -> [u64; 25] {
    let mut frame = Vec::new();
    frame.extend_from_slice(b"RADIX");
    frame.push(1);
    frame.extend_from_slice(&(tag.len() as u16).to_le_bytes());
    frame.extend_from_slice(tag);
    frame.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    for field in fields {
        frame.extend_from_slice(&(field.len() as u32).to_le_bytes());
        frame.extend_from_slice(field);
    }
    assert!(frame.len() < SHAKE_RATE_BYTES);
    let mut rate = [0u8; SHAKE_RATE_BYTES];
    rate[..frame.len()].copy_from_slice(&frame);
    rate[frame.len()] ^= 0x1f;
    rate[SHAKE_RATE_BYTES - 1] ^= 0x80;
    core::array::from_fn(|lane| {
        if lane < SHAKE_RATE_BYTES / 8 {
            u64::from_le_bytes(rate[lane * 8..lane * 8 + 8].try_into().unwrap())
        } else {
            0
        }
    })
}
fn input_kdf_absorb_blocks(
    kem_shared_secret: &[u8; 32],
    kem_ciphertext: &[u8; 1088],
    commitment: &[u8; 64],
) -> Vec<[u8; SHAKE_RATE_BYTES]> {
    let tag = b"radix/note-kdf/v1";
    let mut frame = Vec::with_capacity(INPUT_KDF_FRAME_BYTES);
    frame.extend_from_slice(b"RADIX");
    frame.push(1);
    frame.extend_from_slice(&(tag.len() as u16).to_le_bytes());
    frame.extend_from_slice(tag);
    frame.extend_from_slice(&3u16.to_le_bytes());
    frame.extend_from_slice(&(kem_shared_secret.len() as u32).to_le_bytes());
    frame.extend_from_slice(kem_shared_secret);
    frame.extend_from_slice(&(kem_ciphertext.len() as u32).to_le_bytes());
    frame.extend_from_slice(kem_ciphertext);
    frame.extend_from_slice(&(commitment.len() as u32).to_le_bytes());
    frame.extend_from_slice(commitment);
    assert_eq!(frame.len(), INPUT_KDF_FRAME_BYTES);
    let block_count = (frame.len() + 1).div_ceil(SHAKE_RATE_BYTES);
    (0..block_count)
        .map(|block_index| {
            core::array::from_fn(|within| {
                let offset = block_index * SHAKE_RATE_BYTES + within;
                if offset < frame.len() {
                    frame[offset]
                } else {
                    let mut padding = 0;
                    if offset == frame.len() {
                        padding |= 0x1f;
                    }
                    if within == SHAKE_RATE_BYTES - 1 {
                        padding |= 0x80;
                    }
                    padding
                }
            })
        })
        .collect()
}
fn build_source_key_note_trace(
    source_blocks: &[[u8; SHAKE_RATE_BYTES]],
    source_commitment: &ValArray,
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    note_trace: &RowMajorMatrix<Val>,
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
) -> (RowMajorMatrix<Val>, ValArray, ValArray) {
    let (base_trace, root) = build_source_note_trace(
        source_blocks,
        source_commitment,
        leaf,
        siblings,
        path_index,
        note_trace,
    );
    let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[spend_secret]);
    let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
    let owner_state = candidate_hash_frame_state(
        b"radix/one-time/v1",
        &[&spend_public_key, kem_shared_secret],
    );
    let owner = state_digest(&state_after_one(&owner_state));
    let key_permutations = generate_trace_rows::<Val>(vec![spend_pk_state, owner_state], 0);
    let mut values = vec![Val::ZERO; TRACE_ROWS * SOURCE_KEY_NOTE_TRACE_WIDTH];

    for row_index in 0..TRACE_ROWS {
        let target_start = row_index * SOURCE_KEY_NOTE_TRACE_WIDTH;
        let target = &mut values[target_start..target_start + SOURCE_KEY_NOTE_TRACE_WIDTH];
        if row_index < 2 * NUM_ROUNDS {
            let source_start = row_index * SOURCE_NOTE_TRACE_WIDTH;
            target[..SOURCE_NOTE_TRACE_WIDTH].copy_from_slice(
                &base_trace.values[source_start..source_start + SOURCE_NOTE_TRACE_WIDTH],
            );
            let keccak_start = row_index * NUM_KECCAK_COLS;
            target[..NUM_KECCAK_COLS].copy_from_slice(
                &key_permutations.values[keccak_start..keccak_start + NUM_KECCAK_COLS],
            );
            target[ACTIVE] = Val::ONE;
            target[PHASE] = Val::ZERO;
            target[NOTE_ACTIVE_OFFSET] = Val::ZERO;
            target[SPEND_PK_ACTIVE_OFFSET] = Val::from_u32(u32::from(row_index < NUM_ROUNDS));
            target[NOTE_OWNER_ACTIVE_OFFSET] = Val::from_u32(u32::from(row_index >= NUM_ROUNDS));
        } else {
            let source_row = row_index - 2 * NUM_ROUNDS;
            let source_start = source_row * SOURCE_NOTE_TRACE_WIDTH;
            target[..SOURCE_NOTE_TRACE_WIDTH].copy_from_slice(
                &base_trace.values[source_start..source_start + SOURCE_NOTE_TRACE_WIDTH],
            );
        }
        for (index, byte) in spend_secret
            .iter()
            .chain(kem_shared_secret.iter())
            .copied()
            .enumerate()
        {
            target[SPEND_OWNER_PRIVATE_OFFSET + index] = Val::from_u32(u32::from(byte));
            for bit in 0..8 {
                target[SPEND_OWNER_PRIVATE_BITS_OFFSET + index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    // Carry pk_s as private bit-decomposed bytes from the spend-key hash into the owner frame.
    for row_index in NUM_ROUNDS..(2 * NUM_ROUNDS) {
        let start = row_index * SOURCE_KEY_NOTE_TRACE_WIDTH;
        let row = &mut values[start..start + SOURCE_KEY_NOTE_TRACE_WIDTH];
        for (byte_index, byte) in spend_public_key.iter().copied().enumerate() {
            for bit in 0..8 {
                row[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    (
        RowMajorMatrix::new(values, SOURCE_KEY_NOTE_TRACE_WIDTH),
        root,
        owner,
    )
}
fn build_source_key_note_nullifier_trace(
    source_blocks: &[[u8; SHAKE_RATE_BYTES]],
    source_commitment: &ValArray,
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    note_trace: &RowMajorMatrix<Val>,
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    rho: &[u8; 64],
) -> (RowMajorMatrix<Val>, ValArray, ValArray, ValArray) {
    build_source_key_note_nullifier_trace_with_width(
        source_blocks,
        source_commitment,
        leaf,
        siblings,
        path_index,
        note_trace,
        spend_secret,
        kem_shared_secret,
        rho,
        SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH,
        TRACE_ROWS,
    )
}

// Build at the requested final width and row count. RDXL uses 8192 rows here so
// output-side composition can fill the upper half without a second full-width matrix.
fn build_source_key_note_nullifier_trace_with_width(
    source_blocks: &[[u8; SHAKE_RATE_BYTES]],
    source_commitment: &ValArray,
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    note_trace: &RowMajorMatrix<Val>,
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    rho: &[u8; 64],
    trace_width: usize,
    trace_rows: usize,
) -> (RowMajorMatrix<Val>, ValArray, ValArray, ValArray) {
    assert!(trace_rows == TRACE_ROWS || trace_rows == RDXL_TRACE_ROWS);
    assert!(trace_width >= SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH);
    let (mut base_trace, root) = build_source_note_trace_with_width(
        source_blocks,
        source_commitment,
        leaf,
        siblings,
        path_index,
        note_trace,
        trace_width,
        trace_rows,
    );
    assert_eq!(base_trace.width, trace_width);

    // Arrange the existing base rows in their composed positions in place.
    // This avoids allocating a second full-width matrix just to widen/copy rows.
    let repeated_note_rows = 4 * NUM_ROUNDS;
    for source_row in (0..TRACE_ROWS - repeated_note_rows).rev() {
        let source_start = source_row * trace_width;
        let target_start = (source_row + repeated_note_rows) * trace_width;
        base_trace
            .values
            .copy_within(source_start..source_start + trace_width, target_start);
    }
    for target_row in NOTE_ROWS..repeated_note_rows {
        let source_row = target_row % NOTE_ROWS;
        let source_start = source_row * trace_width;
        let target_start = target_row * trace_width;
        base_trace
            .values
            .copy_within(source_start..source_start + trace_width, target_start);
    }
    let mut values = base_trace.values;
    let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[spend_secret]);
    let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
    let owner_state = candidate_hash_frame_state(
        b"radix/one-time/v1",
        &[&spend_public_key, kem_shared_secret],
    );
    let owner = state_digest(&state_after_one(&owner_state));
    let nullifier_frame = crate::nullifier_opening::frame_for(spend_secret, kem_shared_secret, rho);
    let nullifier_first = crate::nullifier_opening::block_state(&nullifier_frame, 0);
    let nullifier_second = xor_states(
        state_after_one(&nullifier_first),
        crate::nullifier_opening::block_state(&nullifier_frame, 1),
    );
    let nullifier = state_digest(&state_after_one(&nullifier_second));
    let composed_permutations = generate_trace_rows::<Val>(
        vec![
            spend_pk_state,
            owner_state,
            nullifier_first,
            nullifier_second,
        ],
        0,
    );
    for row_index in 0..trace_rows {
        let target_start = row_index * trace_width;
        let target = &mut values[target_start..target_start + trace_width];
        if row_index < 4 * NUM_ROUNDS {
            let keccak_start = row_index * NUM_KECCAK_COLS;
            target[..NUM_KECCAK_COLS].copy_from_slice(
                &composed_permutations.values[keccak_start..keccak_start + NUM_KECCAK_COLS],
            );
            target[ACTIVE] = Val::ONE;
            target[PHASE] = Val::from_u32(u32::from(row_index >= 3 * NUM_ROUNDS));
            target[NOTE_ACTIVE_OFFSET] = Val::ZERO;
            target[SPEND_PK_ACTIVE_OFFSET] = Val::from_u32(u32::from(row_index < NUM_ROUNDS));
            target[NOTE_OWNER_ACTIVE_OFFSET] =
                Val::from_u32(u32::from((NUM_ROUNDS..2 * NUM_ROUNDS).contains(&row_index)));
            target[NULLIFIER_ACTIVE_OFFSET] = Val::from_u32(u32::from(
                (2 * NUM_ROUNDS..4 * NUM_ROUNDS).contains(&row_index),
            ));
            for bit in 0..SOURCE_BUFFER_BITS {
                target[SOURCE_BUFFER_BITS_OFFSET + bit] = Val::ZERO;
            }
        }
        for (index, byte) in spend_secret
            .iter()
            .chain(kem_shared_secret.iter())
            .copied()
            .enumerate()
        {
            target[SPEND_OWNER_PRIVATE_OFFSET + index] = Val::from_u32(u32::from(byte));
            for bit in 0..8 {
                target[SPEND_OWNER_PRIVATE_BITS_OFFSET + index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }

    // Reuse the rate buffer sequentially: owner input first, then nullifier first-block output.
    for row_index in NUM_ROUNDS..(2 * NUM_ROUNDS) {
        let start = row_index * trace_width;
        let row = &mut values[start..start + trace_width];
        for (byte_index, byte) in spend_public_key.iter().copied().enumerate() {
            for bit in 0..8 {
                row[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    let first_nullifier_output = {
        let end_row = 3 * NUM_ROUNDS - 1;
        let start = end_row * NUM_KECCAK_COLS;
        rate_bytes_from_keccak_row(&composed_permutations.values[start..start + NUM_KECCAK_COLS])
    };
    for row_index in (3 * NUM_ROUNDS)..(4 * NUM_ROUNDS) {
        let start = row_index * trace_width;
        let row = &mut values[start..start + trace_width];
        for (byte_index, byte) in first_nullifier_output.iter().copied().enumerate() {
            for bit in 0..8 {
                row[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    (
        RowMajorMatrix::new(values, trace_width),
        root,
        owner,
        nullifier,
    )
}
fn build_source_key_note_nullifier_output_trace(
    trace: RowMajorMatrix<Val>,
    input_value: u64,
    output_note: &OutputNoteOpeningV1,
    fee: u64,
    output_note_trace: &RowMajorMatrix<Val>,
    statement: &TransactionStatementV1,
) -> RowMajorMatrix<Val> {
    let output_shared_secret: [u8; 32] = core::array::from_fn(|byte| {
        let start = SPEND_OWNER_PRIVATE_BITS_OFFSET + (64 + byte) * 8;
        (0..8).fold(0u8, |value, bit| {
            value | ((trace.values[start + bit].as_canonical_u32() as u8) << bit)
        })
    });
    build_source_key_note_nullifier_output_trace_with_secret(
        trace,
        input_value,
        output_note,
        fee,
        output_note_trace,
        statement,
        &output_shared_secret,
    )
}
fn build_source_key_note_nullifier_output_trace_with_secret(
    mut trace: RowMajorMatrix<Val>,
    input_value: u64,
    output_note: &OutputNoteOpeningV1,
    fee: u64,
    output_note_trace: &RowMajorMatrix<Val>,
    statement: &TransactionStatementV1,
    output_shared_secret: &[u8; 32],
) -> RowMajorMatrix<Val> {
    assert_eq!(trace.width, RDXL_TRACE_WIDTH);
    assert_eq!(trace.values.len(), RDXL_TRACE_ROWS * RDXL_TRACE_WIDTH);
    let mut carries = [0u32; 3];
    let mut carry = 0u64;
    for limb in 0..4 {
        let out_limb = (output_note.value >> (limb * 16)) & 0xffff;
        let fee_limb = (fee >> (limb * 16)) & 0xffff;
        carry = (out_limb + fee_limb + carry) >> 16;
        if limb < 3 {
            carries[limb] = carry as u32;
        }
    }
    let mut output_private = [0u8; 200];
    output_private[..64].copy_from_slice(&output_note.owner);
    output_private[64..72].copy_from_slice(&output_note.value.to_le_bytes());
    output_private[72..136].copy_from_slice(&output_note.rho);
    output_private[136..].copy_from_slice(&output_note.randomness);
    let output_inverse = Val::from_u32(output_note.value.count_ones()).inverse();
    let output_start = KEY_NOTE_NULLIFIER_ACTIVE_ROWS;
    let output_end = output_start + NOTE_ROWS;

    for row_index in 0..RDXL_TRACE_ROWS {
        let target_start = row_index * RDXL_TRACE_WIDTH;
        let target = &mut trace.values[target_start..target_start + RDXL_TRACE_WIDTH];
        for bit in 0..64 {
            target[INPUT_VALUE_BITS_OFFSET + bit] =
                Val::from_u32(u32::from(((input_value >> bit) & 1) as u8));
        }
        if row_index >= output_start {
            for (byte_index, byte) in output_private.iter().copied().enumerate() {
                for bit in 0..8 {
                    target[NOTE_PRIVATE_BITS_OFFSET + byte_index * 8 + bit] =
                        Val::from_u32(u32::from((byte >> bit) & 1));
                }
            }
        }
        if (output_start..output_end).contains(&row_index) {
            let output_row = row_index - output_start;
            let output_keccak_start = output_row * note_commitment_opening::NOTE_TRACE_WIDTH;
            target[..NUM_KECCAK_COLS].copy_from_slice(
                &output_note_trace.values
                    [output_keccak_start..output_keccak_start + NUM_KECCAK_COLS],
            );
            for bit in 0..SOURCE_BUFFER_BITS {
                target[SOURCE_BUFFER_BITS_OFFSET + bit] = output_note_trace.values
                    [output_keccak_start + note_commitment_opening::OUTPUT_BITS_OFFSET + bit];
            }
            target[PHASE] = Val::from_u32((output_row / NUM_ROUNDS) as u32);
            target[NOTE_ACTIVE_OFFSET] = Val::ZERO;
            target[OUTPUT_NOTE_ACTIVE_OFFSET] = Val::ONE;
            target[NOTE_INVERSE_OFFSET] = output_inverse;
            for (byte_index, byte) in output_private.iter().copied().enumerate() {
                for bit in 0..8 {
                    target[NOTE_PRIVATE_BITS_OFFSET + byte_index * 8 + bit] =
                        Val::from_u32(u32::from((byte >> bit) & 1));
                }
            }
            for carry_index in 0..3 {
                target[BALANCE_CARRY_BITS_OFFSET + carry_index] =
                    Val::from_u32(carries[carry_index]);
            }
        }
    }

    let output_blocks = output_leaf_absorb_blocks(
        statement.output.commitment,
        statement.output.kem_ciphertext,
        statement.output.nonce,
        &statement.output.ciphertext,
    );
    assert!((10..=14).contains(&output_blocks.len()));
    let mut sponge_state = [0u64; 25];
    let mut output_permutation_inputs = Vec::with_capacity(output_blocks.len());
    let mut states_before_block = Vec::with_capacity(output_blocks.len());
    for block in &output_blocks {
        states_before_block.push(sponge_state);
        let input_state = shake_absorb_rate_block(&sponge_state, block);
        output_permutation_inputs.push(input_state);
        sponge_state = state_after_one(&input_state);
    }
    let output_permutations = generate_trace_rows::<Val>(output_permutation_inputs, 0);
    let output_leaf_start = KEY_NOTE_NULLIFIER_OUTPUT_ACTIVE_ROWS;
    assert!(output_leaf_start + OUTPUT_LEAF_BLOCK_SLOTS * NUM_ROUNDS <= RDXL_TRACE_ROWS);
    assert!(output_blocks.len() <= OUTPUT_LEAF_BLOCK_SLOTS);
    for block_index in 0..output_blocks.len() {
        let prior_state = states_before_block[block_index];
        let prior_bytes = shake_rate_bytes(&prior_state);
        for round in 0..NUM_ROUNDS {
            let row_index = output_leaf_start + block_index * NUM_ROUNDS + round;
            let target_start = row_index * RDXL_TRACE_WIDTH;
            let target = &mut trace.values[target_start..target_start + RDXL_TRACE_WIDTH];
            let perm_start = (block_index * NUM_ROUNDS + round) * NUM_KECCAK_COLS;
            target[..NUM_KECCAK_COLS].copy_from_slice(
                &output_permutations.values[perm_start..perm_start + NUM_KECCAK_COLS],
            );
            target[ACTIVE] = Val::ZERO;
            target[PHASE] = Val::ZERO;
            target[OUTPUT_LEAF_ACTIVE_OFFSET] = Val::ONE;
            for bit in 0..7 {
                target[LEVEL_BITS + bit] = Val::from_u32(u32::from(bit == 6));
            }
            for bit in 0..4 {
                target[OUTPUT_LEAF_INDEX_BITS_OFFSET + bit] =
                    Val::from_u32(((block_index >> bit) & 1) as u32);
            }
            for byte_index in 0..SHAKE_RATE_BYTES {
                let byte = prior_bytes[byte_index];
                for bit in 0..8 {
                    target[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                        Val::from_u32(u32::from((byte >> bit) & 1));
                    target[OUTPUT_LEAF_BLOCK_BITS_OFFSET + byte_index * 8 + bit] = Val::from_u32(
                        u32::from((output_blocks[block_index][byte_index] >> bit) & 1),
                    );
                }
            }
        }
    }

    let mut source_field_bytes = [0u8; INPUT_KDF_SOURCE_BYTES];
    for (field_index, frame_offset) in (27..=90).chain(95..=1182).enumerate() {
        let block = frame_offset / SHAKE_RATE_BYTES;
        let within = frame_offset % SHAKE_RATE_BYTES;
        // The composed trace begins with four spend/owner/nullifier permutations,
        // then the input-note commitment permutations, then source-leaf blocks.
        let source_row = 4 * NUM_ROUNDS + NOTE_ROWS + block * NUM_ROUNDS;
        let row_start = source_row * RDXL_TRACE_WIDTH;
        source_field_bytes[field_index] = (0..8).fold(0u8, |value, bit| {
            let witnessed = trace.values[row_start + SOURCE_BUFFER_BITS_OFFSET + within * 8 + bit]
                .as_canonical_u32() as u8;
            value | (witnessed << bit)
        });
    }
    let mut source_aead_bytes = [0u8; INPUT_AEAD_SOURCE_BYTES];
    for (field_index, frame_offset) in (SOURCE_NONCE_FRAME_OFFSET..SOURCE_NONCE_FRAME_OFFSET + 12)
        .chain(
            SOURCE_CIPHERTEXT_FRAME_OFFSET
                ..SOURCE_CIPHERTEXT_FRAME_OFFSET + SOURCE_CIPHERTEXT_BYTES,
        )
        .enumerate()
    {
        let block = frame_offset / SHAKE_RATE_BYTES;
        let within = frame_offset % SHAKE_RATE_BYTES;
        let source_row = 4 * NUM_ROUNDS + NOTE_ROWS + block * NUM_ROUNDS;
        let row_start = source_row * RDXL_TRACE_WIDTH;
        source_aead_bytes[field_index] = (0..8).fold(0u8, |value, bit| {
            let witnessed = trace.values[row_start + SOURCE_BUFFER_BITS_OFFSET + within * 8 + bit]
                .as_canonical_u32() as u8;
            value | (witnessed << bit)
        });
    }
    let input_note_row_start = 4 * NUM_ROUNDS * RDXL_TRACE_WIDTH;
    let mut input_note_rho_randomness = [0u8; INPUT_NOTE_RHO_RANDOMNESS_BYTES];
    for byte in 0..INPUT_NOTE_RHO_RANDOMNESS_BYTES {
        input_note_rho_randomness[byte] = (0..8).fold(0u8, |value, bit| {
            let note_bit = trace.values
                [input_note_row_start + NOTE_PRIVATE_BITS_OFFSET + (72 + byte) * 8 + bit]
                .as_canonical_u32() as u8;
            value | (note_bit << bit)
        });
    }
    let kem_shared_secret: [u8; 32] = core::array::from_fn(|byte| {
        let row_start = SPEND_OWNER_PRIVATE_BITS_OFFSET + (64 + byte) * 8;
        (0..8).fold(0u8, |value, bit| {
            value | ((trace.values[row_start + bit].as_canonical_u32() as u8) << bit)
        })
    });
    let mut source_commitment = [0u8; 64];
    source_commitment.copy_from_slice(&source_field_bytes[..64]);
    let mut source_kem_ciphertext = [0u8; 1088];
    source_kem_ciphertext.copy_from_slice(&source_field_bytes[64..]);
    let kdf_blocks = input_kdf_absorb_blocks(
        &kem_shared_secret,
        &source_kem_ciphertext,
        &source_commitment,
    );
    assert_eq!(kdf_blocks.len(), INPUT_KDF_BLOCKS);
    let mut kdf_sponge_state = [0u64; 25];
    let mut kdf_permutation_inputs = Vec::with_capacity(INPUT_KDF_BLOCKS);
    let mut kdf_states_before_block = Vec::with_capacity(INPUT_KDF_BLOCKS);
    for block in &kdf_blocks {
        kdf_states_before_block.push(kdf_sponge_state);
        let input_state = shake_absorb_rate_block(&kdf_sponge_state, block);
        kdf_permutation_inputs.push(input_state);
        kdf_sponge_state = state_after_one(&input_state);
    }
    let kdf_key = shake_rate_bytes(&kdf_sponge_state);
    let aes256_key: [u8; 32] = kdf_key[..32].try_into().unwrap();
    let expanded_aes256_key = aes_sbox_air::expand_aes256_key(&aes256_key);
    let kdf_permutations = generate_trace_rows::<Val>(kdf_permutation_inputs, 0);
    let kdf_start = output_leaf_start + output_blocks.len() * NUM_ROUNDS;
    let output_leaf_max_end = output_leaf_start + OUTPUT_LEAF_MAX_BLOCKS * NUM_ROUNDS;
    assert!(
        output_leaf_max_end + INPUT_KDF_ROWS + AES256_KEY_SCHEDULE_ROWS + AES256_BLOCK_ROWS
            <= RDXL_TRACE_ROWS
    );
    assert!(
        kdf_start + INPUT_KDF_ROWS + AES256_KEY_SCHEDULE_ROWS + AES256_BLOCK_ROWS
            <= RDXL_TRACE_ROWS
    );
    for block_index in 0..INPUT_KDF_BLOCKS {
        let prior_bytes = shake_rate_bytes(&kdf_states_before_block[block_index]);
        for round in 0..NUM_ROUNDS {
            let row_index = kdf_start + block_index * NUM_ROUNDS + round;
            let target_start = row_index * RDXL_TRACE_WIDTH;
            let target = &mut trace.values[target_start..target_start + RDXL_TRACE_WIDTH];
            let perm_start = (block_index * NUM_ROUNDS + round) * NUM_KECCAK_COLS;
            target[..NUM_KECCAK_COLS].copy_from_slice(
                &kdf_permutations.values[perm_start..perm_start + NUM_KECCAK_COLS],
            );
            target[ACTIVE] = Val::ZERO;
            target[PHASE] = Val::ZERO;
            target[INPUT_KDF_ACTIVE_OFFSET] = Val::ONE;
            for bit in 0..7 {
                target[LEVEL_BITS + bit] = Val::from_u32(u32::from(bit == 6));
            }
            for bit in 0..4 {
                target[INPUT_KDF_INDEX_BITS_OFFSET + bit] =
                    Val::from_u32(((block_index >> bit) & 1) as u32);
            }
            for byte_index in 0..SHAKE_RATE_BYTES {
                let byte = prior_bytes[byte_index];
                for bit in 0..8 {
                    target[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                        Val::from_u32(u32::from((byte >> bit) & 1));
                    target[INPUT_KDF_BLOCK_BITS_OFFSET + byte_index * 8 + bit] =
                        Val::from_u32(u32::from((kdf_blocks[block_index][byte_index] >> bit) & 1));
                }
            }
        }
    }
    let kdf_end = kdf_start + INPUT_KDF_ROWS;
    for group in 0..AES256_KEY_SCHEDULE_ROWS {
        let row_index = kdf_end + group;
        let row_start = row_index * RDXL_TRACE_WIDTH;
        let target = &mut trace.values[row_start..row_start + RDXL_TRACE_WIDTH];
        target[AES256_KEY_SCHEDULE_ACTIVE_OFFSET] = Val::ONE;
        for bit in 0..4 {
            target[AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET + bit] =
                Val::from_u32(((group >> bit) & 1) as u32);
        }
        let word = 8 + group * 4;
        for sbox_index in 0..AES256_SBOX_COUNT {
            let source_byte = if word % 8 == 0 {
                (sbox_index + 1) % 4
            } else {
                sbox_index
            };
            let input = expanded_aes256_key[(word - 1) * 4 + source_byte];
            populate_sbox_air_witness(
                target,
                input,
                AES256_SBOX_INPUT_BITS_OFFSET + sbox_index * 8,
                AES256_SBOX_OUTPUT_BITS_OFFSET + sbox_index * 8,
                AES256_SBOX_WITNESS_OFFSET + sbox_index * AES_SBOX_WITNESS_COLUMNS,
            );
        }
        for (byte_index, byte) in expanded_aes256_key.iter().copied().enumerate() {
            for bit in 0..8 {
                target[AES256_KEY_SCHEDULE_BITS_OFFSET + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    let aes_start = kdf_end + AES256_KEY_SCHEDULE_ROWS;
    let mut input_plaintext = [0u8; 140];
    input_plaintext[..8].copy_from_slice(&input_value.to_le_bytes());
    input_plaintext[8..136].copy_from_slice(&input_note_rho_randomness);
    for block_index in 0..AES256_BLOCKS {
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(&source_aead_bytes[..12]);
        counter_block[12..].copy_from_slice(&(2u32 + block_index as u32).to_be_bytes());
        let aes_round_states =
            aes_sbox_air::aes256_encrypt_round_states(&expanded_aes256_key, &counter_block);
        for round in 0..AES256_BLOCK_ROUNDS {
            let row_index = aes_start + block_index * AES256_BLOCK_ROUNDS + round;
            let row_start = row_index * RDXL_TRACE_WIDTH;
            let target = &mut trace.values[row_start..row_start + RDXL_TRACE_WIDTH];
            target[AES256_BLOCK_ACTIVE_OFFSET] = Val::ONE;
            for bit in 0..4 {
                target[AES256_BLOCK_INDEX_BITS_OFFSET + bit] =
                    Val::from_u32(((round >> bit) & 1) as u32);
                target[AES256_BLOCK_NUMBER_BITS_OFFSET + bit] =
                    Val::from_u32(((block_index >> bit) & 1) as u32);
            }
            for (key_byte_index, key_byte) in expanded_aes256_key.iter().copied().enumerate() {
                for bit in 0..8 {
                    target[AES256_KEY_SCHEDULE_BITS_OFFSET + key_byte_index * 8 + bit] =
                        Val::from_u32(u32::from((key_byte >> bit) & 1));
                }
            }
            for byte in 0..16 {
                let input = aes_round_states[round][byte];
                let output = aes_round_states[round + 1][byte];
                for bit in 0..8 {
                    target[AES256_BLOCK_STATE_INPUT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(u32::from((input >> bit) & 1));
                    target[AES256_BLOCK_STATE_OUTPUT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(u32::from((output >> bit) & 1));
                }
                if round > 0 {
                    populate_sbox_air_witness(
                        target,
                        input,
                        AES256_BLOCK_STATE_INPUT_BITS_OFFSET + byte * 8,
                        AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + byte * 8,
                        AES256_BLOCK_SBOX_WITNESS_OFFSET + byte * AES_SBOX_WITNESS_COLUMNS,
                    );
                }
                let plaintext_index = block_index * 16 + byte;
                let plaintext_byte = input_plaintext.get(plaintext_index).copied().unwrap_or(0);
                for bit in 0..8 {
                    target[AES256_BLOCK_CIPHERTEXT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(if plaintext_index < input_plaintext.len() {
                            u32::from((source_aead_bytes[12 + plaintext_index] >> bit) & 1)
                        } else {
                            0
                        });
                    target[AES256_BLOCK_PLAINTEXT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(u32::from((plaintext_byte >> bit) & 1));
                }
            }
            if (1..14).contains(&round) {
                let substituted: [u8; 16] =
                    core::array::from_fn(|byte| aes_sbox_air::sbox(aes_round_states[round][byte]));
                let shifted = aes_sbox_air::shift_rows(&substituted);
                let mixed = aes_sbox_air::mix_columns(&shifted);
                for byte in 0..16 {
                    let doubled = aes_sbox_air::mul2(shifted[byte]);
                    let tripled = doubled ^ shifted[byte];
                    for bit in 0..8 {
                        target[AES256_BLOCK_XTIME_BITS_OFFSET + byte * 8 + bit] =
                            Val::from_u32(u32::from((doubled >> bit) & 1));
                        target[AES256_BLOCK_MUL3_BITS_OFFSET + byte * 8 + bit] =
                            Val::from_u32(u32::from((tripled >> bit) & 1));
                        target[AES256_BLOCK_MIXED_BITS_OFFSET + byte * 8 + bit] =
                            Val::from_u32(u32::from((mixed[byte] >> bit) & 1));
                    }
                }
            }
        }
    }
    let final_rate = shake_rate_bytes(&kdf_sponge_state);
    for row_index in kdf_end..RDXL_TRACE_ROWS {
        let target_start = row_index * RDXL_TRACE_WIDTH;
        let target = &mut trace.values[target_start..target_start + RDXL_TRACE_WIDTH];
        for (byte_index, byte) in final_rate.iter().copied().enumerate() {
            for bit in 0..8 {
                target[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }

    let output_kdf_blocks = input_kdf_absorb_blocks(
        output_shared_secret,
        &statement.output.kem_ciphertext,
        &statement.output.commitment,
    );
    assert_eq!(output_kdf_blocks.len(), INPUT_KDF_BLOCKS);
    let mut output_sponge_state = [0u64; 25];
    let mut output_permutation_inputs = Vec::with_capacity(INPUT_KDF_BLOCKS);
    let mut output_states_before_block = Vec::with_capacity(INPUT_KDF_BLOCKS);
    for block in &output_kdf_blocks {
        output_states_before_block.push(output_sponge_state);
        let input_state = shake_absorb_rate_block(&output_sponge_state, block);
        output_permutation_inputs.push(input_state);
        output_sponge_state = state_after_one(&input_state);
    }
    let output_kdf_rate = shake_rate_bytes(&output_sponge_state);
    let output_aes_key: [u8; 32] = output_kdf_rate[..32].try_into().unwrap();
    let output_expanded_key = aes_sbox_air::expand_aes256_key(&output_aes_key);
    let output_kdf_permutations = generate_trace_rows::<Val>(output_permutation_inputs, 0);
    let output_kdf_start = aes_start + AES256_BLOCK_ROWS;
    let output_kdf_end = output_kdf_start + INPUT_KDF_ROWS;
    let output_schedule_start = output_kdf_end;
    let output_aes_start = output_schedule_start + AES256_KEY_SCHEDULE_ROWS;
    let output_aes_end = output_aes_start + AES256_BLOCK_ROWS;
    assert!(
        output_leaf_max_end
            + INPUT_KDF_ROWS
            + AES256_KEY_SCHEDULE_ROWS
            + AES256_BLOCK_ROWS
            + INPUT_KDF_ROWS
            + AES256_KEY_SCHEDULE_ROWS
            + AES256_BLOCK_ROWS
            <= RDXL_TRACE_ROWS
    );
    assert!(output_aes_end <= RDXL_TRACE_ROWS);
    for block_index in 0..INPUT_KDF_BLOCKS {
        let prior_bytes = shake_rate_bytes(&output_states_before_block[block_index]);
        for round in 0..NUM_ROUNDS {
            let row_index = output_kdf_start + block_index * NUM_ROUNDS + round;
            let target_start = row_index * RDXL_TRACE_WIDTH;
            let target = &mut trace.values[target_start..target_start + RDXL_TRACE_WIDTH];
            let perm_start = (block_index * NUM_ROUNDS + round) * NUM_KECCAK_COLS;
            target[..NUM_KECCAK_COLS].copy_from_slice(
                &output_kdf_permutations.values[perm_start..perm_start + NUM_KECCAK_COLS],
            );
            target[ACTIVE] = Val::ZERO;
            target[PHASE] = Val::ZERO;
            target[INPUT_KDF_ACTIVE_OFFSET] = Val::ONE;
            target[CRYPTO_OUTPUT_MODE_OFFSET] = Val::ONE;
            for bit in 0..7 {
                target[LEVEL_BITS + bit] = Val::from_u32(u32::from(bit == 6));
            }
            for bit in 0..4 {
                target[INPUT_KDF_INDEX_BITS_OFFSET + bit] =
                    Val::from_u32(((block_index >> bit) & 1) as u32);
            }
            for byte_index in 0..SHAKE_RATE_BYTES {
                let byte = prior_bytes[byte_index];
                for bit in 0..8 {
                    target[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                        Val::from_u32(u32::from((byte >> bit) & 1));
                    target[INPUT_KDF_BLOCK_BITS_OFFSET + byte_index * 8 + bit] = Val::from_u32(
                        u32::from((output_kdf_blocks[block_index][byte_index] >> bit) & 1),
                    );
                }
            }
        }
    }
    for group in 0..AES256_KEY_SCHEDULE_ROWS {
        let row_index = output_schedule_start + group;
        let row_start = row_index * RDXL_TRACE_WIDTH;
        let target = &mut trace.values[row_start..row_start + RDXL_TRACE_WIDTH];
        target[AES256_KEY_SCHEDULE_ACTIVE_OFFSET] = Val::ONE;
        target[CRYPTO_OUTPUT_MODE_OFFSET] = Val::ONE;
        for bit in 0..4 {
            target[AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET + bit] =
                Val::from_u32(((group >> bit) & 1) as u32);
        }
        let word = 8 + group * 4;
        for sbox_index in 0..AES256_SBOX_COUNT {
            let source_byte = if word % 8 == 0 {
                (sbox_index + 1) % 4
            } else {
                sbox_index
            };
            let input = output_expanded_key[(word - 1) * 4 + source_byte];
            populate_sbox_air_witness(
                target,
                input,
                AES256_SBOX_INPUT_BITS_OFFSET + sbox_index * 8,
                AES256_SBOX_OUTPUT_BITS_OFFSET + sbox_index * 8,
                AES256_SBOX_WITNESS_OFFSET + sbox_index * AES_SBOX_WITNESS_COLUMNS,
            );
        }
        for (byte_index, byte) in output_expanded_key.iter().copied().enumerate() {
            for bit in 0..8 {
                target[AES256_KEY_SCHEDULE_BITS_OFFSET + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    assert_eq!(statement.output.ciphertext.len(), OUTPUT_CIPHERTEXT_BYTES);
    // This profile constrains only AES-CTR ciphertext bytes [0..140]. The final
    // 16-byte tag is bound into the statement/output leaf, but no GHASH relation
    // authenticates it; do not describe this as AES-GCM verification.
    let mut output_plaintext = [0u8; 140];
    output_plaintext[..8].copy_from_slice(&output_note.value.to_le_bytes());
    output_plaintext[8..72].copy_from_slice(&output_note.rho);
    output_plaintext[72..136].copy_from_slice(&output_note.randomness);
    for block_index in 0..AES256_BLOCKS {
        let mut counter_block = [0u8; 16];
        counter_block[..12].copy_from_slice(&statement.output.nonce);
        counter_block[12..].copy_from_slice(&(2u32 + block_index as u32).to_be_bytes());
        let aes_round_states =
            aes_sbox_air::aes256_encrypt_round_states(&output_expanded_key, &counter_block);
        for round in 0..AES256_BLOCK_ROUNDS {
            let row_index = output_aes_start + block_index * AES256_BLOCK_ROUNDS + round;
            let row_start = row_index * RDXL_TRACE_WIDTH;
            let target = &mut trace.values[row_start..row_start + RDXL_TRACE_WIDTH];
            target[AES256_BLOCK_ACTIVE_OFFSET] = Val::ONE;
            target[CRYPTO_OUTPUT_MODE_OFFSET] = Val::ONE;
            for bit in 0..4 {
                target[AES256_BLOCK_INDEX_BITS_OFFSET + bit] =
                    Val::from_u32(((round >> bit) & 1) as u32);
                target[AES256_BLOCK_NUMBER_BITS_OFFSET + bit] =
                    Val::from_u32(((block_index >> bit) & 1) as u32);
            }
            for (key_byte_index, key_byte) in output_expanded_key.iter().copied().enumerate() {
                for bit in 0..8 {
                    target[AES256_KEY_SCHEDULE_BITS_OFFSET + key_byte_index * 8 + bit] =
                        Val::from_u32(u32::from((key_byte >> bit) & 1));
                }
            }
            for byte in 0..16 {
                let input = aes_round_states[round][byte];
                let output = aes_round_states[round + 1][byte];
                for bit in 0..8 {
                    target[AES256_BLOCK_STATE_INPUT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(u32::from((input >> bit) & 1));
                    target[AES256_BLOCK_STATE_OUTPUT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(u32::from((output >> bit) & 1));
                }
                if round > 0 {
                    populate_sbox_air_witness(
                        target,
                        input,
                        AES256_BLOCK_STATE_INPUT_BITS_OFFSET + byte * 8,
                        AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET + byte * 8,
                        AES256_BLOCK_SBOX_WITNESS_OFFSET + byte * AES_SBOX_WITNESS_COLUMNS,
                    );
                }
                let plaintext_index = block_index * 16 + byte;
                let plaintext_byte = output_plaintext.get(plaintext_index).copied().unwrap_or(0);
                for bit in 0..8 {
                    target[AES256_BLOCK_CIPHERTEXT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(if plaintext_index < output_plaintext.len() {
                            u32::from((statement.output.ciphertext[plaintext_index] >> bit) & 1)
                        } else {
                            0
                        });
                    target[AES256_BLOCK_PLAINTEXT_BITS_OFFSET + byte * 8 + bit] =
                        Val::from_u32(u32::from((plaintext_byte >> bit) & 1));
                }
            }
            if (1..14).contains(&round) {
                let substituted: [u8; 16] =
                    core::array::from_fn(|byte| aes_sbox_air::sbox(aes_round_states[round][byte]));
                let shifted = aes_sbox_air::shift_rows(&substituted);
                let mixed = aes_sbox_air::mix_columns(&shifted);
                for byte in 0..16 {
                    let doubled = aes_sbox_air::mul2(shifted[byte]);
                    let tripled = doubled ^ shifted[byte];
                    for bit in 0..8 {
                        target[AES256_BLOCK_XTIME_BITS_OFFSET + byte * 8 + bit] =
                            Val::from_u32(u32::from((doubled >> bit) & 1));
                        target[AES256_BLOCK_MUL3_BITS_OFFSET + byte * 8 + bit] =
                            Val::from_u32(u32::from((tripled >> bit) & 1));
                        target[AES256_BLOCK_MIXED_BITS_OFFSET + byte * 8 + bit] =
                            Val::from_u32(u32::from((mixed[byte] >> bit) & 1));
                    }
                }
            }
        }
    }
    for row_index in output_kdf_end..RDXL_TRACE_ROWS {
        let target_start = row_index * RDXL_TRACE_WIDTH;
        let target = &mut trace.values[target_start..target_start + RDXL_TRACE_WIDTH];
        for (byte_index, byte) in output_kdf_rate.iter().copied().enumerate() {
            for bit in 0..8 {
                target[SOURCE_BUFFER_BITS_OFFSET + byte_index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
    }
    for row_index in 0..RDXL_TRACE_ROWS {
        let target_start = row_index * RDXL_TRACE_WIDTH;
        let target = &mut trace.values[target_start..target_start + RDXL_TRACE_WIDTH];
        for (index, byte) in source_field_bytes.iter().copied().enumerate() {
            target[INPUT_KDF_SOURCE_BYTES_OFFSET + index] = Val::from_u32(u32::from(byte));
        }
        let active_kdf_key = if row_index < output_kdf_start {
            &kdf_key[..32]
        } else {
            &output_aes_key[..]
        };
        for (index, byte) in active_kdf_key.iter().copied().enumerate() {
            target[INPUT_KDF_KEY_BYTES_OFFSET + index] = Val::from_u32(u32::from(byte));
        }
        for (index, byte) in output_shared_secret.iter().copied().enumerate() {
            target[OUTPUT_KDF_SECRET_BYTES_OFFSET + index] = Val::from_u32(u32::from(byte));
            for bit in 0..8 {
                target[OUTPUT_KDF_SECRET_BITS_OFFSET + index * 8 + bit] =
                    Val::from_u32(u32::from((byte >> bit) & 1));
            }
        }
        for (index, byte) in source_aead_bytes.iter().copied().enumerate() {
            target[INPUT_AEAD_SOURCE_BYTES_OFFSET + index] = Val::from_u32(u32::from(byte));
        }
        for (index, byte) in input_note_rho_randomness.iter().copied().enumerate() {
            target[INPUT_NOTE_RHO_RANDOMNESS_BYTES_OFFSET + index] = Val::from_u32(u32::from(byte));
        }
    }
    trace
}
fn public_values(root: &ValArray) -> Vec<Val> {
    root.iter()
        .map(|byte| Val::from_u32(u32::from(*byte)))
        .collect()
}
fn statement_public_values(root: &ValArray, statement_bytes: &[u8]) -> Vec<Val> {
    let mut values = public_values(root);
    values.extend(
        statement_bytes
            .iter()
            .map(|byte| Val::from_u32(u32::from(*byte))),
    );
    values
}
fn rdxl_statement_public_values(
    statement_bytes: &[u8],
    statement: &TransactionStatementV1,
) -> Result<Vec<Val>, Depth64PathProofError> {
    if statement.output.ciphertext.len() != OUTPUT_CIPHERTEXT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "RDXL output ciphertext must be exactly 156 bytes",
        ));
    }
    let canonical_statement_bytes = statement
        .serialize()
        .map_err(|_| Depth64PathProofError::Malformed("invalid parsed transaction statement"))?;
    if canonical_statement_bytes.as_slice() != statement_bytes {
        return Err(Depth64PathProofError::Malformed(
            "parsed statement does not match canonical statement bytes",
        ));
    }
    let frame = output_leaf_frame(
        statement.output.commitment,
        statement.output.kem_ciphertext,
        statement.output.nonce,
        &statement.output.ciphertext,
    );
    let blocks = output_leaf_absorb_blocks_from_frame(&frame);
    if !(10..=14).contains(&blocks.len()) || blocks.len() > OUTPUT_LEAF_BLOCK_SLOTS {
        return Err(Depth64PathProofError::Malformed(
            "RDXL output leaf block count out of bounds",
        ));
    }
    if blocks.len() != (frame.len() + 1).div_ceil(SHAKE_RATE_BYTES) {
        return Err(Depth64PathProofError::Malformed(
            "RDXL output leaf frame/block count mismatch",
        ));
    }
    // Keep the Merkle root bound to the parsed canonical statement as the sole
    // source of truth; callers cannot accidentally pair unrelated root bytes.
    let mut values = statement_public_values(&statement.root_out, statement_bytes);
    values.push(Val::from_u32(blocks.len() as u32));
    let last_index = blocks.len() - 1;
    for bit in 0..4 {
        values.push(Val::from_u32(((last_index >> bit) & 1) as u32));
    }
    for slot in 0..OUTPUT_LEAF_BLOCK_SLOTS {
        if let Some(block) = blocks.get(slot) {
            values.extend(block.iter().map(|byte| Val::from_u32(u32::from(*byte))));
        } else {
            values.extend((0..SHAKE_RATE_BYTES).map(|_| Val::ZERO));
        }
    }
    values.extend(
        statement
            .output
            .leaf
            .iter()
            .map(|byte| Val::from_u32(u32::from(*byte))),
    );
    Ok(values)
}
fn encode(root: &ValArray, proof: &Proof<Stark>) -> Result<Vec<u8>, Depth64PathProofError> {
    let payload_len = serialized_proof_size(proof)?;
    let total_len = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(Depth64PathProofError::Malformed("envelope length overflow"))?;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    let out = postcard::to_extend(proof, out)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    if out.len() != total_len {
        return Err(Depth64PathProofError::Malformed(
            "proof serialization size mismatch",
        ));
    }
    Ok(out)
}
fn encode_statement_bound(
    statement_bytes: &[u8],
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, Depth64PathProofError> {
    encode_statement_bound_with_magic(STATEMENT_MAGIC, statement_bytes, proof)
}
fn encode_source_statement_bound(
    statement_bytes: &[u8],
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, Depth64PathProofError> {
    encode_statement_bound_with_magic(SOURCE_STATEMENT_MAGIC, statement_bytes, proof)
}
fn encode_statement_bound_with_magic(
    magic: &[u8; 8],
    statement_bytes: &[u8],
    proof: &Proof<Stark>,
) -> Result<Vec<u8>, Depth64PathProofError> {
    if statement_bytes.is_empty() || statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    let payload_len = serialized_proof_size(proof)?;
    let payload_offset = STATEMENT_HEADER_BYTES
        .checked_add(statement_bytes.len())
        .ok_or(Depth64PathProofError::Malformed("envelope length overflow"))?;
    let total_len = payload_offset
        .checked_add(payload_len)
        .ok_or(Depth64PathProofError::Malformed("envelope length overflow"))?;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(magic);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(statement_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    out.extend_from_slice(statement_bytes);
    let out = postcard::to_extend(proof, out)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    if out.len() != total_len {
        return Err(Depth64PathProofError::Malformed(
            "proof serialization size mismatch",
        ));
    }
    Ok(out)
}
fn serialized_proof_size(proof: &Proof<Stark>) -> Result<usize, Depth64PathProofError> {
    let payload_len = postcard::experimental::serialized_size(proof)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    if payload_len == 0 || payload_len > MAX_PROOF_BYTES {
        return Err(Depth64PathProofError::Malformed("proof size out of bounds"));
    }
    Ok(payload_len)
}
fn decode_proof(payload: &[u8]) -> Result<Proof<Stark>, Depth64PathProofError> {
    if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
        return Err(Depth64PathProofError::Malformed("proof size out of bounds"));
    }
    let proof: Proof<Stark> = std::panic::catch_unwind(AssertUnwindSafe(|| {
        crate::bounded_postcard::from_proof_bytes(payload)
    }))
    .map_err(|_| Depth64PathProofError::Malformed("proof deserializer panicked"))?
    .map_err(|_| Depth64PathProofError::Malformed("invalid proof serialization"))?;
    let canonical = std::panic::catch_unwind(AssertUnwindSafe(|| {
        postcard::to_extend(&proof, CanonicalBytes::new(payload))
    }))
    .map_err(|_| Depth64PathProofError::Malformed("proof serializer panicked"))?
    .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(Depth64PathProofError::Malformed(
            "non-canonical proof serialization",
        ));
    }
    Ok(proof)
}
fn decode_statement_bound_with_magic(
    bytes: &[u8],
    expected_magic: &[u8; 8],
) -> Result<(Vec<u8>, Proof<Stark>), Depth64PathProofError> {
    let (statement_bytes, proof_payload) = split_statement_bound_with_magic(bytes, expected_magic)?;
    let proof = decode_proof(proof_payload)?;
    Ok((statement_bytes.to_vec(), proof))
}
// Validate envelope framing and return borrowed slices so callers can match the
// canonical statement before deserializing the potentially large proof payload.
fn split_statement_bound_with_magic<'a>(
    bytes: &'a [u8],
    expected_magic: &[u8; 8],
) -> Result<(&'a [u8], &'a [u8]), Depth64PathProofError> {
    if bytes.len() < STATEMENT_HEADER_BYTES {
        return Err(Depth64PathProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > MAX_STATEMENT_BOUND_ENVELOPE_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "envelope exceeds size limit",
        ));
    }
    if &bytes[..8] != expected_magic {
        return Err(Depth64PathProofError::Malformed("wrong magic"));
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION {
        return Err(Depth64PathProofError::Malformed("unsupported version"));
    }
    let statement_len = u32::from_le_bytes(bytes[10..14].try_into().unwrap()) as usize;
    let proof_len = u32::from_le_bytes(bytes[14..18].try_into().unwrap()) as usize;
    if statement_len == 0 || statement_len > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    if proof_len == 0 || proof_len > MAX_PROOF_BYTES {
        return Err(Depth64PathProofError::Malformed("proof size out of bounds"));
    }
    let expected_len = STATEMENT_HEADER_BYTES
        .checked_add(statement_len)
        .and_then(|length| length.checked_add(proof_len))
        .ok_or(Depth64PathProofError::Malformed("envelope length overflow"))?;
    if bytes.len() != expected_len {
        return Err(Depth64PathProofError::Malformed("envelope length mismatch"));
    }
    let statement_end = STATEMENT_HEADER_BYTES + statement_len;
    Ok((
        &bytes[STATEMENT_HEADER_BYTES..statement_end],
        &bytes[statement_end..],
    ))
}
fn decode(
    bytes: &[u8],
    expected_root: &ValArray,
) -> Result<(ValArray, Proof<Stark>), Depth64PathProofError> {
    if bytes.len() < HEADER_BYTES {
        return Err(Depth64PathProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "envelope exceeds size limit",
        ));
    }
    if &bytes[..8] != MAGIC {
        return Err(Depth64PathProofError::Malformed("wrong magic"));
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION {
        return Err(Depth64PathProofError::Malformed("unsupported version"));
    }
    let root: ValArray = bytes[10..74].try_into().unwrap();
    let len = u32::from_le_bytes(bytes[74..78].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_PROOF_BYTES || bytes.len() != HEADER_BYTES + len {
        return Err(Depth64PathProofError::Malformed("proof length mismatch"));
    }
    if &root != expected_root {
        return Err(Depth64PathProofError::RootMismatch);
    }
    let payload = &bytes[HEADER_BYTES..];
    let proof = decode_proof(payload)?;
    Ok((root, proof))
}
/// Prove a private 64-level Candidate-A path against an explicit public root.
/// The 64-bit path index and every sibling remain in the private witness.
pub fn prove_depth64_path(
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    expected_root: &ValArray,
) -> Result<Vec<u8>, Depth64PathProofError> {
    let (trace, computed_root) = build_trace(leaf, siblings, path_index);
    if &computed_root != expected_root {
        return Err(Depth64PathProofError::RootMismatch);
    }
    let config = amount_opening::make_config();
    let air = Depth64PathAir {
        public_value_count: DIGEST_BYTES,
        source_bound: false,
        note_bound: false,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let proof = prove(&config, &air, trace, &public_values(expected_root))
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    encode(expected_root, &proof)
}
/// Verify a depth-64 path proof against a caller-supplied public root.
pub fn verify_depth64_path(
    bytes: &[u8],
    expected_root: &ValArray,
) -> Result<Depth64PathStatementV1, Depth64PathProofError> {
    let (root, proof) = decode(bytes, expected_root)?;
    let config = amount_opening::make_config();
    let air = Depth64PathAir {
        public_value_count: DIGEST_BYTES,
        source_bound: false,
        note_bound: false,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify(&config, &air, &proof, &public_values(expected_root))
    }))
    .map_err(|_| Depth64PathProofError::Malformed("proof verifier panicked"))?
    .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    Ok(Depth64PathStatementV1 { root })
}
/// Prove that a private depth-64 path hashes to the root in a canonical
/// one-input/one-output transaction statement. The exact statement bytes are
/// included as public values and transcript inputs; this does not bind the path
/// leaf to the transaction nullifier or prove the other transaction relations.
pub fn prove_statement_bound_depth64_path(
    statement_bytes: &[u8],
    leaf: &ValArray,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
) -> Result<Vec<u8>, Depth64PathProofError> {
    if statement_bytes.is_empty() || statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid canonical transaction statement"))?;
    let (trace, computed_root) = build_trace(leaf, siblings, path_index);
    if computed_root != statement.root_out {
        return Err(Depth64PathProofError::RootMismatch);
    }
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: false,
        note_bound: false,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    let proof = prove(&config, &air, trace, &values)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    encode_statement_bound(statement_bytes, &proof)
}
/// Verify a depth-64 path subrelation against the caller's exact canonical
/// transaction statement bytes.
pub fn verify_statement_bound_depth64_path(
    bytes: &[u8],
    expected_statement_bytes: &[u8],
) -> Result<TransactionStatementV1, Depth64PathProofError> {
    if expected_statement_bytes.is_empty() || expected_statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "expected transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(expected_statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid expected transaction statement"))?;
    let (statement_bytes, proof_payload) =
        split_statement_bound_with_magic(bytes, STATEMENT_MAGIC)?;
    if statement_bytes != expected_statement_bytes {
        return Err(Depth64PathProofError::StatementMismatch);
    }
    let proof = decode_proof(proof_payload)?;
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: false,
        note_bound: false,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| verify(&config, &air, &proof, &values)))
        .map_err(|_| Depth64PathProofError::Malformed("proof verifier panicked"))?
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    Ok(statement)
}
fn checked_source_leaf_blocks(
    source: &OutputRecordV1,
) -> Result<Vec<[u8; SHAKE_RATE_BYTES]>, Depth64PathProofError> {
    if source.ciphertext.len() != SOURCE_CIPHERTEXT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "RDXS64P1 requires a 156-byte source ciphertext",
        ));
    }
    let frame = output_leaf_frame(
        source.commitment,
        source.kem_ciphertext,
        source.nonce,
        &source.ciphertext,
    );
    let blocks = output_leaf_absorb_blocks_from_frame(&frame);
    if frame.len() != SOURCE_FRAME_BYTES || blocks.len() != SOURCE_BLOCKS {
        return Err(Depth64PathProofError::Malformed(
            "source leaf frame has an unexpected fixed-profile length",
        ));
    }
    for (block_index, block) in blocks.iter().enumerate() {
        for (within, byte) in block.iter().copied().enumerate() {
            let offset = block_index * SHAKE_RATE_BYTES + within;
            let expected = frame.get(offset).copied().unwrap_or_else(|| {
                let mut padding = 0;
                if offset == frame.len() {
                    padding |= 0x1f;
                }
                if within == SHAKE_RATE_BYTES - 1 {
                    padding |= 0x80;
                }
                padding
            });
            if byte != expected {
                return Err(Depth64PathProofError::Malformed(
                    "source leaf padding differs from fixed frame",
                ));
            }
        }
    }
    let computed_leaf = output_leaf_from_frame(&frame);
    if computed_leaf != source.leaf {
        return Err(Depth64PathProofError::Malformed(
            "source output leaf does not match its fields",
        ));
    }
    Ok(blocks)
}
/// Prove a private source OutputRecordV1's exact `radix/leaf/v1` hash is the
/// private leaf of a depth-64 path to the statement root. This v1 prototype is
/// deliberately limited to 156-byte ciphertexts. The source record is a
/// separate private witness, not `statement.output`; its digest is never public.
/// This still does not link the path to the statement nullifier or prove a full
/// transaction relation.
pub fn prove_source_bound_depth64_path(
    statement_bytes: &[u8],
    source: &OutputRecordV1,
    siblings: &[ValArray; DEPTH],
    path_index: u64,
) -> Result<Vec<u8>, Depth64PathProofError> {
    if statement_bytes.is_empty() || statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid canonical transaction statement"))?;
    let blocks = checked_source_leaf_blocks(source)?;
    let (trace, computed_root) =
        build_source_bound_trace(&blocks, &source.leaf, siblings, path_index);
    if computed_root != statement.root_out {
        return Err(Depth64PathProofError::RootMismatch);
    }
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: false,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    let proof = prove(&config, &air, trace, &values)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    encode_source_statement_bound(statement_bytes, &proof)
}
/// Verify the source-linked fixed-156-byte `RDXS64P1` profile against exact
/// caller-supplied canonical statement bytes.
pub fn verify_source_bound_depth64_path(
    bytes: &[u8],
    expected_statement_bytes: &[u8],
) -> Result<TransactionStatementV1, Depth64PathProofError> {
    if expected_statement_bytes.is_empty() || expected_statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "expected transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(expected_statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid expected transaction statement"))?;
    let (statement_bytes, proof_payload) =
        split_statement_bound_with_magic(bytes, SOURCE_STATEMENT_MAGIC)?;
    if statement_bytes != expected_statement_bytes {
        return Err(Depth64PathProofError::StatementMismatch);
    }
    let proof = decode_proof(proof_payload)?;
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: false,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| verify(&config, &air, &proof, &values)))
        .map_err(|_| Depth64PathProofError::Malformed("proof verifier panicked"))?
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    Ok(statement)
}
/// Prove one experimental `RDXI64P1` relation: a private note opening hashes to
/// the commitment in a private fixed-156-byte source record, whose source leaf
/// opens through a private depth-64 path to the exact public statement root.
/// This remains a partial, non-production transaction relation.
pub fn prove_source_note_depth64_path(
    statement_bytes: &[u8],
    source: &OutputRecordV1,
    owner: &[u8; 64],
    value: u64,
    rho: &[u8; 64],
    randomness: &[u8; 64],
    siblings: &[ValArray; DEPTH],
    path_index: u64,
) -> Result<Vec<u8>, Depth64PathProofError> {
    if statement_bytes.is_empty() || statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid canonical transaction statement"))?;
    let blocks = checked_source_leaf_blocks(source)?;
    if value == 0 {
        return Err(Depth64PathProofError::Malformed(
            "note value must be nonzero",
        ));
    }
    let (note_trace, note_digest) =
        crate::note_commitment_opening::build_trace(owner, value, rho, randomness);
    if note_digest != source.commitment {
        return Err(Depth64PathProofError::NoteCommitmentMismatch);
    }
    let (trace, computed_root) = build_source_note_trace(
        &blocks,
        &source.commitment,
        &source.leaf,
        siblings,
        path_index,
        &note_trace,
    );
    drop(note_trace);
    if computed_root != statement.root_out {
        return Err(Depth64PathProofError::RootMismatch);
    }
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    let proof = prove(&config, &air, trace, &values)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    encode_statement_bound_with_magic(SOURCE_NOTE_MAGIC, statement_bytes, &proof)
}
/// Verify `RDXI64P1` against exact caller-supplied canonical statement bytes.
pub fn verify_source_note_depth64_path(
    bytes: &[u8],
    expected_statement_bytes: &[u8],
) -> Result<TransactionStatementV1, Depth64PathProofError> {
    if expected_statement_bytes.is_empty() || expected_statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "expected transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(expected_statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid expected transaction statement"))?;
    let (statement_bytes, proof_payload) =
        split_statement_bound_with_magic(bytes, SOURCE_NOTE_MAGIC)?;
    if statement_bytes != expected_statement_bytes {
        return Err(Depth64PathProofError::StatementMismatch);
    }
    let proof = decode_proof(proof_payload)?;
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: false,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| verify(&config, &air, &proof, &values)))
        .map_err(|_| Depth64PathProofError::Malformed("proof verifier panicked"))?
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    Ok(statement)
}
/// Prove the experimental `RDXJ64P1` composition: `spend_secret` derives `pk_s`,
/// `pk_s` and a private KEM shared-secret input derive the note owner, and that
/// owner is the one consumed by the RDXI note/source/path relation. This does
/// not prove ML-KEM decapsulation, nullifier correctness, or a complete transaction.
pub fn prove_source_key_note_depth64_path(
    statement_bytes: &[u8],
    source: &OutputRecordV1,
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    value: u64,
    rho: &[u8; 64],
    randomness: &[u8; 64],
    siblings: &[ValArray; DEPTH],
    path_index: u64,
) -> Result<Vec<u8>, Depth64PathProofError> {
    if statement_bytes.is_empty() || statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid canonical transaction statement"))?;
    let blocks = checked_source_leaf_blocks(source)?;
    if value == 0 {
        return Err(Depth64PathProofError::Malformed(
            "note value must be nonzero",
        ));
    }
    let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[spend_secret]);
    let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
    let owner_state = candidate_hash_frame_state(
        b"radix/one-time/v1",
        &[&spend_public_key, kem_shared_secret],
    );
    let owner = state_digest(&state_after_one(&owner_state));
    let (note_trace, note_digest) =
        crate::note_commitment_opening::build_trace(&owner, value, rho, randomness);
    if note_digest != source.commitment {
        return Err(Depth64PathProofError::NoteCommitmentMismatch);
    }
    let (trace, computed_root, trace_owner) = build_source_key_note_trace(
        &blocks,
        &source.commitment,
        &source.leaf,
        siblings,
        path_index,
        &note_trace,
        spend_secret,
        kem_shared_secret,
    );
    drop(note_trace);
    if trace_owner != owner {
        return Err(Depth64PathProofError::Malformed(
            "trace-derived owner mismatch",
        ));
    }
    if computed_root != statement.root_out {
        return Err(Depth64PathProofError::RootMismatch);
    }
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: true,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    let proof = prove(&config, &air, trace, &values)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    encode_statement_bound_with_magic(SOURCE_KEY_NOTE_MAGIC, statement_bytes, &proof)
}
/// Verify `RDXJ64P1` against the exact canonical statement bytes supplied by the caller.
pub fn verify_source_key_note_depth64_path(
    bytes: &[u8],
    expected_statement_bytes: &[u8],
) -> Result<TransactionStatementV1, Depth64PathProofError> {
    if expected_statement_bytes.is_empty() || expected_statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "expected transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(expected_statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid expected transaction statement"))?;
    let (statement_bytes, proof_payload) =
        split_statement_bound_with_magic(bytes, SOURCE_KEY_NOTE_MAGIC)?;
    if statement_bytes != expected_statement_bytes {
        return Err(Depth64PathProofError::StatementMismatch);
    }
    let proof = decode_proof(proof_payload)?;
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: true,
        nullifier_bound: false,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| verify(&config, &air, &proof, &values)))
        .map_err(|_| Depth64PathProofError::Malformed("proof verifier panicked"))?
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    Ok(statement)
}
/// Prove the experimental `RDXK64P1` common-witness extension, which adds the
/// public nullifier hash of the same spend key, KEM shared-secret input, and rho
/// already consumed by the RDXJ owner/note relation. This does not prove KEM
/// decapsulation, output encryption, value balance, or complete transaction validity.
pub fn prove_source_key_note_nullifier_depth64_path(
    statement_bytes: &[u8],
    source: &OutputRecordV1,
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    value: u64,
    rho: &[u8; 64],
    randomness: &[u8; 64],
    siblings: &[ValArray; DEPTH],
    path_index: u64,
) -> Result<Vec<u8>, Depth64PathProofError> {
    if statement_bytes.is_empty() || statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid canonical transaction statement"))?;
    let blocks = checked_source_leaf_blocks(source)?;
    if value == 0 {
        return Err(Depth64PathProofError::Malformed(
            "note value must be nonzero",
        ));
    }
    let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[spend_secret]);
    let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
    let owner_state = candidate_hash_frame_state(
        b"radix/one-time/v1",
        &[&spend_public_key, kem_shared_secret],
    );
    let owner = state_digest(&state_after_one(&owner_state));
    let (note_trace, note_digest) =
        crate::note_commitment_opening::build_trace(&owner, value, rho, randomness);
    if note_digest != source.commitment {
        return Err(Depth64PathProofError::NoteCommitmentMismatch);
    }
    let (trace, computed_root, trace_owner, computed_nullifier) =
        build_source_key_note_nullifier_trace(
            &blocks,
            &source.commitment,
            &source.leaf,
            siblings,
            path_index,
            &note_trace,
            spend_secret,
            kem_shared_secret,
            rho,
        );
    drop(note_trace);
    if trace_owner != owner {
        return Err(Depth64PathProofError::Malformed(
            "trace-derived owner mismatch",
        ));
    }
    if computed_root != statement.root_out {
        return Err(Depth64PathProofError::RootMismatch);
    }
    if computed_nullifier != statement.nullifier {
        return Err(Depth64PathProofError::NullifierMismatch);
    }
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: true,
        nullifier_bound: true,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    let proof = prove(&config, &air, trace, &values)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    encode_statement_bound_with_magic(SOURCE_KEY_NOTE_NULLIFIER_MAGIC, statement_bytes, &proof)
}
/// Verify `RDXK64P1` against the exact canonical statement bytes supplied by the caller.
pub fn verify_source_key_note_nullifier_depth64_path(
    bytes: &[u8],
    expected_statement_bytes: &[u8],
) -> Result<TransactionStatementV1, Depth64PathProofError> {
    if expected_statement_bytes.is_empty() || expected_statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "expected transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(expected_statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid expected transaction statement"))?;
    let (statement_bytes, proof_payload) =
        split_statement_bound_with_magic(bytes, SOURCE_KEY_NOTE_NULLIFIER_MAGIC)?;
    if statement_bytes != expected_statement_bytes {
        return Err(Depth64PathProofError::StatementMismatch);
    }
    let proof = decode_proof(proof_payload)?;
    let values = statement_public_values(&statement.root_out, statement_bytes);
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: true,
        nullifier_bound: true,
        output_note_balance_bound: false,
    };
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| verify(&config, &air, &proof, &values)))
        .map_err(|_| Depth64PathProofError::Malformed("proof verifier panicked"))?
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    Ok(statement)
}
fn log_rdxl_profile_phase(enabled: bool, phase: &str, started: Instant) {
    if enabled {
        eprintln!(
            "RDXL_PROFILE phase={phase} elapsed_ms={:.3}",
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
}

/// Prove the experimental `RDXL64P1` composition: it extends RDXK with a
/// private opening of the public output commitment and the exact relation
/// `value_in = value_out + fee` without u64 overflow. It also constrains separate
/// input/output KDF witnesses and nine AES-256-CTR blocks on each side, binding
/// the fixed empty-memo plaintexts to their ciphertext prefixes. Set
/// `RDXL_PROFILE_TIMINGS=1` to emit phase timings and raw trace bytes; no witness
/// values are logged. This does not prove ML-KEM operations, recipient ownership,
/// GCM/GHASH tag authentication, or complete transaction validity. For backward
/// compatibility this entry point reuses `kem_shared_secret` as the output-KDF
/// witness; use the `_with_output_secret` variant to provide an independent one.
pub fn prove_source_key_note_nullifier_output_balance_depth64_path(
    statement_bytes: &[u8],
    source: &OutputRecordV1,
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    input_value: u64,
    input_rho: &[u8; 64],
    input_randomness: &[u8; 64],
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    output_note: &OutputNoteOpeningV1,
) -> Result<Vec<u8>, Depth64PathProofError> {
    prove_source_key_note_nullifier_output_balance_depth64_path_with_output_secret(
        statement_bytes,
        source,
        spend_secret,
        kem_shared_secret,
        kem_shared_secret,
        input_value,
        input_rho,
        input_randomness,
        siblings,
        path_index,
        output_note,
    )
}

/// Prove RDXL while supplying an independent output KEM shared-secret witness.
/// The proof binds this witness to the output KDF/AES-CTR relation, but does not
/// prove ML-KEM encapsulation/decapsulation or authenticate the GCM tag.
pub fn prove_source_key_note_nullifier_output_balance_depth64_path_with_output_secret(
    statement_bytes: &[u8],
    source: &OutputRecordV1,
    spend_secret: &[u8; 64],
    kem_shared_secret: &[u8; 32],
    output_kem_shared_secret: &[u8; 32],
    input_value: u64,
    input_rho: &[u8; 64],
    input_randomness: &[u8; 64],
    siblings: &[ValArray; DEPTH],
    path_index: u64,
    output_note: &OutputNoteOpeningV1,
) -> Result<Vec<u8>, Depth64PathProofError> {
    let profile_phases = std::env::var_os("RDXL_PROFILE_TIMINGS").is_some();
    let total_started = Instant::now();
    let mut phase_started = Instant::now();
    if statement_bytes.is_empty() || statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid canonical transaction statement"))?;
    if statement.output.ciphertext.len() != OUTPUT_CIPHERTEXT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "RDXL output ciphertext must be exactly 156 bytes",
        ));
    }
    let blocks = checked_source_leaf_blocks(source)?;
    if input_value == 0 || output_note.value == 0 {
        return Err(Depth64PathProofError::Malformed(
            "input and output note values must be nonzero",
        ));
    }
    if output_note.value.checked_add(statement.fee) != Some(input_value) {
        return Err(Depth64PathProofError::UnbalancedValues);
    }
    // A valid RDXL witness currently has a conservative raw randomized-matrix /
    // LDE overlap estimate above both the 4-GiB desktop and 1-GiB mobile caps.
    // Stop before constructing component traces until a target-specific budget
    // and measured peak-memory evidence justify changing this gate.
    ensure_rdxl_process_budget()?;
    log_rdxl_profile_phase(profile_phases, "preflight", phase_started);
    phase_started = Instant::now();
    let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[spend_secret]);
    let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
    let owner_state = candidate_hash_frame_state(
        b"radix/one-time/v1",
        &[&spend_public_key, kem_shared_secret],
    );
    let input_owner = state_digest(&state_after_one(&owner_state));
    let (input_note_trace, input_note_digest) = crate::note_commitment_opening::build_trace(
        &input_owner,
        input_value,
        input_rho,
        input_randomness,
    );
    if input_note_digest != source.commitment {
        return Err(Depth64PathProofError::NoteCommitmentMismatch);
    }
    log_rdxl_profile_phase(profile_phases, "input_note_witness", phase_started);
    phase_started = Instant::now();
    let (output_note_trace, output_note_digest) = crate::note_commitment_opening::build_trace(
        &output_note.owner,
        output_note.value,
        &output_note.rho,
        &output_note.randomness,
    );
    if output_note_digest != statement.output.commitment {
        return Err(Depth64PathProofError::OutputNoteCommitmentMismatch);
    }
    log_rdxl_profile_phase(profile_phases, "output_note_witness", phase_started);
    phase_started = Instant::now();
    let (base_trace, computed_root, trace_owner, computed_nullifier) =
        build_source_key_note_nullifier_trace_with_width(
            &blocks,
            &source.commitment,
            &source.leaf,
            siblings,
            path_index,
            &input_note_trace,
            spend_secret,
            kem_shared_secret,
            input_rho,
            RDXL_TRACE_WIDTH,
            RDXL_TRACE_ROWS,
        );
    drop(input_note_trace);
    if trace_owner != input_owner {
        return Err(Depth64PathProofError::Malformed(
            "trace-derived input owner mismatch",
        ));
    }
    if computed_root != statement.root_out {
        return Err(Depth64PathProofError::RootMismatch);
    }
    if computed_nullifier != statement.nullifier {
        return Err(Depth64PathProofError::NullifierMismatch);
    }
    log_rdxl_profile_phase(profile_phases, "base_trace_and_path", phase_started);
    phase_started = Instant::now();
    let trace = build_source_key_note_nullifier_output_trace_with_secret(
        base_trace,
        input_value,
        output_note,
        statement.fee,
        &output_note_trace,
        &statement,
        output_kem_shared_secret,
    );
    drop(output_note_trace);
    log_rdxl_profile_phase(profile_phases, "output_trace_composition", phase_started);
    if profile_phases {
        eprintln!(
            "RDXL_PROFILE raw_trace_bytes={}",
            trace.values.len() * std::mem::size_of::<Val>()
        );
    }
    phase_started = Instant::now();
    let values = rdxl_statement_public_values(statement_bytes, &statement)?;
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: true,
        nullifier_bound: true,
        output_note_balance_bound: true,
    };
    let config = amount_opening::make_config();
    let proof = prove(&config, &air, trace, &values)
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    log_rdxl_profile_phase(profile_phases, "stark_prove", phase_started);
    phase_started = Instant::now();
    let envelope = encode_statement_bound_with_magic(
        SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC,
        statement_bytes,
        &proof,
    )?;
    log_rdxl_profile_phase(profile_phases, "envelope_encode", phase_started);
    log_rdxl_profile_phase(profile_phases, "total", total_started);
    Ok(envelope)
}
/// Verify `RDXL64P1` against exact caller-supplied canonical statement bytes.
pub fn verify_source_key_note_nullifier_output_balance_depth64_path(
    bytes: &[u8],
    expected_statement_bytes: &[u8],
) -> Result<TransactionStatementV1, Depth64PathProofError> {
    if expected_statement_bytes.is_empty() || expected_statement_bytes.len() > MAX_STATEMENT_BYTES {
        return Err(Depth64PathProofError::Malformed(
            "expected transaction statement size out of bounds",
        ));
    }
    let statement = TransactionStatementV1::parse(expected_statement_bytes)
        .map_err(|_| Depth64PathProofError::Malformed("invalid expected transaction statement"))?;
    let (statement_bytes, proof_payload) =
        split_statement_bound_with_magic(bytes, SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC)?;
    if statement_bytes != expected_statement_bytes {
        return Err(Depth64PathProofError::StatementMismatch);
    }
    let proof = decode_proof(proof_payload)?;
    let values = rdxl_statement_public_values(statement_bytes, &statement)?;
    let air = Depth64PathAir {
        public_value_count: values.len(),
        source_bound: true,
        note_bound: true,
        spend_owner_bound: true,
        nullifier_bound: true,
        output_note_balance_bound: true,
    };
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| verify(&config, &air, &proof, &values)))
        .map_err(|_| Depth64PathProofError::Malformed("proof verifier panicked"))?
        .map_err(|e| Depth64PathProofError::Backend(e.to_string()))?;
    Ok(statement)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_statement::{OutputRecordV1, output_leaf};
    use std::time::Instant;

    #[test]
    fn aes_key_schedule_bank_is_contiguous_and_disjoint() {
        // The expanded schedule is one bank of AES256_EXPANDED_KEY_BITS bits,
        // followed immediately by the key-schedule stage selector and index
        // bits. A future overlay optimisation must preserve this invariant or
        // replace it with an accessor plus a column-disjointness test.
        assert_eq!(
            AES256_KEY_SCHEDULE_BITS_OFFSET,
            AES256_KEY_SCHEDULE_TAIL_OFFSET
        );
        assert_eq!(
            AES256_KEY_SCHEDULE_ACTIVE_OFFSET,
            AES256_KEY_SCHEDULE_BITS_OFFSET + AES256_EXPANDED_KEY_BITS
        );
        assert_eq!(
            AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET,
            AES256_KEY_SCHEDULE_ACTIVE_OFFSET + 1
        );
        assert!(AES256_KEY_SCHEDULE_ACTIVE_OFFSET < RDXL_TRACE_WIDTH);
    }

    #[test]
    fn rdxl_resource_report_matches_pinned_workspace_dimensions() {
        let report = rdxl_resource_report().expect("fixed dimensions fit usize");
        assert_eq!(
            AES256_BLOCK_ACTIVE_OFFSET,
            AES256_KEY_SCHEDULE_INDEX_BITS_OFFSET + 4
        );
        assert_eq!(
            AES256_SBOX_INPUT_BITS_OFFSET,
            AES256_BLOCK_STATE_INPUT_BITS_OFFSET
        );
        assert_eq!(
            AES256_SBOX_OUTPUT_BITS_OFFSET,
            AES256_BLOCK_SBOX_OUTPUT_BITS_OFFSET
        );
        assert_eq!(AES256_SBOX_WITNESS_OFFSET, AES256_BLOCK_SBOX_WITNESS_OFFSET);
        assert_eq!((report.trace_rows, report.trace_width), (8_192, 15_629));
        assert_eq!(report.trace_payload_bytes, 512_131_072);
        assert_eq!(
            (report.randomized_rows, report.randomized_width),
            (16_384, 15_633)
        );
        assert_eq!(report.randomized_payload_bytes, 1_024_524_288);
        assert_eq!((report.lde_rows, report.lde_width), (65_536, 15_633));
        assert_eq!(report.lde_payload_bytes, 4_098_097_152);
        assert_eq!(report.randomized_plus_lde_payload_bytes, 5_122_621_440);
        assert_eq!(report.desktop_process_budget_bytes, 4_294_967_296);
        assert_eq!(report.mobile_process_budget_bytes, 1_073_741_824);
    }

    #[test]
    fn rdxl_proving_preflight_rejects_current_estimate() {
        let report = rdxl_resource_report().expect("fixed dimensions fit usize");
        let error =
            ensure_rdxl_process_budget().expect_err("the current RDXL profile must fail closed");
        assert!(report.randomized_plus_lde_payload_bytes > 1_073_741_824);
        assert!(report.randomized_plus_lde_payload_bytes > 4_294_967_296);
        assert_eq!(
            error,
            Depth64PathProofError::ResourceBudgetExceeded {
                estimated_workspace_bytes: 5_122_621_440,
                process_budget_bytes: 1_073_741_824,
            }
        );
    }

    #[test]
    fn canonical_byte_sink_checks_exact_content_and_length_across_chunks() {
        let mut exact = CanonicalBytes::new(&[1, 2, 3]);
        exact.extend([1, 2]);
        exact.extend([3]);
        assert!(exact.matches_exactly());

        let mut different_byte = CanonicalBytes::new(&[1, 2, 3]);
        different_byte.extend([1, 9, 3]);
        assert!(!different_byte.matches_exactly());

        let mut truncated = CanonicalBytes::new(&[1, 2, 3]);
        truncated.extend([1, 2]);
        assert!(!truncated.matches_exactly());

        let mut extended = CanonicalBytes::new(&[1, 2]);
        extended.extend([1, 2, 3]);
        assert!(!extended.matches_exactly());
    }

    fn test_fixture() -> (ValArray, [ValArray; DEPTH], u64, ValArray) {
        let leaf = core::array::from_fn(|i| (i * 3 + 7) as u8);
        let siblings: [ValArray; DEPTH] =
            core::array::from_fn(|level| core::array::from_fn(|i| (level * 19 + i * 11 + 5) as u8));
        let index = 0xA5C3_7E19_8246_D0B1u64;
        let python_reference_root: ValArray = [
            0x15, 0xf0, 0x3b, 0x9b, 0x9c, 0x02, 0x3e, 0x98, 0x16, 0x5d, 0xc8, 0x6d, 0x42, 0xaf,
            0xff, 0xe7, 0x43, 0x0d, 0x54, 0x3c, 0xfd, 0x75, 0xf0, 0xaa, 0x2c, 0x92, 0x6a, 0x0f,
            0xa1, 0x69, 0x42, 0xd7, 0xc8, 0x4b, 0x55, 0xc2, 0xad, 0x8f, 0x2e, 0xf6, 0xbe, 0x60,
            0xb2, 0xa3, 0x2d, 0xea, 0x87, 0xbf, 0x90, 0xdb, 0x47, 0xfd, 0x05, 0x41, 0x94, 0x46,
            0x29, 0x23, 0xd6, 0x23, 0x30, 0x26, 0xff, 0xd3,
        ];
        (leaf, siblings, index, python_reference_root)
    }
    fn canonical_statement(root: ValArray) -> Vec<u8> {
        let commitment = [0x11; DIGEST_BYTES];
        let kem_ciphertext = [0x22; 1088];
        let nonce = [0x33; 12];
        let ciphertext = vec![0x44; 156];
        let leaf = output_leaf(commitment, kem_ciphertext, nonce, &ciphertext);
        TransactionStatementV1 {
            chain_id: [0x55; 32],
            anchor_height: 123,
            root_out: root,
            fee: 4,
            nullifier: [0x66; DIGEST_BYTES],
            output: OutputRecordV1 {
                commitment,
                kem_ciphertext,
                nonce,
                ciphertext,
                leaf,
            },
        }
        .serialize()
        .unwrap()
    }
    #[test]
    fn rdxl_public_values_reject_mismatched_statement_object() {
        let parsed_bytes = canonical_statement([0; DIGEST_BYTES]);
        let unrelated_bytes = canonical_statement([1; DIGEST_BYTES]);
        let parsed = TransactionStatementV1::parse(&parsed_bytes).unwrap();
        assert!(rdxl_statement_public_values(&parsed_bytes, &parsed).is_ok());
        assert!(rdxl_statement_public_values(&unrelated_bytes, &parsed).is_err());
    }
    #[test]
    fn rdxl_public_values_reject_other_codec_valid_ciphertext_lengths() {
        let base = TransactionStatementV1::parse(&canonical_statement([0; DIGEST_BYTES])).unwrap();
        for ciphertext_len in [412, 668] {
            let mut statement = base.clone();
            statement.output.ciphertext = vec![0x44; ciphertext_len];
            statement.output.leaf = output_leaf(
                statement.output.commitment,
                statement.output.kem_ciphertext,
                statement.output.nonce,
                &statement.output.ciphertext,
            );
            let statement_bytes = statement.serialize().unwrap();
            assert!(TransactionStatementV1::parse(&statement_bytes).is_ok());
            assert_eq!(
                rdxl_statement_public_values(&statement_bytes, &statement),
                Err(Depth64PathProofError::Malformed(
                    "RDXL output ciphertext must be exactly 156 bytes"
                ))
            );
        }
    }
    fn source_fixture() -> OutputRecordV1 {
        let commitment = [0x81; DIGEST_BYTES];
        let kem_ciphertext = [0x92; 1088];
        let nonce = [0xa3; 12];
        let ciphertext = vec![0xb4; SOURCE_CIPHERTEXT_BYTES];
        let leaf = output_leaf(commitment, kem_ciphertext, nonce, &ciphertext);
        OutputRecordV1 {
            commitment,
            kem_ciphertext,
            nonce,
            ciphertext,
            leaf,
        }
    }
    fn rdxl_preflight_result(
        input_value: u64,
        fee: u64,
        output_value: u64,
    ) -> Result<Vec<u8>, Depth64PathProofError> {
        let (_, siblings, index, root) = test_fixture();
        let mut statement = TransactionStatementV1::parse(&canonical_statement(root)).unwrap();
        statement.fee = fee;
        let statement_bytes = statement.serialize().unwrap();
        let source = source_fixture();
        let output_note = OutputNoteOpeningV1 {
            owner: [0x42; 64],
            value: output_value,
            rho: [0x24; 64],
            randomness: [0x91; 64],
        };
        prove_source_key_note_nullifier_output_balance_depth64_path(
            &statement_bytes,
            &source,
            &[0; 64],
            &[0; 32],
            input_value,
            &[0; 64],
            &[0; 64],
            &siblings,
            index,
            &output_note,
        )
    }
    #[test]
    fn rdxl_preflight_rejects_zero_mismatch_and_u64_overflow_without_proving() {
        assert_eq!(
            rdxl_preflight_result(0, 4, 1),
            Err(Depth64PathProofError::Malformed(
                "input and output note values must be nonzero"
            ))
        );
        assert_eq!(
            rdxl_preflight_result(5, 4, 0),
            Err(Depth64PathProofError::Malformed(
                "input and output note values must be nonzero"
            ))
        );
        assert_eq!(
            rdxl_preflight_result(4, 4, 1),
            Err(Depth64PathProofError::UnbalancedValues)
        );
        assert_eq!(
            rdxl_preflight_result(u64::MAX, 1, u64::MAX),
            Err(Depth64PathProofError::UnbalancedValues)
        );
    }
    #[test]
    fn depth64_path_root_matches_python_reference() {
        let (leaf, siblings, index, expected_root) = test_fixture();
        let (_, root) = build_trace(&leaf, &siblings, index);
        assert_eq!(root, expected_root);
    }

    #[test]
    fn rdxl_verifier_rejects_output_leaf_mutation_at_host_codec_boundary() {
        let (_, _, _, root) = test_fixture();
        let statement_bytes = canonical_statement(root);
        let mut mutated_leaf = statement_bytes;
        *mutated_leaf.last_mut().unwrap() ^= 1;

        // This verifies the host parser gate only; the output-leaf hash is not an AIR relation.
        assert!(TransactionStatementV1::parse(&mutated_leaf).is_err());
        assert_eq!(
            verify_source_key_note_nullifier_output_balance_depth64_path(&[], &mutated_leaf),
            Err(Depth64PathProofError::Malformed(
                "invalid expected transaction statement"
            ))
        );
    }

    #[test]
    fn rdxl_verifier_rejects_malformed_envelope_headers_without_proof_decode() {
        let (_, _, _, root) = test_fixture();
        let statement_bytes = canonical_statement(root);
        let header = |magic: &[u8; 8], version: u16, statement_len: u32, proof_len: u32| {
            let mut bytes = Vec::with_capacity(STATEMENT_HEADER_BYTES);
            bytes.extend_from_slice(magic);
            bytes.extend_from_slice(&version.to_le_bytes());
            bytes.extend_from_slice(&statement_len.to_le_bytes());
            bytes.extend_from_slice(&proof_len.to_le_bytes());
            bytes
        };
        let check = |bytes: &[u8], reason| {
            assert_eq!(
                verify_source_key_note_nullifier_output_balance_depth64_path(
                    bytes,
                    &statement_bytes,
                ),
                Err(Depth64PathProofError::Malformed(reason))
            );
        };

        check(&[], "truncated envelope");
        let mut bad_magic = header(SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC, VERSION, 1, 1);
        bad_magic[0] ^= 1;
        check(&bad_magic, "wrong magic");
        check(
            &header(SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC, VERSION + 1, 1, 1),
            "unsupported version",
        );
        check(
            &header(SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC, VERSION, 0, 1),
            "transaction statement size out of bounds",
        );
        check(
            &header(SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC, VERSION, 1, 0),
            "proof size out of bounds",
        );
        check(
            &header(
                SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC,
                VERSION,
                (MAX_STATEMENT_BYTES + 1) as u32,
                1,
            ),
            "transaction statement size out of bounds",
        );
        check(
            &header(
                SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC,
                VERSION,
                1,
                (MAX_PROOF_BYTES + 1) as u32,
            ),
            "proof size out of bounds",
        );
        check(
            &header(SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC, VERSION, 1, 1),
            "envelope length mismatch",
        );
    }

    #[test]
    fn statement_bound_envelopes_return_borrowed_exact_slices() {
        let (_, _, _, root) = test_fixture();
        let statement = canonical_statement(root);
        let invalid_proof = [0xff];
        let profiles = [
            STATEMENT_MAGIC,
            SOURCE_STATEMENT_MAGIC,
            SOURCE_NOTE_MAGIC,
            SOURCE_KEY_NOTE_MAGIC,
            SOURCE_KEY_NOTE_NULLIFIER_MAGIC,
            SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC,
        ];

        for magic in profiles {
            let mut envelope =
                Vec::with_capacity(STATEMENT_HEADER_BYTES + statement.len() + invalid_proof.len());
            envelope.extend_from_slice(magic);
            envelope.extend_from_slice(&VERSION.to_le_bytes());
            envelope.extend_from_slice(&(statement.len() as u32).to_le_bytes());
            envelope.extend_from_slice(&(invalid_proof.len() as u32).to_le_bytes());
            envelope.extend_from_slice(&statement);
            envelope.extend_from_slice(&invalid_proof);

            let (statement_slice, proof_slice) =
                split_statement_bound_with_magic(&envelope, magic).unwrap();
            assert_eq!(statement_slice, statement.as_slice());
            assert_eq!(proof_slice, invalid_proof);
            assert_eq!(
                statement_slice.as_ptr(),
                envelope[STATEMENT_HEADER_BYTES..].as_ptr()
            );
            assert_eq!(
                proof_slice.as_ptr(),
                envelope[envelope.len() - 1..].as_ptr()
            );
        }
    }

    #[test]
    fn statement_bound_verifiers_reject_mismatch_before_proof_deserialization() {
        let (_, _, _, root) = test_fixture();
        let expected_statement_bytes = canonical_statement(root);
        let mut embedded_statement =
            TransactionStatementV1::parse(&expected_statement_bytes).unwrap();
        embedded_statement.fee += 1;
        let embedded_statement = embedded_statement.serialize().unwrap();
        let invalid_proof = [0xff];
        let profiles: [(
            &[u8; 8],
            fn(&[u8], &[u8]) -> Result<TransactionStatementV1, Depth64PathProofError>,
        ); 6] = [
            (STATEMENT_MAGIC, verify_statement_bound_depth64_path),
            (SOURCE_STATEMENT_MAGIC, verify_source_bound_depth64_path),
            (SOURCE_NOTE_MAGIC, verify_source_note_depth64_path),
            (SOURCE_KEY_NOTE_MAGIC, verify_source_key_note_depth64_path),
            (
                SOURCE_KEY_NOTE_NULLIFIER_MAGIC,
                verify_source_key_note_nullifier_depth64_path,
            ),
            (
                SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC,
                verify_source_key_note_nullifier_output_balance_depth64_path,
            ),
        ];

        for (magic, verify) in profiles {
            let mut envelope = Vec::with_capacity(
                STATEMENT_HEADER_BYTES + embedded_statement.len() + invalid_proof.len(),
            );
            envelope.extend_from_slice(magic);
            envelope.extend_from_slice(&VERSION.to_le_bytes());
            envelope.extend_from_slice(&(embedded_statement.len() as u32).to_le_bytes());
            envelope.extend_from_slice(&(invalid_proof.len() as u32).to_le_bytes());
            envelope.extend_from_slice(&embedded_statement);
            envelope.extend_from_slice(&invalid_proof);

            // Every profile must reject the structurally valid but mismatched
            // statement before deserializing this deliberately invalid proof slice.
            assert_eq!(
                verify(&envelope, &expected_statement_bytes),
                Err(Depth64PathProofError::StatementMismatch)
            );
        }
    }

    #[test]
    #[ignore = "proof-heavy 4096-row STARK; peak RSS not bounded to 4-GiB desktop/1-GiB mobile caps; require profile-specific fit evidence before opt-in"]
    fn proves_and_verifies_private_depth64_path() {
        let (leaf, siblings, index, expected_root) = test_fixture();
        let (_, root) = build_trace(&leaf, &siblings, index);
        assert_eq!(root, expected_root);
        let prove_started = std::time::Instant::now();
        let proof = prove_depth64_path(&leaf, &siblings, index, &root).unwrap();
        eprintln!(
            "depth64 proof bytes: {}; prove elapsed: {:?}",
            proof.len(),
            prove_started.elapsed()
        );
        let verify_started = std::time::Instant::now();
        assert_eq!(
            verify_depth64_path(&proof, &root).unwrap(),
            Depth64PathStatementV1 { root }
        );
        eprintln!("depth64 verify elapsed: {:?}", verify_started.elapsed());
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert_eq!(
            verify_depth64_path(&proof, &wrong_root),
            Err(Depth64PathProofError::RootMismatch)
        );
        let mut changed_siblings = siblings;
        changed_siblings[17][9] ^= 1;
        assert_eq!(
            prove_depth64_path(&leaf, &changed_siblings, index, &root),
            Err(Depth64PathProofError::RootMismatch)
        );
        assert_eq!(
            prove_depth64_path(&leaf, &siblings, index ^ 1, &root),
            Err(Depth64PathProofError::RootMismatch)
        );
        let mut bad_magic = proof.clone();
        bad_magic[0] ^= 1;
        assert!(verify_depth64_path(&bad_magic, &root).is_err());
        let mut bad_version = proof.clone();
        bad_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(verify_depth64_path(&bad_version, &root).is_err());
        let mut bad_length = proof.clone();
        bad_length[74..78].copy_from_slice(&1u32.to_le_bytes());
        assert!(verify_depth64_path(&bad_length, &root).is_err());
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(verify_depth64_path(&trailing, &root).is_err());
        let mut tampered = proof.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_depth64_path(&tampered, &root).is_err());
        let mut truncated = proof;
        truncated.pop();
        assert!(verify_depth64_path(&truncated, &root).is_err());
    }
    #[test]
    #[ignore = "proof-heavy 4096-row STARK; peak RSS not bounded to 4-GiB desktop/1-GiB mobile caps; require profile-specific fit evidence before opt-in"]
    fn statement_bound_path_binds_exact_canonical_statement_bytes() {
        let (leaf, siblings, index, root) = test_fixture();
        let statement_bytes = canonical_statement(root);
        let proof =
            prove_statement_bound_depth64_path(&statement_bytes, &leaf, &siblings, index).unwrap();
        let parsed_statement = TransactionStatementV1::parse(&statement_bytes).unwrap();
        assert_eq!(
            verify_statement_bound_depth64_path(&proof, &statement_bytes),
            Ok(parsed_statement.clone())
        );
        let mut changed_statement = parsed_statement;
        changed_statement.fee += 1;
        let changed_statement_bytes = changed_statement.serialize().unwrap();
        assert_eq!(
            verify_statement_bound_depth64_path(&proof, &changed_statement_bytes),
            Err(Depth64PathProofError::StatementMismatch)
        );
        let mut transcript_mutation = proof.clone();
        let statement_end = STATEMENT_HEADER_BYTES + statement_bytes.len();
        transcript_mutation[STATEMENT_HEADER_BYTES..statement_end]
            .copy_from_slice(&changed_statement_bytes);
        assert!(
            verify_statement_bound_depth64_path(&transcript_mutation, &changed_statement_bytes)
                .is_err()
        );
        let mut bad_magic = proof.clone();
        bad_magic[0] ^= 1;
        assert!(verify_statement_bound_depth64_path(&bad_magic, &statement_bytes).is_err());
        let mut bad_version = proof.clone();
        bad_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(verify_statement_bound_depth64_path(&bad_version, &statement_bytes).is_err());
        let mut bad_statement_length = proof.clone();
        bad_statement_length[10..14].copy_from_slice(&1u32.to_le_bytes());
        assert!(
            verify_statement_bound_depth64_path(&bad_statement_length, &statement_bytes).is_err()
        );
        let mut bad_proof_length = proof.clone();
        bad_proof_length[14..18].copy_from_slice(&1u32.to_le_bytes());
        assert!(verify_statement_bound_depth64_path(&bad_proof_length, &statement_bytes).is_err());
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(verify_statement_bound_depth64_path(&trailing, &statement_bytes).is_err());
        let mut tampered_proof = proof.clone();
        *tampered_proof.last_mut().unwrap() ^= 1;
        assert!(verify_statement_bound_depth64_path(&tampered_proof, &statement_bytes).is_err());
        let mut truncated = proof;
        truncated.pop();
        assert!(verify_statement_bound_depth64_path(&truncated, &statement_bytes).is_err());
    }
    #[test]
    #[ignore = "proof-heavy 4096-row STARK; peak RSS not bounded to 4-GiB desktop/1-GiB mobile caps; require profile-specific fit evidence before opt-in"]
    fn source_bound_profile_hashes_private_fixed156_output_before_path() {
        let (_, siblings, index, _) = test_fixture();
        let source = source_fixture();
        let source_frame = output_leaf_frame(
            source.commitment,
            source.kem_ciphertext,
            source.nonce,
            &source.ciphertext,
        );
        let source_blocks = checked_source_leaf_blocks(&source).unwrap();
        assert_eq!(source_frame.len(), SOURCE_FRAME_BYTES);
        assert_eq!(source_blocks.len(), SOURCE_BLOCKS);
        for (offset, byte) in source_frame.iter().copied().enumerate() {
            if let Some(expected) = source_frame_constant(offset) {
                assert_eq!(byte, expected, "fixed frame byte at offset {offset}");
            }
            assert_eq!(
                source_blocks[offset / SHAKE_RATE_BYTES][offset % SHAKE_RATE_BYTES],
                byte
            );
        }
        assert_eq!(source_frame_constant(SOURCE_FRAME_BYTES), Some(0x9f));
        assert_eq!(SOURCE_ROWS, 10 * NUM_ROUNDS);
        assert_eq!(SOURCE_BOUND_ACTIVE_ROWS, 3312);
        assert_eq!(
            source_blocks[9][SOURCE_FRAME_BYTES - 9 * SHAKE_RATE_BYTES],
            0x9f
        );
        assert_eq!(
            output_leaf(
                source.commitment,
                source.kem_ciphertext,
                source.nonce,
                &source.ciphertext,
            ),
            source.leaf
        );
        // The statement's public output is intentionally unrelated to this
        // distinct private source record.
        let (_, root) = build_trace(&source.leaf, &siblings, index);
        let statement_bytes = canonical_statement(root);
        let statement = TransactionStatementV1::parse(&statement_bytes).unwrap();
        assert_ne!(statement.output.leaf, source.leaf);
        assert_ne!(statement.output.commitment, source.commitment);
        let trace_build_started = Instant::now();
        let source_trace =
            build_source_bound_trace(&source_blocks, &source.leaf, &siblings, index).0;
        eprintln!(
            "RDXS64P1 witness trace build: {:?}",
            trace_build_started.elapsed()
        );
        let source_values = statement_public_values(&root, &statement_bytes);
        let source_air = Depth64PathAir {
            public_value_count: source_values.len(),
            source_bound: true,
            note_bound: false,
            spend_owner_bound: false,
            nullifier_bound: false,
            output_note_balance_bound: false,
        };
        let constraint_check_started = Instant::now();
        let report =
            p3_air::check_all_constraints(&source_air, &source_trace, &source_values, Some(20));
        eprintln!(
            "RDXS64P1 standalone AIR check: {:?}",
            constraint_check_started.elapsed()
        );
        assert!(report.is_ok(), "{:?}", report.failures);
        let prove_started = Instant::now();
        let proof = prove_source_bound_depth64_path(&statement_bytes, &source, &siblings, index)
            .expect("valid fixed-source path proof");
        eprintln!(
            "RDXS64P1 prove API: {} envelope bytes in {:?}",
            proof.len(),
            prove_started.elapsed()
        );
        assert_eq!(&proof[..8], SOURCE_STATEMENT_MAGIC);
        assert_eq!(
            &proof[STATEMENT_HEADER_BYTES..STATEMENT_HEADER_BYTES + statement_bytes.len()],
            statement_bytes.as_slice()
        );
        let verify_started = Instant::now();
        let verified = verify_source_bound_depth64_path(&proof, &statement_bytes);
        eprintln!("RDXS64P1 verify API: {:?}", verify_started.elapsed());
        assert_eq!(verified, Ok(statement.clone()));
        assert!(verify_statement_bound_depth64_path(&proof, &statement_bytes).is_err());
        let mut wrong_leaf = source.clone();
        wrong_leaf.leaf[0] ^= 1;
        assert!(matches!(
            prove_source_bound_depth64_path(&statement_bytes, &wrong_leaf, &siblings, index),
            Err(Depth64PathProofError::Malformed(_))
        ));
        let mut wrong_length = source.clone();
        wrong_length.ciphertext.push(0);
        wrong_length.leaf = output_leaf(
            wrong_length.commitment,
            wrong_length.kem_ciphertext,
            wrong_length.nonce,
            &wrong_length.ciphertext,
        );
        assert!(matches!(
            prove_source_bound_depth64_path(&statement_bytes, &wrong_length, &siblings, index),
            Err(Depth64PathProofError::Malformed(_))
        ));
        let mut short_ciphertext = source.clone();
        short_ciphertext.ciphertext.pop();
        short_ciphertext.leaf = output_leaf(
            short_ciphertext.commitment,
            short_ciphertext.kem_ciphertext,
            short_ciphertext.nonce,
            &short_ciphertext.ciphertext,
        );
        assert!(matches!(
            prove_source_bound_depth64_path(&statement_bytes, &short_ciphertext, &siblings, index),
            Err(Depth64PathProofError::Malformed(_))
        ));
        let mut wrong_field = source.clone();
        wrong_field.commitment[0] ^= 1;
        wrong_field.leaf = output_leaf(
            wrong_field.commitment,
            wrong_field.kem_ciphertext,
            wrong_field.nonce,
            &wrong_field.ciphertext,
        );
        assert_eq!(
            prove_source_bound_depth64_path(&statement_bytes, &wrong_field, &siblings, index),
            Err(Depth64PathProofError::RootMismatch)
        );
        let mut wrong_siblings = siblings.clone();
        wrong_siblings[0][0] ^= 1;
        assert_eq!(
            prove_source_bound_depth64_path(&statement_bytes, &source, &wrong_siblings, index),
            Err(Depth64PathProofError::RootMismatch)
        );
        assert_eq!(
            prove_source_bound_depth64_path(&statement_bytes, &source, &siblings, index ^ 1),
            Err(Depth64PathProofError::RootMismatch)
        );
        // Bypass host preflight: prove a trace whose private frame has a changed
        // source field but whose path still starts at the original leaf. The AIR
        // must reject its digest-to-path link against the original public root.
        let bad_blocks = output_leaf_absorb_blocks(
            wrong_field.commitment,
            wrong_field.kem_ciphertext,
            wrong_field.nonce,
            &wrong_field.ciphertext,
        );
        let (bad_trace, bad_root) =
            build_source_bound_trace(&bad_blocks, &source.leaf, &siblings, index);
        assert_eq!(bad_root, root);
        let values = statement_public_values(&root, &statement_bytes);
        let air = Depth64PathAir {
            public_value_count: values.len(),
            source_bound: true,
            note_bound: false,
            spend_owner_bound: false,
            nullifier_bound: false,
            output_note_balance_bound: false,
        };
        let config = amount_opening::make_config();
        let bad_prove_started = Instant::now();
        let bad_proof = prove(&config, &air, bad_trace, &values).unwrap();
        eprintln!(
            "RDXS64P1 intentionally inconsistent AIR proof generation: {:?}",
            bad_prove_started.elapsed()
        );
        let bad_envelope = encode_source_statement_bound(&statement_bytes, &bad_proof).unwrap();
        let bad_verify_started = Instant::now();
        assert!(verify_source_bound_depth64_path(&bad_envelope, &statement_bytes).is_err());
        eprintln!(
            "RDXS64P1 adversarial verifier rejection: {:?}",
            bad_verify_started.elapsed()
        );
        let mut wrong_statement = statement.clone();
        wrong_statement.fee += 1;
        assert_eq!(
            verify_source_bound_depth64_path(&proof, &wrong_statement.serialize().unwrap()),
            Err(Depth64PathProofError::StatementMismatch)
        );
        let mut transcript_mutation = proof.clone();
        let changed_statement_bytes = wrong_statement.serialize().unwrap();
        let statement_end = STATEMENT_HEADER_BYTES + statement_bytes.len();
        transcript_mutation[STATEMENT_HEADER_BYTES..statement_end]
            .copy_from_slice(&changed_statement_bytes);
        assert!(
            verify_source_bound_depth64_path(&transcript_mutation, &changed_statement_bytes)
                .is_err()
        );
        let mut bad_version = proof.clone();
        bad_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(verify_source_bound_depth64_path(&bad_version, &statement_bytes).is_err());
        let mut bad_statement_length = proof.clone();
        bad_statement_length[10..14].copy_from_slice(&1u32.to_le_bytes());
        assert!(verify_source_bound_depth64_path(&bad_statement_length, &statement_bytes).is_err());
        let mut oversized_statement = proof.clone();
        oversized_statement[10..14]
            .copy_from_slice(&((MAX_STATEMENT_BYTES as u32) + 1).to_le_bytes());
        assert!(verify_source_bound_depth64_path(&oversized_statement, &statement_bytes).is_err());
        let mut bad_proof_length = proof.clone();
        bad_proof_length[14..18].copy_from_slice(&1u32.to_le_bytes());
        assert!(verify_source_bound_depth64_path(&bad_proof_length, &statement_bytes).is_err());
        let mut oversized_proof = proof.clone();
        oversized_proof[14..18].copy_from_slice(&((MAX_PROOF_BYTES as u32) + 1).to_le_bytes());
        assert!(verify_source_bound_depth64_path(&oversized_proof, &statement_bytes).is_err());
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(verify_source_bound_depth64_path(&trailing, &statement_bytes).is_err());
        let mut truncated = proof.clone();
        truncated.pop();
        assert!(verify_source_bound_depth64_path(&truncated, &statement_bytes).is_err());
        let mut tampered_proof = proof.clone();
        *tampered_proof.last_mut().unwrap() ^= 1;
        assert!(verify_source_bound_depth64_path(&tampered_proof, &statement_bytes).is_err());
        let mut wrong_magic = proof.clone();
        wrong_magic[0] ^= 1;
        assert!(verify_source_bound_depth64_path(&wrong_magic, &statement_bytes).is_err());
    }

    #[test]
    #[ignore = "proof-heavy 4096-row STARK; peak RSS not bounded to 4-GiB desktop/1-GiB mobile caps; require profile-specific fit evidence before opt-in"]
    fn source_note_profile_composes_private_opening_leaf_and_path() {
        let owner = [0x21; 64];
        let rho = [0x32; 64];
        let randomness = [0x43; 64];
        let value = 0x0123_4567_89ab_cdefu64;
        let (_, note_commitment) =
            crate::note_commitment_opening::build_trace(&owner, value, &rho, &randomness);
        let mut source = source_fixture();
        source.commitment = note_commitment;
        source.leaf = output_leaf(
            source.commitment,
            source.kem_ciphertext,
            source.nonce,
            &source.ciphertext,
        );
        let (_, siblings, index, _) = test_fixture();
        let (_, root) = build_trace(&source.leaf, &siblings, index);
        let statement_bytes = canonical_statement(root);
        let statement = TransactionStatementV1::parse(&statement_bytes).unwrap();
        assert_ne!(statement.output.commitment, source.commitment);
        assert_ne!(statement.output.leaf, source.leaf);
        assert_eq!(NOTE_ROWS, 48);
        assert_eq!(SOURCE_NOTE_ACTIVE_ROWS, 3360);

        let source_blocks = checked_source_leaf_blocks(&source).unwrap();
        let (note_trace, digest) =
            crate::note_commitment_opening::build_trace(&owner, value, &rho, &randomness);
        assert_eq!(digest, source.commitment);
        let trace_build_started = Instant::now();
        let (trace, computed_root) = build_source_note_trace(
            &source_blocks,
            &source.commitment,
            &source.leaf,
            &siblings,
            index,
            &note_trace,
        );
        assert_eq!(trace.width, SOURCE_NOTE_TRACE_WIDTH);
        assert_eq!(computed_root, root);
        let note_final_row = &trace.values[(NOTE_ROWS - 1) * SOURCE_NOTE_TRACE_WIDTH
            ..(NOTE_ROWS - 1) * SOURCE_NOTE_TRACE_WIDTH + SOURCE_TRACE_WIDTH];
        assert_eq!(
            &rate_bytes_from_keccak_row(note_final_row)[..DIGEST_BYTES],
            source.commitment.as_slice()
        );
        eprintln!(
            "RDXI64P1 witness trace build: {:?}",
            trace_build_started.elapsed()
        );
        let values = statement_public_values(&root, &statement_bytes);
        let air = Depth64PathAir {
            public_value_count: values.len(),
            source_bound: true,
            note_bound: true,
            spend_owner_bound: false,
            nullifier_bound: false,
            output_note_balance_bound: false,
        };
        let check_started = Instant::now();
        let report = p3_air::check_all_constraints(&air, &trace, &values, Some(20));
        eprintln!("RDXI64P1 AIR check: {:?}", check_started.elapsed());
        assert!(report.is_ok(), "{:?}", report.failures);

        // The host API preflights the relation, but the AIR independently links
        // the note digest to source.commitment when fed a mismatching trace.
        let bad_owner = [0x24; 64];
        let (bad_note_trace, bad_digest) =
            crate::note_commitment_opening::build_trace(&bad_owner, value, &rho, &randomness);
        assert_ne!(bad_digest, source.commitment);
        let (bad_composite_trace, bad_root) = build_source_note_trace(
            &source_blocks,
            &source.commitment,
            &source.leaf,
            &siblings,
            index,
            &bad_note_trace,
        );
        assert_eq!(bad_root, root);
        let bad_report =
            p3_air::check_all_constraints(&air, &bad_composite_trace, &values, Some(20));
        assert!(!bad_report.is_ok());

        let mut bad_stage_trace = trace.clone();
        bad_stage_trace.values[10 * SOURCE_NOTE_TRACE_WIDTH + NOTE_ACTIVE_OFFSET] = Val::ZERO;
        assert!(!p3_air::check_all_constraints(&air, &bad_stage_trace, &values, Some(20)).is_ok());
        let mut bad_phase_trace = trace.clone();
        bad_phase_trace.values[NUM_ROUNDS * SOURCE_NOTE_TRACE_WIDTH + PHASE] = Val::ZERO;
        assert!(!p3_air::check_all_constraints(&air, &bad_phase_trace, &values, Some(20)).is_ok());

        let prove_started = Instant::now();
        let envelope = prove_source_note_depth64_path(
            &statement_bytes,
            &source,
            &owner,
            value,
            &rho,
            &randomness,
            &siblings,
            index,
        )
        .expect("valid source-note path proof");
        eprintln!(
            "RDXI64P1 prove API: {} envelope bytes in {:?}",
            envelope.len(),
            prove_started.elapsed()
        );
        assert_eq!(&envelope[..8], SOURCE_NOTE_MAGIC);
        assert_eq!(
            &envelope[STATEMENT_HEADER_BYTES..STATEMENT_HEADER_BYTES + statement_bytes.len()],
            statement_bytes.as_slice()
        );
        let verify_started = Instant::now();
        assert_eq!(
            verify_source_note_depth64_path(&envelope, &statement_bytes),
            Ok(statement.clone())
        );
        eprintln!("RDXI64P1 verify API: {:?}", verify_started.elapsed());

        assert_eq!(
            prove_source_note_depth64_path(
                &statement_bytes,
                &source,
                &bad_owner,
                value,
                &rho,
                &randomness,
                &siblings,
                index,
            ),
            Err(Depth64PathProofError::NoteCommitmentMismatch)
        );
        assert!(matches!(
            prove_source_note_depth64_path(
                &statement_bytes,
                &source,
                &owner,
                0,
                &rho,
                &randomness,
                &siblings,
                index,
            ),
            Err(Depth64PathProofError::Malformed(_))
        ));
        let mut changed_source_commitment = source.clone();
        changed_source_commitment.commitment[0] ^= 1;
        changed_source_commitment.leaf = output_leaf(
            changed_source_commitment.commitment,
            changed_source_commitment.kem_ciphertext,
            changed_source_commitment.nonce,
            &changed_source_commitment.ciphertext,
        );
        assert_eq!(
            prove_source_note_depth64_path(
                &statement_bytes,
                &changed_source_commitment,
                &owner,
                value,
                &rho,
                &randomness,
                &siblings,
                index,
            ),
            Err(Depth64PathProofError::NoteCommitmentMismatch)
        );
        assert_eq!(
            prove_source_note_depth64_path(
                &statement_bytes,
                &source,
                &owner,
                value,
                &rho,
                &randomness,
                &siblings,
                index ^ 1,
            ),
            Err(Depth64PathProofError::RootMismatch)
        );

        let mut changed_statement = statement.clone();
        changed_statement.fee += 1;
        assert_eq!(
            verify_source_note_depth64_path(&envelope, &changed_statement.serialize().unwrap()),
            Err(Depth64PathProofError::StatementMismatch)
        );
        assert!(verify_source_bound_depth64_path(&envelope, &statement_bytes).is_err());
        let mut bad_magic = envelope.clone();
        bad_magic[0] ^= 1;
        assert!(verify_source_note_depth64_path(&bad_magic, &statement_bytes).is_err());
        let mut bad_version = envelope.clone();
        bad_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert!(verify_source_note_depth64_path(&bad_version, &statement_bytes).is_err());
        let mut trailing = envelope.clone();
        trailing.push(0);
        assert!(verify_source_note_depth64_path(&trailing, &statement_bytes).is_err());
        let mut bad_proof = envelope;
        *bad_proof.last_mut().unwrap() ^= 1;
        assert!(verify_source_note_depth64_path(&bad_proof, &statement_bytes).is_err());
    }

    #[test]
    #[ignore = "proof-heavy 4096-row STARK; peak RSS not bounded to 4-GiB desktop/1-GiB mobile caps; require profile-specific fit evidence before opt-in"]
    fn source_key_note_profile_binds_spend_key_owner_and_note() {
        let spend_secret = [0x51; 64];
        let kem_shared_secret = [0x62; 32];
        let rho = [0x73; 64];
        let randomness = [0x84; 64];
        let value = 0x1020_3040_5060_7080u64;
        let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[&spend_secret]);
        let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
        let owner_state = candidate_hash_frame_state(
            b"radix/one-time/v1",
            &[&spend_public_key, &kem_shared_secret],
        );
        let owner = state_digest(&state_after_one(&owner_state));
        let (note_trace, note_commitment) =
            crate::note_commitment_opening::build_trace(&owner, value, &rho, &randomness);
        let mut source = source_fixture();
        source.commitment = note_commitment;
        source.leaf = output_leaf(
            source.commitment,
            source.kem_ciphertext,
            source.nonce,
            &source.ciphertext,
        );
        let (_, siblings, index, _) = test_fixture();
        let (_, root) = build_trace(&source.leaf, &siblings, index);
        let statement_bytes = canonical_statement(root);
        let statement = TransactionStatementV1::parse(&statement_bytes).unwrap();
        let source_blocks = checked_source_leaf_blocks(&source).unwrap();
        let (trace, computed_root, trace_owner) = build_source_key_note_trace(
            &source_blocks,
            &source.commitment,
            &source.leaf,
            &siblings,
            index,
            &note_trace,
            &spend_secret,
            &kem_shared_secret,
        );
        assert_eq!(trace.width, SOURCE_KEY_NOTE_TRACE_WIDTH);
        assert_eq!(trace.width, 7_511);
        assert_eq!(KEY_NOTE_ACTIVE_ROWS, 3_408);
        assert_eq!(computed_root, root);
        assert_eq!(trace_owner, owner);
        let active_rows = (0..TRACE_ROWS)
            .filter(|row_index| {
                trace.values[row_index * SOURCE_KEY_NOTE_TRACE_WIDTH + ACTIVE] == Val::ONE
            })
            .count();
        assert_eq!(active_rows, KEY_NOTE_ACTIVE_ROWS);
        let values = statement_public_values(&root, &statement_bytes);
        let air = Depth64PathAir {
            public_value_count: values.len(),
            source_bound: true,
            note_bound: true,
            spend_owner_bound: true,
            nullifier_bound: false,
            output_note_balance_bound: false,
        };
        let check_started = Instant::now();
        let report = p3_air::check_all_constraints(&air, &trace, &values, Some(20));
        eprintln!("RDXJ64P1 AIR check: {:?}", check_started.elapsed());
        assert!(report.is_ok(), "{:?}", report.failures);

        // Deliberately break the spend-pk transfer at the 23 -> 24 boundary.
        let mut bad_pk_transfer = trace.clone();
        let pk_transfer_index =
            NUM_ROUNDS * SOURCE_KEY_NOTE_TRACE_WIDTH + SOURCE_BUFFER_BITS_OFFSET;
        bad_pk_transfer.values[pk_transfer_index] =
            Val::ONE - bad_pk_transfer.values[pk_transfer_index];
        assert!(!p3_air::check_all_constraints(&air, &bad_pk_transfer, &values, Some(20)).is_ok());

        // A changed note owner at row 48 must not escape the owner-stage handoff.
        let mut bad_owner_handoff = trace.clone();
        let owner_handoff_index =
            2 * NUM_ROUNDS * SOURCE_KEY_NOTE_TRACE_WIDTH + NOTE_PRIVATE_BITS_OFFSET;
        bad_owner_handoff.values[owner_handoff_index] =
            Val::ONE - bad_owner_handoff.values[owner_handoff_index];
        assert!(
            !p3_air::check_all_constraints(&air, &bad_owner_handoff, &values, Some(20)).is_ok()
        );

        let mut skipped_key_stage = trace.clone();
        skipped_key_stage.values
            [(NUM_ROUNDS - 1) * SOURCE_KEY_NOTE_TRACE_WIDTH + SPEND_PK_ACTIVE_OFFSET] = Val::ZERO;
        assert!(
            !p3_air::check_all_constraints(&air, &skipped_key_stage, &values, Some(20)).is_ok()
        );

        // Mutating either private input across the full trace must break its hash frame.
        let mut changed_spend_secret = trace.clone();
        for row_index in 0..TRACE_ROWS {
            let base = row_index * SOURCE_KEY_NOTE_TRACE_WIDTH;
            changed_spend_secret.values[base + SPEND_OWNER_PRIVATE_OFFSET] = Val::from_u32(0x50);
            changed_spend_secret.values[base + SPEND_OWNER_PRIVATE_BITS_OFFSET] = Val::ZERO;
        }
        assert!(
            !p3_air::check_all_constraints(&air, &changed_spend_secret, &values, Some(20)).is_ok()
        );

        let mut changed_shared_secret = trace.clone();
        for row_index in 0..TRACE_ROWS {
            let base = row_index * SOURCE_KEY_NOTE_TRACE_WIDTH;
            changed_shared_secret.values[base + SPEND_OWNER_PRIVATE_OFFSET + 64] =
                Val::from_u32(0x63);
            changed_shared_secret.values[base + SPEND_OWNER_PRIVATE_BITS_OFFSET + 64 * 8] =
                Val::ONE;
        }
        assert!(
            !p3_air::check_all_constraints(&air, &changed_shared_secret, &values, Some(20)).is_ok()
        );

        let mut overlapping_key_stages = trace.clone();
        overlapping_key_stages.values[NOTE_OWNER_ACTIVE_OFFSET] = Val::ONE;
        assert!(
            !p3_air::check_all_constraints(&air, &overlapping_key_stages, &values, Some(20))
                .is_ok()
        );

        let mut reordered_key_stages = trace.clone();
        let row_24 = NUM_ROUNDS * SOURCE_KEY_NOTE_TRACE_WIDTH;
        reordered_key_stages.values[row_24 + SPEND_PK_ACTIVE_OFFSET] = Val::ONE;
        reordered_key_stages.values[row_24 + NOTE_OWNER_ACTIVE_OFFSET] = Val::ZERO;
        assert!(
            !p3_air::check_all_constraints(&air, &reordered_key_stages, &values, Some(20)).is_ok()
        );

        let prove_started = Instant::now();
        let envelope = prove_source_key_note_depth64_path(
            &statement_bytes,
            &source,
            &spend_secret,
            &kem_shared_secret,
            value,
            &rho,
            &randomness,
            &siblings,
            index,
        )
        .expect("valid spend-key/owner/note source-path proof");
        eprintln!(
            "RDXJ64P1 prove API: {} envelope bytes in {:?}",
            envelope.len(),
            prove_started.elapsed()
        );
        assert_eq!(&envelope[..8], SOURCE_KEY_NOTE_MAGIC);
        let verify_started = Instant::now();
        assert_eq!(
            verify_source_key_note_depth64_path(&envelope, &statement_bytes),
            Ok(statement)
        );
        eprintln!("RDXJ64P1 verify API: {:?}", verify_started.elapsed());
        assert!(verify_source_note_depth64_path(&envelope, &statement_bytes).is_err());
        let mut altered_statement = statement_bytes.clone();
        altered_statement[42] ^= 1; // root_out follows chain_id, version, and anchor_height.
        assert!(verify_source_key_note_depth64_path(&envelope, &altered_statement).is_err());
        let mut corrupted_envelope = envelope.clone();
        *corrupted_envelope.last_mut().unwrap() ^= 1;
        assert!(
            verify_source_key_note_depth64_path(&corrupted_envelope, &statement_bytes).is_err()
        );

        let mut wrong_spend_secret = spend_secret;
        wrong_spend_secret[0] ^= 1;
        assert_eq!(
            prove_source_key_note_depth64_path(
                &statement_bytes,
                &source,
                &wrong_spend_secret,
                &kem_shared_secret,
                value,
                &rho,
                &randomness,
                &siblings,
                index,
            ),
            Err(Depth64PathProofError::NoteCommitmentMismatch)
        );
        let mut wrong_shared_secret = kem_shared_secret;
        wrong_shared_secret[0] ^= 1;
        assert_eq!(
            prove_source_key_note_depth64_path(
                &statement_bytes,
                &source,
                &spend_secret,
                &wrong_shared_secret,
                value,
                &rho,
                &randomness,
                &siblings,
                index,
            ),
            Err(Depth64PathProofError::NoteCommitmentMismatch)
        );
    }

    #[test]
    #[ignore = "proof-heavy 4096-row STARK; peak RSS not bounded to 4-GiB desktop/1-GiB mobile caps; require profile-specific fit evidence before opt-in"]
    fn source_key_note_nullifier_profile_binds_same_witness_and_statement_digest() {
        use core::borrow::BorrowMut;

        let spend_secret = core::array::from_fn(|index| index as u8);
        let kem_shared_secret = core::array::from_fn(|index| index as u8);
        let rho = core::array::from_fn(|index| index as u8);
        let randomness = [0x84; 64];
        let value = 0x1020_3040_5060_7080u64;
        let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[&spend_secret]);
        let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
        let owner_state = candidate_hash_frame_state(
            b"radix/one-time/v1",
            &[&spend_public_key, &kem_shared_secret],
        );
        let owner = state_digest(&state_after_one(&owner_state));
        let (note_trace, note_commitment) =
            crate::note_commitment_opening::build_trace(&owner, value, &rho, &randomness);
        let mut source = source_fixture();
        source.commitment = note_commitment;
        source.leaf = output_leaf(
            source.commitment,
            source.kem_ciphertext,
            source.nonce,
            &source.ciphertext,
        );
        let (_, siblings, index, _) = test_fixture();
        let (_, root) = build_trace(&source.leaf, &siblings, index);
        let frame = crate::nullifier_opening::frame_for(&spend_secret, &kem_shared_secret, &rho);
        let first = crate::nullifier_opening::block_state(&frame, 0);
        let second = xor_states(
            state_after_one(&first),
            crate::nullifier_opening::block_state(&frame, 1),
        );
        let expected_nullifier = state_digest(&state_after_one(&second));
        let known_answer: ValArray = [
            0x16, 0x67, 0xf9, 0xf6, 0x12, 0x53, 0xf1, 0x53, 0x53, 0x23, 0x1b, 0x57, 0xc4, 0x35,
            0x7c, 0x0c, 0x16, 0xd1, 0x39, 0x7d, 0x67, 0x6a, 0x76, 0xc9, 0xac, 0x2f, 0xa2, 0x97,
            0x44, 0x67, 0x89, 0xc6, 0x70, 0x3e, 0xd9, 0xba, 0xbc, 0x10, 0x7c, 0x63, 0x5d, 0x07,
            0xd9, 0x83, 0xb0, 0x02, 0x52, 0x72, 0x50, 0x11, 0xaa, 0x0d, 0x58, 0xaf, 0x95, 0xbe,
            0xf4, 0xb4, 0x67, 0xdc, 0xe7, 0x95, 0xac, 0x8e,
        ];
        assert_eq!(expected_nullifier, known_answer);

        let mut statement = TransactionStatementV1::parse(&canonical_statement(root)).unwrap();
        statement.nullifier = expected_nullifier;
        let statement_bytes = statement.serialize().unwrap();
        let nullifier_start = crate::transaction_statement::STATEMENT_NULLIFIER_BYTES_OFFSET;
        assert_eq!(
            &statement_bytes[nullifier_start..nullifier_start + expected_nullifier.len()],
            &expected_nullifier
        );
        let source_blocks = checked_source_leaf_blocks(&source).unwrap();
        let (trace, computed_root, trace_owner, computed_nullifier) =
            build_source_key_note_nullifier_trace(
                &source_blocks,
                &source.commitment,
                &source.leaf,
                &siblings,
                index,
                &note_trace,
                &spend_secret,
                &kem_shared_secret,
                &rho,
            );
        assert_eq!(trace.width, SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH);
        assert_eq!(trace.width, 7_512);
        assert_eq!(KEY_NOTE_NULLIFIER_ACTIVE_ROWS, 3_456);
        assert_eq!(computed_root, root);
        assert_eq!(trace_owner, owner);
        assert_eq!(computed_nullifier, expected_nullifier);
        let active_rows = (0..TRACE_ROWS)
            .filter(|row_index| {
                trace.values[row_index * SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH + ACTIVE] == Val::ONE
            })
            .count();
        assert_eq!(active_rows, KEY_NOTE_NULLIFIER_ACTIVE_ROWS);
        let first_nullifier_end =
            &trace.values[(3 * NUM_ROUNDS - 1) * trace.width..(3 * NUM_ROUNDS) * trace.width];
        let first_nullifier_cols: &KeccakCols<Val> = first_nullifier_end.borrow();
        let first_nullifier_next =
            &trace.values[(3 * NUM_ROUNDS) * trace.width..(3 * NUM_ROUNDS + 1) * trace.width];
        for limb in 0..RATE_LIMBS {
            let reconstructed = (0..16).fold(Val::ZERO, |value, bit| {
                value
                    + first_nullifier_next[SOURCE_BUFFER_BITS_OFFSET + limb * 16 + bit]
                        * Val::from_u32(1 << bit)
            });
            assert_eq!(
                first_nullifier_cols.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
                reconstructed,
                "first nullifier output limb {limb}"
            );
        }

        let values = statement_public_values(&root, &statement_bytes);
        let air = Depth64PathAir {
            public_value_count: values.len(),
            source_bound: true,
            note_bound: true,
            spend_owner_bound: true,
            nullifier_bound: true,
            output_note_balance_bound: false,
        };
        let check_started = Instant::now();
        let report = p3_air::check_all_constraints(&air, &trace, &values, Some(20));
        eprintln!("RDXK64P1 AIR check: {:?}", check_started.elapsed());
        assert!(report.is_ok(), "{:?}", report.failures);

        let mut wrong_public_digest = values.clone();
        wrong_public_digest[64 + 175] = Val::ONE - wrong_public_digest[64 + 175];
        assert!(
            !p3_air::check_all_constraints(&air, &trace, &wrong_public_digest, Some(20)).is_ok()
        );

        // Owner→nullifier, first→second permutation, and nullifier→note carries.
        let width = SOURCE_KEY_NOTE_NULLIFIER_TRACE_WIDTH;
        let mut broken_selector = trace.clone();
        broken_selector.values[48 * width + NULLIFIER_ACTIVE_OFFSET] = Val::ZERO;
        assert!(!p3_air::check_all_constraints(&air, &broken_selector, &values, Some(20)).is_ok());

        let mut broken_rho_carry = trace.clone();
        broken_rho_carry.values[48 * width + NOTE_PRIVATE_BITS_OFFSET + 73 * 8] = Val::ZERO;
        assert!(!p3_air::check_all_constraints(&air, &broken_rho_carry, &values, Some(20)).is_ok());

        // Corrupt the block-output carry consumed as the second-block input.
        let mut broken_rate_buffer = trace.clone();
        let buffer_index = 72 * width + SOURCE_BUFFER_BITS_OFFSET;
        broken_rate_buffer.values[buffer_index] =
            Val::ONE - broken_rate_buffer.values[buffer_index];
        assert!(
            !p3_air::check_all_constraints(&air, &broken_rate_buffer, &values, Some(20)).is_ok()
        );

        // Corrupt an interior nullifier row to exercise the per-transition buffer hold.
        let mut broken_held_buffer = trace.clone();
        let held_buffer_index = 60 * width + SOURCE_BUFFER_BITS_OFFSET;
        broken_held_buffer.values[held_buffer_index] =
            Val::ONE - broken_held_buffer.values[held_buffer_index];
        assert!(
            !p3_air::check_all_constraints(&air, &broken_held_buffer, &values, Some(20)).is_ok()
        );

        let mut broken_nullifier_phase = trace.clone();
        broken_nullifier_phase.values[72 * width + PHASE] = Val::ZERO;
        assert!(
            !p3_air::check_all_constraints(&air, &broken_nullifier_phase, &values, Some(20))
                .is_ok()
        );

        let mut broken_capacity = trace.clone();
        let capacity_row = &mut broken_capacity.values[72 * width..72 * width + NUM_KECCAK_COLS];
        let capacity_cols: &mut KeccakCols<Val> = capacity_row.borrow_mut();
        capacity_cols.preimage[3][2][0] += Val::ONE; // Lane 17 is capacity, not rate.
        assert!(!p3_air::check_all_constraints(&air, &broken_capacity, &values, Some(20)).is_ok());

        let mut broken_domain_padding = trace.clone();
        let padding_row =
            &mut broken_domain_padding.values[72 * width..72 * width + NUM_KECCAK_COLS];
        let padding_cols: &mut KeccakCols<Val> = padding_row.borrow_mut();
        padding_cols.preimage[1][3][0] += Val::ONE; // Global frame byte 200: 0x1f.
        assert!(
            !p3_air::check_all_constraints(&air, &broken_domain_padding, &values, Some(20)).is_ok()
        );

        let mut broken_final_padding = trace.clone();
        let padding_row =
            &mut broken_final_padding.values[72 * width..72 * width + NUM_KECCAK_COLS];
        let padding_cols: &mut KeccakCols<Val> = padding_row.borrow_mut();
        padding_cols.preimage[3][1][3] += Val::ONE; // Global frame byte 271: 0x80.
        assert!(
            !p3_air::check_all_constraints(&air, &broken_final_padding, &values, Some(20)).is_ok()
        );

        let prove_started = Instant::now();
        let envelope = prove_source_key_note_nullifier_depth64_path(
            &statement_bytes,
            &source,
            &spend_secret,
            &kem_shared_secret,
            value,
            &rho,
            &randomness,
            &siblings,
            index,
        )
        .expect("valid same-witness spend/owner/nullifier/note/source/path proof");
        eprintln!(
            "RDXK64P1 prove API: {} envelope bytes in {:?}",
            envelope.len(),
            prove_started.elapsed()
        );
        assert_eq!(&envelope[..8], SOURCE_KEY_NOTE_NULLIFIER_MAGIC);
        let verify_started = Instant::now();
        assert_eq!(
            verify_source_key_note_nullifier_depth64_path(&envelope, &statement_bytes),
            Ok(statement.clone())
        );
        eprintln!("RDXK64P1 verify API: {:?}", verify_started.elapsed());
        assert!(verify_source_key_note_depth64_path(&envelope, &statement_bytes).is_err());

        // Re-encode the same proof under a changed public nullifier statement. Verification
        // reaches the proof/public-values check (rather than only the envelope equality check).
        let (_, proof) =
            decode_statement_bound_with_magic(&envelope, SOURCE_KEY_NOTE_NULLIFIER_MAGIC).unwrap();
        let mut altered_statement = statement;
        altered_statement.nullifier[0] ^= 1;
        let altered_statement_bytes = altered_statement.serialize().unwrap();
        let altered_envelope = encode_statement_bound_with_magic(
            SOURCE_KEY_NOTE_NULLIFIER_MAGIC,
            &altered_statement_bytes,
            &proof,
        )
        .unwrap();
        assert!(
            verify_source_key_note_nullifier_depth64_path(
                &altered_envelope,
                &altered_statement_bytes,
            )
            .is_err()
        );

        assert_eq!(
            prove_source_key_note_nullifier_depth64_path(
                &altered_statement_bytes,
                &source,
                &spend_secret,
                &kem_shared_secret,
                value,
                &rho,
                &randomness,
                &siblings,
                index,
            ),
            Err(Depth64PathProofError::NullifierMismatch)
        );
    }

    #[test]
    #[ignore = "RDXL 8192x14477: LDE alone 3,620 MiB exceeds 1-GiB mobile cap; possible matrix+LDE coexistence 4,525 MiB exceeds 4-GiB desktop cap; require newer fit evidence before opt-in"]
    fn source_key_note_nullifier_output_balance_profile_binds_opening_and_exact_u64_sum() {
        let spend_secret = core::array::from_fn(|index| index as u8);
        let kem_shared_secret = core::array::from_fn(|index| (index + 7) as u8);
        let input_rho = [0x25; 64];
        let input_randomness = [0x84; 64];
        let input_value = 0x0001_0000_0000_0020u64;
        let fee = 0x30u64;
        let output_note = OutputNoteOpeningV1 {
            owner: [0x42; 64],
            value: input_value - fee,
            rho: [0x24; 64],
            randomness: [0x91; 64],
        };
        let spend_pk_state = candidate_hash_frame_state(b"radix/spend-pk/v1", &[&spend_secret]);
        let spend_public_key = state_digest(&state_after_one(&spend_pk_state));
        let owner_state = candidate_hash_frame_state(
            b"radix/one-time/v1",
            &[&spend_public_key, &kem_shared_secret],
        );
        let input_owner = state_digest(&state_after_one(&owner_state));
        let (input_note_trace, input_commitment) = crate::note_commitment_opening::build_trace(
            &input_owner,
            input_value,
            &input_rho,
            &input_randomness,
        );
        let (output_note_trace, output_commitment) = crate::note_commitment_opening::build_trace(
            &output_note.owner,
            output_note.value,
            &output_note.rho,
            &output_note.randomness,
        );
        let mut source = source_fixture();
        source.commitment = input_commitment;
        source.leaf = output_leaf(
            source.commitment,
            source.kem_ciphertext,
            source.nonce,
            &source.ciphertext,
        );
        let (_, siblings, index, _) = test_fixture();
        let (_, root) = build_trace(&source.leaf, &siblings, index);
        let source_blocks = checked_source_leaf_blocks(&source).unwrap();
        let (base_trace, computed_root, _, nullifier) =
            build_source_key_note_nullifier_trace_with_width(
                &source_blocks,
                &source.commitment,
                &source.leaf,
                &siblings,
                index,
                &input_note_trace,
                &spend_secret,
                &kem_shared_secret,
                &input_rho,
                RDXL_TRACE_WIDTH,
                RDXL_TRACE_ROWS,
            );
        drop(input_note_trace);
        assert_eq!(computed_root, root);
        let mut statement = TransactionStatementV1::parse(&canonical_statement(root)).unwrap();
        statement.fee = fee;
        statement.nullifier = nullifier;
        statement.output.commitment = output_commitment;
        statement.output.leaf = output_leaf(
            statement.output.commitment,
            statement.output.kem_ciphertext,
            statement.output.nonce,
            &statement.output.ciphertext,
        );
        let statement_bytes = statement.serialize().unwrap();
        let mut trace = build_source_key_note_nullifier_output_trace(
            base_trace,
            input_value,
            &output_note,
            fee,
            &output_note_trace,
            &statement,
        );
        drop(output_note_trace);
        assert_eq!(trace.width, RDXL_TRACE_WIDTH);
        assert_eq!(KEY_NOTE_NULLIFIER_OUTPUT_ACTIVE_ROWS, 3504);
        assert_eq!(
            (KEY_NOTE_NULLIFIER_ACTIVE_ROWS..KEY_NOTE_NULLIFIER_OUTPUT_ACTIVE_ROWS)
                .filter(
                    |row| trace.values[row * trace.width + OUTPUT_NOTE_ACTIVE_OFFSET] == Val::ONE
                )
                .count(),
            NOTE_ROWS
        );
        let mut values = rdxl_statement_public_values(&statement_bytes, &statement).unwrap();
        let air = Depth64PathAir {
            public_value_count: values.len(),
            source_bound: true,
            note_bound: true,
            spend_owner_bound: true,
            nullifier_bound: true,
            output_note_balance_bound: true,
        };
        let report = p3_air::check_all_constraints(&air, &trace, &values, Some(20));
        assert!(report.is_ok(), "RDXL AIR failures: {:?}", report.failures);

        let output_row_start = KEY_NOTE_NULLIFIER_ACTIVE_ROWS * trace.width;
        let carry_index = output_row_start + BALANCE_CARRY_BITS_OFFSET;
        let saved_carry = trace.values[carry_index];
        trace.values[carry_index] = Val::ZERO;
        assert!(!p3_air::check_all_constraints(&air, &trace, &values, Some(20)).is_ok());
        trace.values[carry_index] = saved_carry;

        let input_value_bit_index = INPUT_VALUE_BITS_OFFSET;
        let saved_input_value_bit = trace.values[input_value_bit_index];
        trace.values[input_value_bit_index] = Val::ONE - saved_input_value_bit;
        assert!(!p3_air::check_all_constraints(&air, &trace, &values, Some(20)).is_ok());
        trace.values[input_value_bit_index] = saved_input_value_bit;

        let output_commitment_index = PUBLIC_ROOT_PREFIX_BYTES
            + crate::transaction_statement::STATEMENT_OUTPUT_COMMITMENT_BYTES_OFFSET;
        let saved_output_commitment_byte = values[output_commitment_index];
        values[output_commitment_index] += Val::ONE;
        assert!(!p3_air::check_all_constraints(&air, &trace, &values, Some(20)).is_ok());
        values[output_commitment_index] = saved_output_commitment_byte;

        let fee_index =
            PUBLIC_ROOT_PREFIX_BYTES + crate::transaction_statement::STATEMENT_FEE_BYTES_OFFSET;
        let saved_fee_byte = values[fee_index];
        values[fee_index] += Val::ONE;
        assert!(!p3_air::check_all_constraints(&air, &trace, &values, Some(20)).is_ok());
        values[fee_index] = saved_fee_byte;
        drop(trace);

        let mut unbalanced_statement = statement.clone();
        unbalanced_statement.fee += 1;
        assert_eq!(
            prove_source_key_note_nullifier_output_balance_depth64_path(
                &unbalanced_statement.serialize().unwrap(),
                &source,
                &spend_secret,
                &kem_shared_secret,
                input_value,
                &input_rho,
                &input_randomness,
                &siblings,
                index,
                &output_note,
            ),
            Err(Depth64PathProofError::UnbalancedValues)
        );
        let prove_started = Instant::now();
        let envelope = prove_source_key_note_nullifier_output_balance_depth64_path(
            &statement_bytes,
            &source,
            &spend_secret,
            &kem_shared_secret,
            input_value,
            &input_rho,
            &input_randomness,
            &siblings,
            index,
            &output_note,
        )
        .expect("valid output-note opening and balance proof");
        eprintln!(
            "RDXL64P1 prove API: {} envelope bytes in {:?}",
            envelope.len(),
            prove_started.elapsed()
        );
        assert_eq!(&envelope[..8], SOURCE_KEY_NOTE_NULLIFIER_OUTPUT_MAGIC);
        assert_eq!(
            verify_source_key_note_nullifier_output_balance_depth64_path(
                &envelope,
                &statement_bytes,
            ),
            Ok(statement)
        );
        assert!(
            verify_source_key_note_nullifier_depth64_path(&envelope, &statement_bytes).is_err()
        );
    }
}
