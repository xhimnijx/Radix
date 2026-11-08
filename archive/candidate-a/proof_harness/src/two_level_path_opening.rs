//! Standalone proof of a private, exact two-node Candidate-A path.
//!
//! Proves `root = H(1, H(0, leaf, sibling0), sibling1)` with the two private
//! direction bits selecting left/right order. This is only a linked depth-2
//! subrelation; it is not depth-64 membership or a transaction proof.

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
const FRAME_BYTES: usize = 169;
const SHAKE_RATE_BYTES: usize = 136;
const RATE_LIMBS: usize = SHAKE_RATE_BYTES / 2;
const FULL_PERMUTATIONS: usize = 5;
const DUMMY_PARTIAL_ROWS: usize = 8;
const TRACE_ROWS: usize = FULL_PERMUTATIONS * NUM_ROUNDS + DUMMY_PARTIAL_ROWS;
const OUTPUT_BITS: usize = 25 * 64;
const CURRENT_BYTES: usize = NUM_KECCAK_COLS;
const CURRENT_BITS: usize = CURRENT_BYTES + DIGEST_BYTES;
const SIBLING_BYTES: usize = CURRENT_BITS + DIGEST_BYTES * 8;
const SIBLING_BITS: usize = SIBLING_BYTES + DIGEST_BYTES;
const DIRECTION: usize = SIBLING_BITS + DIGEST_BYTES * 8;
const STAGE_BITS: usize = DIRECTION + 1;
const PHASE: usize = STAGE_BITS + 3;
const OUTPUT_BITS_OFFSET: usize = PHASE + 1;
const TRACE_WIDTH: usize = OUTPUT_BITS_OFFSET + OUTPUT_BITS;
const MAGIC: &[u8; 8] = b"RDXZ2P01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 8 + 2 + DIGEST_BYTES + 4;
const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES + MAX_PROOF_BYTES;
const TAG: &[u8] = b"radix/tree-node/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TwoLevelPathStatementV1 {
    pub root: [u8; DIGEST_BYTES],
}

#[derive(Debug, PartialEq, Eq)]
pub enum TwoLevelPathProofError {
    RootMismatch,
    Malformed(&'static str),
    Backend(String),
}

impl fmt::Display for TwoLevelPathProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMismatch => {
                write!(f, "computed two-level path root differs from expected root")
            }
            Self::Malformed(message) => write!(f, "malformed two-level path proof: {message}"),
            Self::Backend(message) => {
                write!(f, "two-level path proof backend rejected proof: {message}")
            }
        }
    }
}
impl Error for TwoLevelPathProofError {}

struct TwoLevelPathAir;

impl BaseAir<Val> for TwoLevelPathAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }
    fn num_public_values(&self) -> usize {
        DIGEST_BYTES
    }
}

impl<AB> Air<AB> for TwoLevelPathAir
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
        let phase: AB::Expr = row[PHASE].into();
        let one = AB::Expr::ONE;

        // Output lanes are bit-decomposed on every row. This is the authenticated
        // bridge that passes node 0's digest into node 1 as a byte string.
        for y in 0..5 {
            for x in 0..5 {
                let lane = y * 5 + x;
                for limb in 0..4 {
                    let mut reconstructed = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let b: AB::Expr =
                            row[OUTPUT_BITS_OFFSET + lane * 64 + limb * 16 + bit].into();
                        builder.assert_zero(b.clone() * (b.clone() - one.clone()));
                        reconstructed += b * AB::Expr::from_u32(1 << bit);
                    }
                    let actual: AB::Expr = keccak.a_prime_prime_prime(y, x, limb).into();
                    builder.assert_zero(reconstructed - actual);
                }
            }
        }

        // Private state is byte-constrained; the active direction and phase/stage
        // bits are boolean. Stages 0..5 are represented as 000,001,010,011,100,101.
        let mut stage = [AB::Expr::ZERO; 3];
        for i in 0..3 {
            stage[i] = row[STAGE_BITS + i].into();
            builder.assert_zero(stage[i].clone() * (stage[i].clone() - one.clone()));
        }
        // Disallow the unused encodings 110 and 111.
        builder.assert_zero(stage[2].clone() * stage[1].clone());
        builder.assert_zero(phase.clone() * (phase.clone() - one.clone()));
        builder.assert_zero(phase.clone() - stage[0].clone());
        let direction: AB::Expr = row[DIRECTION].into();
        builder.assert_zero(direction.clone() * (direction.clone() - one.clone()));
        for (byte_offset, bits_offset) in
            [(CURRENT_BYTES, CURRENT_BITS), (SIBLING_BYTES, SIBLING_BITS)]
        {
            for index in 0..DIGEST_BYTES {
                let mut reconstructed = AB::Expr::ZERO;
                for bit in 0..8 {
                    let b: AB::Expr = row[bits_offset + index * 8 + bit].into();
                    builder.assert_zero(b.clone() * (b.clone() - one.clone()));
                    reconstructed += b * AB::Expr::from_u32(1 << bit);
                }
                let byte: AB::Expr = row[byte_offset + index].into();
                builder.assert_zero(reconstructed - byte);
            }
        }

        // Pin the phase/level schedule to an exact row-ordered stage counter. It
        // begins at node0/block0, advances only on a real Keccak final round, and
        // finishes in the 8-row dummy continuation after five full permutations.
        builder.when_first_row().assert_zero(stage[0].clone());
        builder.when_first_row().assert_zero(stage[1].clone());
        builder.when_first_row().assert_zero(stage[2].clone());
        builder.when_first_row().assert_zero(phase.clone());
        builder
            .when_last_row()
            .assert_zero(stage[0].clone() - one.clone());
        builder.when_last_row().assert_zero(stage[1].clone());
        builder
            .when_last_row()
            .assert_zero(stage[2].clone() - one.clone());
        let not_final = transition.clone() * (one.clone() - final_step.clone());
        for i in 0..3 {
            let next_bit: AB::Expr = next[STAGE_BITS + i].into();
            builder
                .when(not_final.clone())
                .assert_zero(next_bit.clone() - stage[i].clone());
        }
        let next_b0: AB::Expr = next[STAGE_BITS].into();
        let next_b1: AB::Expr = next[STAGE_BITS + 1].into();
        let next_b2: AB::Expr = next[STAGE_BITS + 2].into();
        builder
            .when(transition.clone() * final_step.clone())
            .assert_zero(next_b0.clone() - (one.clone() - stage[0].clone()));
        builder
            .when(transition.clone() * final_step.clone())
            .assert_zero(
                next_b1
                    - (stage[1].clone() + stage[0].clone()
                        - stage[1].clone() * stage[0].clone() * AB::Expr::from_u32(2)),
            );
        builder
            .when(transition.clone() * final_step.clone())
            .assert_zero(
                next_b2
                    - (stage[2].clone() + stage[1].clone() * stage[0].clone()
                        - stage[2].clone()
                            * stage[1].clone()
                            * stage[0].clone()
                            * AB::Expr::from_u32(2)),
            );
        let next_phase: AB::Expr = next[PHASE].into();
        builder
            .when(transition.clone())
            .assert_zero(next_phase - next_b0);

        // Only the node0->node1 boundary may replace current digest, sibling, and
        // direction. At that boundary, current digest bits are copied from the
        // output-bit columns of node0's phase1 final row.
        let node0_to_node1 = final_step.clone()
            * (one.clone() - stage[2].clone())
            * (one.clone() - stage[1].clone())
            * stage[0].clone();
        let boundary = transition.clone() * node0_to_node1.clone();
        let stay = transition.clone() * (one.clone() - node0_to_node1);
        for index in 0..DIGEST_BYTES {
            let current: AB::Expr = row[CURRENT_BYTES + index].into();
            let next_current: AB::Expr = next[CURRENT_BYTES + index].into();
            builder
                .when(stay.clone())
                .assert_zero(next_current.clone() - current);
            let sibling: AB::Expr = row[SIBLING_BYTES + index].into();
            let next_sibling: AB::Expr = next[SIBLING_BYTES + index].into();
            builder
                .when(stay.clone())
                .assert_zero(next_sibling - sibling);
            for bit in 0..8 {
                let current_bit: AB::Expr = row[CURRENT_BITS + index * 8 + bit].into();
                let next_current_bit: AB::Expr = next[CURRENT_BITS + index * 8 + bit].into();
                builder
                    .when(stay.clone())
                    .assert_zero(next_current_bit.clone() - current_bit);
                let sibling_bit: AB::Expr = row[SIBLING_BITS + index * 8 + bit].into();
                let next_sibling_bit: AB::Expr = next[SIBLING_BITS + index * 8 + bit].into();
                builder
                    .when(stay.clone())
                    .assert_zero(next_sibling_bit - sibling_bit);
                let output_bit: AB::Expr =
                    row[OUTPUT_BITS_OFFSET + (index / 8) * 64 + (index % 8) * 8 + bit].into();
                builder
                    .when(boundary.clone())
                    .assert_zero(next_current_bit - output_bit);
            }
            let mut output_byte = AB::Expr::ZERO;
            for bit in 0..8 {
                let output_bit: AB::Expr =
                    row[OUTPUT_BITS_OFFSET + (index / 8) * 64 + (index % 8) * 8 + bit].into();
                output_byte += output_bit * AB::Expr::from_u32(1 << bit);
            }
            builder
                .when(boundary.clone())
                .assert_zero(next_current - output_byte);
        }
        let next_direction: AB::Expr = next[DIRECTION].into();
        builder.when(stay).assert_zero(next_direction - direction);

        // A node's left/right child encoding is selected by its private direction
        // bit. Levels are fixed by stage: 0 for stages 0/1, 1 for stages 2..5.
        let node1: AB::Expr = stage[1].clone() + stage[2].clone();
        let first_block_start = first_step.clone() * (one.clone() - phase.clone());
        for limb in 0..RATE_LIMBS {
            let low = frame_byte::<AB>(row, limb * 2, node1.clone());
            let high = frame_byte::<AB>(row, limb * 2 + 1, node1.clone());
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

        // At phase0->phase1, absorb exactly the second block of the same framed
        // hash. This also covers capacity lanes, which remain unchanged except XOR.
        let second_block_boundary =
            transition.clone() * final_step.clone() * (one.clone() - phase.clone());
        for y in 0..5 {
            for x in 0..5 {
                let lane = y * 5 + x;
                for limb in 0..4 {
                    let mut expected = AB::Expr::ZERO;
                    for bit in 0..16 {
                        let output_bit: AB::Expr =
                            row[OUTPUT_BITS_OFFSET + lane * 64 + limb * 16 + bit].into();
                        let state_byte = lane * 8 + limb * 2 + bit / 8;
                        let block_bit = frame_bit::<AB>(
                            next,
                            SHAKE_RATE_BYTES + state_byte,
                            bit % 8,
                            node1.clone(),
                        );
                        let xor = output_bit.clone() + block_bit.clone()
                            - output_bit * block_bit * AB::Expr::from_u32(2);
                        expected += xor * AB::Expr::from_u32(1 << bit);
                    }
                    builder
                        .when(second_block_boundary.clone())
                        .assert_zero(next_keccak.preimage[y][x][limb] - expected);
                }
            }
        }

        // The public root is bound exclusively to stage3 (node1, phase1) output.
        let stage3 = (one.clone() - stage[2].clone()) * stage[1].clone() * stage[0].clone();
        let root_selector = final_step * stage3;
        for limb in 0..(DIGEST_BYTES / 2) {
            let lo: AB::Expr = builder.public_values()[limb * 2].into();
            let hi: AB::Expr = builder.public_values()[limb * 2 + 1].into();
            let actual: AB::Expr = row[output_limb(limb)].into();
            builder
                .when(root_selector.clone())
                .assert_zero(actual - (lo + hi * AB::Expr::from_u32(256)));
        }
    }
}

fn frame_byte<AB: AirBuilder<F = Val>>(
    row: &[AB::Var],
    offset: usize,
    node1: AB::Expr,
) -> AB::Expr {
    if offset < FRAME_BYTES {
        match offset {
            32 => node1,
            37..=100 => {
                let index = offset - 37;
                let cur: AB::Expr = row[CURRENT_BYTES + index].into();
                let sib: AB::Expr = row[SIBLING_BYTES + index].into();
                let dir: AB::Expr = row[DIRECTION].into();
                cur.clone() + dir.clone() * (sib - cur)
            }
            105..=168 => {
                let index = offset - 105;
                let cur: AB::Expr = row[CURRENT_BYTES + index].into();
                let sib: AB::Expr = row[SIBLING_BYTES + index].into();
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

fn frame_bit<AB: AirBuilder<F = Val>>(
    row: &[AB::Var],
    offset: usize,
    bit: usize,
    node1: AB::Expr,
) -> AB::Expr {
    if offset < FRAME_BYTES {
        match offset {
            32 => {
                if bit == 0 {
                    node1
                } else {
                    AB::Expr::ZERO
                }
            }
            37..=100 => {
                let index = offset - 37;
                let cur: AB::Expr = row[CURRENT_BITS + index * 8 + bit].into();
                let sib: AB::Expr = row[SIBLING_BITS + index * 8 + bit].into();
                let dir: AB::Expr = row[DIRECTION].into();
                cur.clone() + dir.clone() * (sib - cur)
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

fn candidate_frame(level: u8, left: &[u8; 64], right: &[u8; 64]) -> [u8; FRAME_BYTES] {
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
    let final_row = &trace.values[(NUM_ROUNDS - 1) * NUM_KECCAK_COLS..NUM_ROUNDS * NUM_KECCAK_COLS];
    let cols: &KeccakCols<Val> = final_row.borrow();
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

fn path_inputs(
    leaf: &[u8; 64],
    sibling0: &[u8; 64],
    sibling1: &[u8; 64],
    direction0: bool,
    direction1: bool,
) -> (
    [u64; 25],
    [u64; 25],
    [u64; 25],
    [u64; 25],
    [u64; 25],
    [u64; 25],
) {
    fn order<'a>(
        current: &'a [u8; 64],
        sibling: &'a [u8; 64],
        direction: bool,
    ) -> (&'a [u8; 64], &'a [u8; 64]) {
        if direction {
            (sibling, current)
        } else {
            (current, sibling)
        }
    }
    let (left0, right0) = order(leaf, sibling0, direction0);
    let frame0 = candidate_frame(0, left0, right0);
    let first0 = block_state(&frame0, 0);
    let second0 = block_state(&frame0, 1);
    let input0_second = xor_states(state_after_one(&first0), second0);
    // Host-side KAT aid to obtain the linked child for trace generation.
    let full0 = generate_trace_rows::<Val>(vec![first0, input0_second], 0);
    let row =
        &full0.values[(2 * NUM_ROUNDS - 1) * NUM_KECCAK_COLS..2 * NUM_ROUNDS * NUM_KECCAK_COLS];
    let cols: &KeccakCols<Val> = row.borrow();
    let child: [u8; 64] = core::array::from_fn(|i| {
        let limb = i / 2;
        let v = cols
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .as_canonical_u32() as u16;
        v.to_le_bytes()[i % 2]
    });
    let (left1, right1) = order(&child, sibling1, direction1);
    let frame1 = candidate_frame(1, left1, right1);
    let first1 = block_state(&frame1, 0);
    let second1 = block_state(&frame1, 1);
    let input1_second = xor_states(state_after_one(&first1), second1);
    (
        first0,
        input0_second,
        first1,
        input1_second,
        first1,
        xor_states(state_after_one(&first1), second1),
    )
}

fn populate_state(row: &mut [Val], current: &[u8; 64], sibling: &[u8; 64], direction: bool) {
    for i in 0..64 {
        row[CURRENT_BYTES + i] = Val::from_u32(u32::from(current[i]));
        row[SIBLING_BYTES + i] = Val::from_u32(u32::from(sibling[i]));
        for b in 0..8 {
            row[CURRENT_BITS + i * 8 + b] = Val::from_u32(u32::from((current[i] >> b) & 1));
            row[SIBLING_BITS + i * 8 + b] = Val::from_u32(u32::from((sibling[i] >> b) & 1));
        }
    }
    row[DIRECTION] = Val::from_u32(u32::from(direction));
}

fn build_trace(
    leaf: &[u8; 64],
    sibling0: &[u8; 64],
    sibling1: &[u8; 64],
    direction0: bool,
    direction1: bool,
) -> (RowMajorMatrix<Val>, [u8; 64]) {
    let (first0, second0, first1, second1, dummy0, dummy1) =
        path_inputs(leaf, sibling0, sibling1, direction0, direction1);
    let full = generate_trace_rows::<Val>(vec![first0, second0, first1, second1, dummy0], 0);
    let partial = generate_trace_rows::<Val>(vec![dummy1], 0);
    let mut trace = vec![Val::ZERO; TRACE_ROWS * TRACE_WIDTH];
    for i in 0..(FULL_PERMUTATIONS * NUM_ROUNDS) {
        trace[i * TRACE_WIDTH..i * TRACE_WIDTH + NUM_KECCAK_COLS]
            .copy_from_slice(&full.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS]);
    }
    for i in 0..DUMMY_PARTIAL_ROWS {
        let dst = (FULL_PERMUTATIONS * NUM_ROUNDS + i) * TRACE_WIDTH;
        trace[dst..dst + NUM_KECCAK_COLS]
            .copy_from_slice(&partial.values[i * NUM_KECCAK_COLS..(i + 1) * NUM_KECCAK_COLS]);
    }
    let child = {
        let i = 2 * NUM_ROUNDS - 1;
        let cols: &KeccakCols<Val> =
            trace[i * TRACE_WIDTH..i * TRACE_WIDTH + NUM_KECCAK_COLS].borrow();
        core::array::from_fn(|j| {
            let limb = j / 2;
            let v = cols
                .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
                .as_canonical_u32() as u16;
            v.to_le_bytes()[j % 2]
        })
    };
    let (current0, current1) = (leaf, &child);
    for row_index in 0..TRACE_ROWS {
        let start = row_index * TRACE_WIDTH;
        let row = &mut trace[start..start + TRACE_WIDTH];
        let in_node1 = row_index >= 2 * NUM_ROUNDS;
        if in_node1 {
            populate_state(row, current1, sibling1, direction1);
        } else {
            populate_state(row, current0, sibling0, direction0);
        }
        let stage = if row_index < NUM_ROUNDS {
            0
        } else if row_index < 2 * NUM_ROUNDS {
            1
        } else if row_index < 3 * NUM_ROUNDS {
            2
        } else if row_index < 4 * NUM_ROUNDS {
            3
        } else if row_index < 5 * NUM_ROUNDS {
            4
        } else {
            5
        };
        for i in 0..3 {
            row[STAGE_BITS + i] = Val::from_u32(((stage >> i) & 1) as u32);
        }
        row[PHASE] = Val::from_u32((stage & 1) as u32);
        let mut output_bits = [0u32; OUTPUT_BITS];
        {
            let cols: &KeccakCols<Val> = row[..NUM_KECCAK_COLS].borrow();
            for y in 0..5 {
                for x in 0..5 {
                    let lane = y * 5 + x;
                    for limb in 0..4 {
                        let v = cols.a_prime_prime_prime(y, x, limb).as_canonical_u32();
                        for bit in 0..16 {
                            output_bits[lane * 64 + limb * 16 + bit] = (v >> bit) & 1;
                        }
                    }
                }
            }
        }
        for (index, bit) in output_bits.into_iter().enumerate() {
            row[OUTPUT_BITS_OFFSET + index] = Val::from_u32(bit);
        }
    }
    let root_row = (3 * NUM_ROUNDS + NUM_ROUNDS - 1) * TRACE_WIDTH;
    let cols: &KeccakCols<Val> = trace[root_row..root_row + NUM_KECCAK_COLS].borrow();
    let root = core::array::from_fn(|i| {
        let limb = i / 2;
        let v = cols
            .a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4)
            .as_canonical_u32() as u16;
        v.to_le_bytes()[i % 2]
    });
    // At the stage1->stage2 transition, the *next* row must carry this digest.
    let boundary_next = 2 * NUM_ROUNDS * TRACE_WIDTH;
    populate_state(
        &mut trace[boundary_next..boundary_next + TRACE_WIDTH],
        &child,
        sibling1,
        direction1,
    );
    (RowMajorMatrix::new(trace, TRACE_WIDTH), root)
}

fn public_values(root: &[u8; 64]) -> Vec<Val> {
    root.iter().map(|b| Val::from_u32(u32::from(*b))).collect()
}

fn encode(root: &[u8; 64], proof: &Proof<Stark>) -> Result<Vec<u8>, TwoLevelPathProofError> {
    let payload =
        postcard::to_allocvec(proof).map_err(|e| TwoLevelPathProofError::Backend(e.to_string()))?;
    if payload.is_empty() || payload.len() > MAX_PROOF_BYTES {
        return Err(TwoLevelPathProofError::Malformed(
            "proof size out of bounds",
        ));
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}
fn decode(bytes: &[u8]) -> Result<([u8; 64], Proof<Stark>), TwoLevelPathProofError> {
    if bytes.len() < HEADER_BYTES {
        return Err(TwoLevelPathProofError::Malformed("truncated envelope"));
    }
    if bytes.len() > HEADER_BYTES + MAX_PROOF_BYTES {
        return Err(TwoLevelPathProofError::Malformed(
            "envelope exceeds size limit",
        ));
    }
    if &bytes[..8] != MAGIC {
        return Err(TwoLevelPathProofError::Malformed("wrong magic"));
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION {
        return Err(TwoLevelPathProofError::Malformed("unsupported version"));
    }
    let root = bytes[10..74].try_into().unwrap();
    let len = u32::from_le_bytes(bytes[74..78].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_PROOF_BYTES || bytes.len() != HEADER_BYTES + len {
        return Err(TwoLevelPathProofError::Malformed("proof length mismatch"));
    }
    let payload = &bytes[HEADER_BYTES..];
    let proof: Proof<Stark> = std::panic::catch_unwind(AssertUnwindSafe(|| {
        crate::bounded_postcard::from_proof_bytes(payload)
    }))
    .map_err(|_| TwoLevelPathProofError::Malformed("proof deserializer panicked"))?
    .map_err(|_| TwoLevelPathProofError::Malformed("invalid proof serialization"))?;
    let canonical = postcard::to_extend(
        &proof,
        crate::canonical_postcard::CanonicalBytes::new(payload),
    )
    .map_err(|e| TwoLevelPathProofError::Backend(e.to_string()))?;
    if !canonical.matches_exactly() {
        return Err(TwoLevelPathProofError::Malformed(
            "non-canonical proof serialization",
        ));
    }
    Ok((root, proof))
}

/// Prove the exact path `root = H(1, H(0, leaf, sibling0), sibling1)`.
/// Directions are private (`false`: current is left; `true`: current is right).
/// `expected_root` is an explicit caller-provided public statement, not inferred from proof bytes.
pub fn prove_two_level_path(
    leaf: &[u8; 64],
    sibling0: &[u8; 64],
    sibling1: &[u8; 64],
    direction0: bool,
    direction1: bool,
    expected_root: &[u8; 64],
) -> Result<Vec<u8>, TwoLevelPathProofError> {
    let (trace, computed_root) = build_trace(leaf, sibling0, sibling1, direction0, direction1);
    if &computed_root != expected_root {
        return Err(TwoLevelPathProofError::RootMismatch);
    }
    let config = amount_opening::make_config();
    let proof = prove(
        &config,
        &TwoLevelPathAir,
        trace,
        &public_values(expected_root),
    )
    .map_err(|e| TwoLevelPathProofError::Backend(e.to_string()))?;
    encode(expected_root, &proof)
}

/// Verify against an explicit expected root supplied by the caller.
pub fn verify_two_level_path(
    bytes: &[u8],
    expected_root: &[u8; 64],
) -> Result<TwoLevelPathStatementV1, TwoLevelPathProofError> {
    let (root, proof) = decode(bytes)?;
    if &root != expected_root {
        return Err(TwoLevelPathProofError::RootMismatch);
    }
    let config = amount_opening::make_config();
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        verify(
            &config,
            &TwoLevelPathAir,
            &proof,
            &public_values(expected_root),
        )
    }))
    .map_err(|_| TwoLevelPathProofError::Malformed("proof verifier panicked"))?
    .map_err(|e| TwoLevelPathProofError::Backend(e.to_string()))?;
    Ok(TwoLevelPathStatementV1 { root })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_node_opening;

    fn from_hex(text: &str) -> [u8; 64] {
        core::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    #[test]
    fn proves_known_two_node_path_and_cross_checks_node_zero() {
        let leaf = core::array::from_fn(|i| i as u8);
        let sibling0 = core::array::from_fn(|i| (64 + i) as u8);
        let sibling1 = core::array::from_fn(|i| (128 + i) as u8);
        let child = from_hex(
            "9cb65318ced9008e15b82ec9ee833ee059fc43f8c6242cd0ead92412c610503c8a2876855475d78cdbfb7e9b05f6748946bce01d86bc6778c880c2026d159862",
        );
        let root = from_hex(
            "8f301c1895c7f6ccf0e0729065e54f9b941675557a4bb2b8285e4010fc47a1fd0ddebb6e8c83b24b1bde8f66f3c334294d1150ce9ec58dd6bead8e67ee934fdf",
        );
        let node_proof = tree_node_opening::prove_tree_node(0, &sibling0, &leaf).unwrap();
        assert_eq!(
            tree_node_opening::verify_tree_node(&node_proof).unwrap().1,
            child
        );
        let proof = prove_two_level_path(&leaf, &sibling0, &sibling1, true, false, &root).unwrap();
        assert_eq!(verify_two_level_path(&proof, &root).unwrap().root, root);

        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(verify_two_level_path(&proof, &wrong_root).is_err());
        let mut bad_magic = proof.clone();
        bad_magic[0] ^= 1;
        assert!(verify_two_level_path(&bad_magic, &root).is_err());
        let mut truncated = proof.clone();
        truncated.pop();
        assert!(verify_two_level_path(&truncated, &root).is_err());
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(verify_two_level_path(&trailing, &root).is_err());
        let mut mutated_payload = proof;
        let last = mutated_payload.len() - 1;
        mutated_payload[last] ^= 1;
        assert!(verify_two_level_path(&mutated_payload, &root).is_err());
    }

    #[test]
    fn rejects_wrong_path_root_and_direction() {
        let leaf = core::array::from_fn(|i| i as u8);
        let sibling0 = core::array::from_fn(|i| (64 + i) as u8);
        let sibling1 = core::array::from_fn(|i| (128 + i) as u8);
        let root = from_hex(
            "8f301c1895c7f6ccf0e0729065e54f9b941675557a4bb2b8285e4010fc47a1fd0ddebb6e8c83b24b1bde8f66f3c334294d1150ce9ec58dd6bead8e67ee934fdf",
        );
        let mut wrong_path = sibling1;
        wrong_path[3] ^= 1;
        assert_eq!(
            prove_two_level_path(&leaf, &sibling0, &wrong_path, true, false, &root),
            Err(TwoLevelPathProofError::RootMismatch)
        );
        assert_eq!(
            prove_two_level_path(&leaf, &sibling0, &sibling1, false, false, &root),
            Err(TwoLevelPathProofError::RootMismatch)
        );
        assert_eq!(
            prove_two_level_path(&leaf, &sibling0, &sibling1, true, true, &root),
            Err(TwoLevelPathProofError::RootMismatch)
        );
    }
}
