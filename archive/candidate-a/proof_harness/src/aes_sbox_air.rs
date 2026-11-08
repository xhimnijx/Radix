//! Reusable AIR gadget for the AES-256 substitution byte.
//!
//! The byte is split into high and low nibbles. Each nibble is represented by
//! an exact 16-way one-hot product of its four boolean input bits. The high
//! selector chooses one row of the AES S-box table; the low selector chooses
//! one value from that row. This AIR gadget only supplies the local S-box relation;
//! host helpers form round witnesses and the separate RDXL AIR constrains nine counter blocks, not full AES-GCM.

use p3_air::AirBuilder;
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

/// Standard AES substitution table, indexed by the input byte.
pub(crate) const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

pub(crate) const AES_SBOX_INPUT_BITS: usize = 8;
pub(crate) const AES_SBOX_OUTPUT_BITS: usize = 8;
pub(crate) const AES_SBOX_SELECTOR_COLUMNS: usize = 16;
pub(crate) const AES_SBOX_INTERMEDIATE_COLUMNS: usize = 16;
pub(crate) const AES_SBOX_WITNESS_COLUMNS: usize =
    2 * AES_SBOX_SELECTOR_COLUMNS + AES_SBOX_INTERMEDIATE_COLUMNS;

/// Host-side AES S-box lookup used to form witness output bits and table values.
#[inline]
pub(crate) fn sbox(input: u8) -> u8 {
    AES_SBOX[input as usize]
}

/// Expand an AES-256 key into all 15 round keys in byte-major order.
pub(crate) fn expand_aes256_key(key: &[u8; 32]) -> [u8; 240] {
    let mut expanded = [0u8; 240];
    expanded[..32].copy_from_slice(key);
    let mut rcon = 1u8;
    for word_index in 8..60 {
        let previous_word = (word_index - 1) * 4;
        let mut temp = [0u8; 4];
        temp.copy_from_slice(&expanded[previous_word..previous_word + 4]);
        if word_index % 8 == 0 {
            temp.rotate_left(1);
            for byte in &mut temp {
                *byte = sbox(*byte);
            }
            temp[0] ^= rcon;
            rcon = (rcon << 1) ^ if rcon & 0x80 == 0 { 0 } else { 0x1b };
        } else if word_index % 8 == 4 {
            for byte in &mut temp {
                *byte = sbox(*byte);
            }
        }
        let base_word = (word_index - 8) * 4;
        let target_word = word_index * 4;
        for byte in 0..4 {
            expanded[target_word + byte] = expanded[base_word + byte] ^ temp[byte];
        }
    }
    expanded
}

/// Compute all AES-256 states from the input block through the final round.
pub(crate) fn aes256_encrypt_round_states(
    expanded_key: &[u8; 240],
    block: &[u8; 16],
) -> [[u8; 16]; 16] {
    let mut states = [[0u8; 16]; 16];
    states[0] = *block;
    for byte in 0..16 {
        states[1][byte] = block[byte] ^ expanded_key[byte];
    }
    for round in 1..=14 {
        let substituted = states[round].map(sbox);
        let shifted = shift_rows(&substituted);
        let mixed = if round == 14 {
            shifted
        } else {
            mix_columns(&shifted)
        };
        for byte in 0..16 {
            states[round + 1][byte] = mixed[byte] ^ expanded_key[round * 16 + byte];
        }
    }
    states
}

/// Apply AES-256 MixColumns to one column-major state.
pub(crate) fn mix_columns(state: &[u8; 16]) -> [u8; 16] {
    let mut mixed = [0u8; 16];
    for column in 0..4 {
        let index = column * 4;
        let s = [
            state[index],
            state[index + 1],
            state[index + 2],
            state[index + 3],
        ];
        let doubled = s.map(mul2);
        let tripled = [
            doubled[0] ^ s[0],
            doubled[1] ^ s[1],
            doubled[2] ^ s[2],
            doubled[3] ^ s[3],
        ];
        mixed[index] = doubled[0] ^ tripled[1] ^ s[2] ^ s[3];
        mixed[index + 1] = s[0] ^ doubled[1] ^ tripled[2] ^ s[3];
        mixed[index + 2] = s[0] ^ s[1] ^ doubled[2] ^ tripled[3];
        mixed[index + 3] = tripled[0] ^ s[1] ^ s[2] ^ doubled[3];
    }
    mixed
}

pub(crate) fn shift_rows(state: &[u8; 16]) -> [u8; 16] {
    let mut shifted = [0u8; 16];
    for row in 0..4 {
        for column in 0..4 {
            shifted[row + 4 * column] = state[row + 4 * ((column + row) % 4)];
        }
    }
    shifted
}

#[inline]
pub(crate) fn mul2(value: u8) -> u8 {
    (value << 1) ^ if value & 0x80 == 0 { 0 } else { 0x1b }
}

/// Constrain one byte substitution using nibble one-hot selectors.
///
/// Bit columns are little-endian within each byte: input bit 0 is the least
/// significant bit, input bits 4..8 encode the high nibble, and output bit 0
/// is the least significant output bit. Selector entries are indexed by their
/// represented nibble value. `active` gates every Booleanity and lookup
/// relation, allowing the columns to be reused on inactive rows.
///
/// `row` is the current AIR row. The supplied offsets must identify disjoint
/// column slices of lengths 8 (input bits), 8 (output bits), 16 (high
/// selectors), 16 (low selectors), and 16 (intermediate values).
pub(crate) fn eval_constraints<AB: AirBuilder<F = BabyBear>>(
    builder: &mut AB,
    row: &[AB::Var],
    input_bits_offset: usize,
    output_bits_offset: usize,
    high_selector_offset: usize,
    low_selector_offset: usize,
    intermediate_offset: usize,
    active: AB::Expr,
) {
    let one = AB::Expr::ONE;

    let input_bits: [AB::Expr; AES_SBOX_INPUT_BITS] =
        core::array::from_fn(|bit| row[input_bits_offset + bit].into());
    let output_bits: [AB::Expr; AES_SBOX_OUTPUT_BITS] =
        core::array::from_fn(|bit| row[output_bits_offset + bit].into());

    for bit in input_bits.iter().chain(output_bits.iter()) {
        builder.assert_zero(active.clone() * bit.clone() * (bit.clone() - one.clone()));
    }

    // Each selector is exactly the product of the four literals matching its
    // nibble value, so boolean input bits imply a unique one-hot selector.
    for nibble in 0..16 {
        let high_product = (0..4).fold(AB::Expr::ONE, |product, bit| {
            let input_bit = input_bits[bit + 4].clone();
            let literal = if (nibble >> bit) & 1 == 1 {
                input_bit
            } else {
                one.clone() - input_bit
            };
            product * literal
        });
        let high_selector: AB::Expr = row[high_selector_offset + nibble].into();
        builder.assert_zero(active.clone() * (high_selector - high_product));

        let low_product = (0..4).fold(AB::Expr::ONE, |product, bit| {
            let input_bit = input_bits[bit].clone();
            let literal = if (nibble >> bit) & 1 == 1 {
                input_bit
            } else {
                one.clone() - input_bit
            };
            product * literal
        });
        let low_selector: AB::Expr = row[low_selector_offset + nibble].into();
        builder.assert_zero(active.clone() * (low_selector - low_product));
    }

    for low_nibble in 0..16 {
        let intermediate: AB::Expr = row[intermediate_offset + low_nibble].into();
        let selected_high_row = (0..16).fold(AB::Expr::ZERO, |sum, high_nibble| {
            let selector: AB::Expr = row[high_selector_offset + high_nibble].into();
            sum + selector * AB::Expr::from_u32(u32::from(AES_SBOX[high_nibble * 16 + low_nibble]))
        });
        builder.assert_zero(active.clone() * (intermediate - selected_high_row));
    }

    let output_byte = output_bits
        .iter()
        .enumerate()
        .fold(AB::Expr::ZERO, |value, (bit, output)| {
            value + output.clone() * AB::Expr::from_u32(1 << bit)
        });
    let selected_low_column = (0..16).fold(AB::Expr::ZERO, |sum, low_nibble| {
        let selector: AB::Expr = row[low_selector_offset + low_nibble].into();
        let intermediate: AB::Expr = row[intermediate_offset + low_nibble].into();
        sum + selector * intermediate
    });
    builder.assert_zero(active * (output_byte - selected_low_column));
}
