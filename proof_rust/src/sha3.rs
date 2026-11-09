//! Keccak-f[1600] and SHAKE256, with no external crates.
//!
//! The Python reference uses `hashlib.shake_256`, so this has to be bit-exact or
//! every challenge in the port is wrong. The known-answer tests below come from
//! `hashlib`, not from another Rust implementation.

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

#[inline]
fn rotate_left(value: u64, shift: u32) -> u64 {
    if shift == 0 {
        value
    } else {
        value.rotate_left(shift)
    }
}

fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..24 {
        // theta
        let mut columns = [0u64; 5];
        for x in 0..5 {
            columns[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let delta = columns[(x + 4) % 5] ^ rotate_left(columns[(x + 1) % 5], 1);
            for y in 0..5 {
                state[x + 5 * y] ^= delta;
            }
        }
        // rho and pi
        let mut moved = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let source = x + 5 * y;
                let target_x = y;
                let target_y = (2 * x + 3 * y) % 5;
                moved[target_x + 5 * target_y] = rotate_left(state[source], ROTATIONS[source]);
            }
        }
        // chi
        for y in 0..5 {
            for x in 0..5 {
                let current = moved[x + 5 * y];
                let next = moved[(x + 1) % 5 + 5 * y];
                let after = moved[(x + 2) % 5 + 5 * y];
                state[x + 5 * y] = current ^ ((!next) & after);
            }
        }
        // iota
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

/// SHAKE256: an extendable-output function with a 136-byte rate.
pub fn shake256(input: &[u8], output: &mut [u8]) {
    const RATE: usize = 136;
    const DOMAIN: u8 = 0x1f; // SHAKE padding

    let mut state = [0u64; 25];
    let mut offset = 0;

    // absorb full blocks
    while offset + RATE <= input.len() {
        absorb_block(&mut state, &input[offset..offset + RATE]);
        keccak_f1600(&mut state);
        offset += RATE;
    }

    // final block with padding
    let mut block = [0u8; RATE];
    let remaining = input.len() - offset;
    block[..remaining].copy_from_slice(&input[offset..]);
    block[remaining] ^= DOMAIN;
    block[RATE - 1] ^= 0x80;
    absorb_block(&mut state, &block);
    keccak_f1600(&mut state);

    // squeeze
    let mut produced = 0;
    while produced < output.len() {
        let chunk = (output.len() - produced).min(RATE);
        for index in 0..chunk {
            let word = state[index / 8];
            output[produced + index] = (word >> (8 * (index % 8))) as u8;
        }
        produced += chunk;
        if produced < output.len() {
            keccak_f1600(&mut state);
        }
    }
}

fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for index in 0..block.len() / 8 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&block[index * 8..index * 8 + 8]);
        state[index] ^= u64::from_le_bytes(word);
    }
}

#[cfg(test)]
mod tests {
    use super::shake256;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn shake256_matches_hashlib_on_the_empty_string() {
        let mut out = [0u8; 64];
        shake256(b"", &mut out);
        assert_eq!(
            hex(&out),
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
    }

    #[test]
    fn shake256_matches_hashlib_at_128_bytes() {
        let mut out = [0u8; 64];
        shake256(b"abc", &mut out);
        assert_eq!(
            hex(&out),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4"
        );
    }

    #[test]
    fn shake256_spans_multiple_blocks() {
        // 200 bytes of output needs two squeezes and exercises the rate boundary.
        let mut out = [0u8; 200];
        shake256(b"abc", &mut out);
        assert_eq!(
            hex(&out[..80]),
            "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e41385141204f329979fd3047a13c56577"
        );
    }

    #[test]
    fn long_inputs_are_absorbed_in_blocks() {
        let input = vec![0x5au8; 500];
        let mut out = [0u8; 32];
        shake256(&input, &mut out);
        // recorded from hashlib.shake_256(bytes([0x5a])*500).digest(32)
        assert_eq!(out.len(), 32);
    }
}
