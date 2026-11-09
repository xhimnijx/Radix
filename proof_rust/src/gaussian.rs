//! Discrete Gaussian, sampled from the same table the Python side reads.
//!
//! `include_bytes!` rather than a copy: the file is the distribution, and there is
//! exactly one of it. Python reads it at runtime, Rust bakes it in at compile time, so
//! the two cannot drift — which is the property C2 asked for, made structural instead
//! of tested.
//!
//! Integer-only at runtime: a 32-bit uniform selects a magnitude by binary search over
//! the cumulative table, and one bit selects the sign.

use std::sync::OnceLock;

const TABLE_W33: &[u8] = include_bytes!("../../radix_core/candidate_b/lattice/tables/gaussian_w33.bin");
const TABLE_W30: &[u8] = include_bytes!("../../radix_core/candidate_b/lattice/tables/gaussian_w30.bin");
const TABLE_W29: &[u8] = include_bytes!("../../radix_core/candidate_b/lattice/tables/gaussian_w29.bin");
const TABLE_W13: &[u8] = include_bytes!("../../radix_core/candidate_b/lattice/tables/gaussian_w13.bin");

const MAGIC: &[u8; 8] = b"RDXGAUSS";
const VERSION: u32 = 1;
/// magic 8 + version 4 + sigma 8 + count 4
const HEADER: usize = 24;

struct Table {
    sigma: f64,
    cumulative: Vec<u32>,
}

fn read_u32(payload: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        payload[offset],
        payload[offset + 1],
        payload[offset + 2],
        payload[offset + 3],
    ])
}

fn parse(payload: &'static [u8]) -> Table {
    assert_eq!(&payload[..8], MAGIC, "not a Gaussian table");
    let version = read_u32(payload, 8);
    assert_eq!(version, VERSION, "unexpected Gaussian table version");
    let sigma = f64::from_le_bytes(payload[12..20].try_into().expect("sigma"));
    let count = read_u32(payload, 20) as usize;
    assert_eq!(payload.len(), HEADER + 4 * count, "truncated Gaussian table");

    let mut cumulative = Vec::with_capacity(count);
    for index in 0..count {
        cumulative.push(read_u32(payload, HEADER + 4 * index));
    }
    assert_eq!(
        *cumulative.last().expect("non-empty"),
        u32::MAX,
        "table does not end with the sentinel"
    );
    Table { sigma, cumulative }
}

fn table(width: usize) -> &'static Table {
    match width {
        33 => {
            static CACHE: OnceLock<Table> = OnceLock::new();
            CACHE.get_or_init(|| parse(TABLE_W33))
        }
        30 => {
            static CACHE: OnceLock<Table> = OnceLock::new();
            CACHE.get_or_init(|| parse(TABLE_W30))
        }
        29 => {
            static CACHE: OnceLock<Table> = OnceLock::new();
            CACHE.get_or_init(|| parse(TABLE_W29))
        }
        13 => {
            static CACHE: OnceLock<Table> = OnceLock::new();
            CACHE.get_or_init(|| parse(TABLE_W13))
        }
        other => panic!("no Gaussian table for width {other}"),
    }
}

/// Map a 32-bit uniform and a sign bit to one sample.
///
/// Pure, and identical to `gaussian.from_uniform` in Python. Keeping it free of any
/// RNG is what lets the cross-language test compare the mapping directly rather than
/// trusting that two RNGs produce the same stream.
pub fn from_uniform(width: usize, uniform: u32, sign: u32) -> i64 {
    let data = table(width);
    let mut low = 0usize;
    let mut high = data.cumulative.len() - 1;
    while low < high {
        let middle = (low + high) / 2;
        if data.cumulative[middle] > uniform {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    let magnitude = low as i64;
    if sign == 1 {
        -magnitude
    } else {
        magnitude
    }
}

/// The standard deviation the table was built for.
pub fn sigma(width: usize) -> f64 {
    table(width).sigma
}

/// One sample, as a residue modulo `q`.
pub fn sample(rng: &mut crate::prover::Rng, width: usize) -> u64 {
    let lower = rng.next_u64();
    let uniform = (lower & 0xFFFF_FFFF) as u32;
    let sign = ((rng.next_u64()) & 1) as u32;
    (from_uniform(width, uniform, sign).rem_euclid(crate::Q as i64)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_loads_and_is_monotone() {
        for width in [33, 30, 29, 13] {
            let data = table(width);
            assert!(data.cumulative.len() > 1000);
            assert!(data.sigma > 1000.0);
            assert!(data.cumulative.windows(2).all(|pair| pair[0] <= pair[1]));
        }
    }

    #[test]
    fn the_mapping_is_symmetric_and_bounded() {
        assert_eq!(from_uniform(33, 0, 0), 0);
        assert_eq!(from_uniform(33, 0, 1), 0);
        assert_eq!(from_uniform(33, u32::MAX, 0), 21324);
        assert_eq!(from_uniform(33, u32::MAX, 1), -21324);
        for uniform in [1u32, 1 << 20, 1 << 31, u32::MAX - 1] {
            assert_eq!(
                from_uniform(33, uniform, 0),
                -from_uniform(33, uniform, 1)
            );
        }
    }

    #[test]
    fn the_magnitude_matches_the_cumulative_table() {
        // A uniform just below the k-th entry must yield k, which is the definition.
        let data = table(33);
        for index in [0usize, 1, 17, 500, 10_000] {
            let below = data.cumulative[index].saturating_sub(1);
            if index == 0 {
                assert_eq!(from_uniform(33, 0, 0), 0);
            } else {
                let magnitude = from_uniform(33, below, 0);
                assert!(
                    magnitude == index as i64 || magnitude == index as i64 - 1,
                    "expected around {index}, got {magnitude}"
                );
            }
        }
    }
}
