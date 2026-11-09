//! Print the discrete-Gaussian mapping for a grid of uniforms, so Python can compare.
//!
//! The point is that `from_uniform` is a *pure* function: no RNG, no floating point, no
//! dependence on the order in which bits are consumed. If both languages map the same
//! uniform to the same integer across the whole grid, they are sampling the same
//! distribution — which is what C2's portability objection required and what a test of
//! "both verify each other's proofs" could never establish.

use radix_lattice::gaussian::from_uniform;

fn main() {
    // A fixed, reproducible grid: the boundaries, the centre, and a spread of values.
    let mut grid: Vec<u32> = vec![0, 1, 2, 3, 7, 255, 256, 65_535, 1 << 24, 1 << 31, u32::MAX - 1, u32::MAX];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..128 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        grid.push((state >> 32) as u32);
    }

    for width in [33usize, 29, 13] {
        for uniform in &grid {
            let positive = from_uniform(width, *uniform, 0);
            let negative = from_uniform(width, *uniform, 1);
            println!("{width} {uniform} {positive} {negative}");
        }
    }
}
