//! Timing and cross-language checksum for the lattice arithmetic.
//!
//! The checksum is computed from the same 64-bit LCG the Python reference uses,
//! so `experiments/rust_crosscheck.py` can compute the identical value and confirm
//! that the two implementations agree bit for bit.

use radix_lattice::{mul_crt, mul_naive, norm_inf, Poly, D, Q};
use std::time::Instant;

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn poly(&mut self) -> Poly {
        let mut out = [0u64; D];
        for value in out.iter_mut() {
            *value = self.next() % Q;
        }
        out
    }
}

fn checksum(poly: &Poly) -> u64 {
    let mut total = 0u64;
    for &value in poly.iter() {
        total = total.wrapping_mul(31).wrapping_add(value);
    }
    total
}

fn bench(label: &str, rounds: usize, mut body: impl FnMut()) -> f64 {
    let start = Instant::now();
    for _ in 0..rounds {
        body();
    }
    let elapsed = start.elapsed().as_secs_f64() * 1e6 / rounds as f64;
    println!("{label:>12}: {elapsed:>8.1} us per multiplication");
    elapsed
}

fn main() {
    let mut rng = Lcg(11);
    let a = rng.poly();
    let b = rng.poly();

    println!("q = {Q}, d = {D}");
    println!("checksum(mul_crt(a, b)) = {:#018x}", checksum(&mul_crt(&a, &b)));
    println!("checksum(mul_naive(a, b)) = {:#018x}", checksum(&mul_naive(&a, &b)));
    println!("max |a| = {}", norm_inf(&a));

    let rounds = 2000;
    let crt = bench("mul_crt", rounds, || {
        std::hint::black_box(mul_crt(&a, &b));
    });
    let naive = bench("mul_naive", rounds / 20, || {
        std::hint::black_box(mul_naive(&a, &b));
    });
    println!("\nCRT speedup over naive: {:.1}x", naive / crt);
    println!("Python reference: ntt 1.0 ms, crt 3.2 ms, naive 2.0 ms (prototype q)");
}
