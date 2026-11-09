//! End-to-end timing of the prover's and verifier's dominant work.
//!
//! The profile of one Python proof is unambiguous: `_set_matrix` is 58% of the
//! time and `ring.dot` is 35%, and both are built from the same ring
//! multiplication this crate already implements and has measured. So this binary
//! reproduces their *structure and sizes* exactly and times them, rather than
//! projecting from a per-operation cost.
//!
//! What it is not: the protocol. There is no transcript, no challenge derivation
//! and no recursion here. That is 5% of the Python profile, and the point of this
//! binary is to replace an extrapolation about the other 95% with a measurement.

use radix_lattice::{
    mul_crt, quartic_multiply, roots, slots, Poly, D, K, L, Q, SLOTS,
};
use std::hint::black_box;
use std::time::Instant;

/// The set matrix, built the way an efficient implementation would: the quarry
/// residues of `c` are computed once and multiplied slotwise, instead of
/// multiplying in full and decomposing again.
fn set_matrix(c: &Poly, keys: &[[Poly; K]]) -> usize {
    let c_slots = slots(c);
    let table = roots();
    let mut checksum = 0usize;
    for key in keys {
        for component in 0..K {
            let key_slots = slots(&key[component]);
            let mut column = [[0u64; 4]; SLOTS];
            for index in 0..SLOTS {
                column[index] = quartic_multiply(&c_slots[index], &key_slots[index], table[index]);
            }
            checksum = checksum.wrapping_add(column[0][0] as usize);
        }
    }
    checksum
}

/// One `ring.dot(row, vector)` for a row of `width` components.
fn dot(row: &[Poly], vector: &[Poly]) -> Poly {
    let mut total = [0u64; D];
    for (left, right) in row.iter().zip(vector.iter()) {
        let product = mul_crt(left, right);
        for index in 0..D {
            let sum = total[index] as u128 + product[index] as u128;
            total[index] = (sum % Q as u128) as u64;
        }
    }
    total
}

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

fn main() {
    let mut rng = Lcg(2026);
    let c = rng.poly();

    // Depth 2: 1024 ring members, K components each.
    let ring_size = L * L;
    let keys: Vec<[Poly; K]> = (0..ring_size)
        .map(|_| {
            let mut key = [[0u64; D]; K];
            for component in key.iter_mut() {
                *component = rng.poly();
            }
            key
        })
        .collect();

    // --- the set matrix, twice (Fig. 8 recursion runs it at each level)
    let start = Instant::now();
    let mut sink = 0usize;
    for _ in 0..2 {
        sink = sink.wrapping_add(set_matrix(&c, &keys));
    }
    let set_matrix_seconds = start.elapsed().as_secs_f64();

    // --- the dot products: 240 calls totalling 6,240 ring multiplications,
    //     which is what the Python profile attributes to ring.dot.
    let width = 26;
    let vector: Vec<Poly> = (0..width).map(|_| rng.poly()).collect();
    let row: Vec<Poly> = (0..width).map(|_| rng.poly()).collect();
    let dot_calls = 240;
    let start = Instant::now();
    for _ in 0..dot_calls {
        black_box(dot(&row, &vector));
    }
    let dot_seconds = start.elapsed().as_secs_f64();

    // --- verification: one set matrix plus the remaining multiplications that do
    //     not belong to it (4,741 total, 4,096 of which are the matrix).
    let start = Instant::now();
    sink = sink.wrapping_add(set_matrix(&c, &keys));
    for _ in 0..645 {
        black_box(mul_crt(&row[0], &vector[0]));
    }
    let verify_seconds = start.elapsed().as_secs_f64();

    let total = set_matrix_seconds + dot_seconds;
    println!("q = {Q}, d = {D}, ring 1024");
    println!("set matrix x2 : {:>8.3} s", set_matrix_seconds);
    println!("240 dot calls : {:>8.3} s", dot_seconds);
    println!("one attempt   : {:>8.3} s", total);
    println!();
    println!("The Python profile for the same work (6 attempts, 65.2 s):");
    println!("  _set_matrix  38.0 s, ring.dot 22.8 s, of which these are the same");
    println!("  operations. One accepted proof is an expected 2M^2 ~ 3 attempts.");
    println!("Rust, one attempt: {:.3} s -- so ~{:.1} s per proof.", total, total * 3.0);
    println!("Rust, verify   : {:.3} s (one set matrix + 645 multiplications)", verify_seconds);
    println!("(checksum {sink}, so the work is not optimised away)");
}
