//! End-to-end timing for prove and verify, in release mode.
//!
//! Replaces the projection in PERFORMANCE.md with a measurement: the earlier figure
//! was the dominant work scaled by a per-multiplication cost, which is a model, not
//! a timing. This runs the real prover and the real verifier.

use radix_lattice::codec::ProofWire;
use radix_lattice::prover::{prove, Rng, Attempts};
use radix_lattice::sample::{dot, uniform_from};
use radix_lattice::statement::{commitment_count, masking_width, Keys, Statement, CHALLENGE_DIM, MATRIX_COLS};
use radix_lattice::verifier::verify;
use radix_lattice::{constant_poly, Poly, SLOTS};
use std::time::Instant;

const DEPTH: usize = 2;
const ROWS: usize = 4;
const HONEST: usize = 7;

fn main() {
    let width = masking_width(DEPTH, ROWS).expect("width");
    let rows0: Vec<Vec<Poly>> = (0..CHALLENGE_DIM)
        .map(|row| (0..width).map(|column| uniform_from(b"K0", (row * width + column) as u32)).collect())
        .collect();
    let b_rows: Vec<Vec<Poly>> = (0..ROWS + 2 * DEPTH + 1)
        .map(|row| (0..width).map(|column| uniform_from(b"K1", (row * width + column) as u32)).collect())
        .collect();
    let keys = Keys::new(rows0, b_rows, DEPTH, ROWS).expect("keys");

    let matrix: Vec<Vec<Poly>> = (0..ROWS)
        .map(|row| (0..MATRIX_COLS).map(|column| uniform_from(b"A", (row * MATRIX_COLS + column) as u32)).collect())
        .collect();
    let secret: Vec<Poly> = (0..MATRIX_COLS)
        .map(|index| constant_poly(((index % 7) as i64 - 3).rem_euclid(radix_lattice::Q as i64) as u64))
        .collect();
    let public: Vec<Poly> = matrix.iter().map(|row| dot(row, &secret)).collect();
    let mut ring: Vec<Vec<Poly>> = (0..SLOTS.pow(DEPTH as u32))
        .map(|key| (0..ROWS).map(|component| uniform_from(b"pk", (key * ROWS + component) as u32)).collect())
        .collect();
    ring[HONEST] = public;
    let statement = Statement::new(matrix, ring, DEPTH).expect("statement");

    let rounds = 8;
    let message = b"timing";

    let mut prove_seconds = 0.0f64;
    let mut attempts_total = 0usize;
    let mut proofs: Vec<ProofWire> = Vec::new();
    for round in 0..rounds {
        let mut rng = Rng::new(1000 + round as u64);
        Attempts::reset();
        let start = Instant::now();
        let proof = prove(&keys, &statement, &secret, HONEST, message, &mut rng).expect("prove");
        prove_seconds += start.elapsed().as_secs_f64();
        attempts_total += Attempts::get();
        proofs.push(proof);
    }

    let mut verify_seconds = 0.0f64;
    for proof in &proofs {
        let start = Instant::now();
        assert!(verify(&keys, &statement, proof, message).expect("verify"));
        verify_seconds += start.elapsed().as_secs_f64();
    }

    let bytes = proofs[0].encode().len();
    println!("proof size        {} bytes", bytes);
    println!("prove   mean      {:.3} s  ({:.0} ms)", prove_seconds / rounds as f64, prove_seconds * 1000.0 / rounds as f64);
    println!("verify  mean      {:.4} s  ({:.1} ms)", verify_seconds / rounds as f64, verify_seconds * 1000.0 / rounds as f64);
    println!("attempts per proof {:.2}", attempts_total as f64 / rounds as f64);
    println!("commitment arity  {}", commitment_count(ROWS, DEPTH));
}
