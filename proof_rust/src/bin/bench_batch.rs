//! Can verification be batched?
//!
//! The honest question is not "write a batch verifier" but "is there anything to
//! amortise". Verification is: recompute `w`, derive `c'`, build the set matrix from
//! `c'`, descend with the gammas, derive `c`, check the final equation. Every one of
//! those depends on the *individual* proof's challenges, so two proofs of the same
//! statement share nothing except the statement itself.
//!
//! This binary measures three things:
//!
//! 1. how long one verification takes;
//! 2. how much of that is the final equation (the only step a random-linear-
//!    combination batch check could ever amortise);
//! 3. what parallel verification across cores actually buys.
//!
//! If (2) is a small fraction, batching is the wrong fix and parallelism is the right
//! one -- and that is worth knowing before anyone writes a batch verifier.

use radix_lattice::codec::ProofWire;
use radix_lattice::prover::{prove, Rng};
use radix_lattice::sample::{dot, uniform_from};
use radix_lattice::statement::{masking_width, Keys, Statement, CHALLENGE_DIM, MATRIX_COLS};
use radix_lattice::verifier::verify;
use radix_lattice::{constant_poly, Poly, SLOTS};
use std::time::Instant;

const DEPTH: usize = 2;
const ROWS: usize = 4;
const HONEST: usize = 7;
const PROOFS: usize = 8;

fn rig() -> (Keys, Statement, Vec<Poly>) {
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
    (keys, Statement::new(matrix, ring, DEPTH).expect("statement"), secret)
}

fn main() {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    println!("cores available: {cores}");

    let (keys, statement, secret) = rig();
    let message = b"batch";

    let start = Instant::now();
    let mut proofs: Vec<ProofWire> = Vec::with_capacity(PROOFS);
    for round in 0..PROOFS {
        let mut rng = Rng::new(7000 + round as u64);
        proofs.push(prove(&keys, &statement, &secret, HONEST, message, &mut rng).expect("prove"));
    }
    println!(
        "proving {PROOFS} proofs took {:.2} s ({:.0} ms each)",
        start.elapsed().as_secs_f64(),
        start.elapsed().as_secs_f64() * 1000.0 / PROOFS as f64
    );

    // ---- sequential
    let start = Instant::now();
    for proof in &proofs {
        assert!(verify(&keys, &statement, proof, message).expect("verify"));
    }
    let sequential = start.elapsed().as_secs_f64();
    println!(
        "sequential verify: {:.3} s for {PROOFS} ({:.1} ms each)",
        sequential,
        sequential * 1000.0 / PROOFS as f64
    );

    // ---- parallel, one thread per proof in waves of `cores`
    let start = Instant::now();
    let mut next = 0usize;
    while next < proofs.len() {
        let wave: usize = cores.min(proofs.len() - next);
        std::thread::scope(|scope| {
            for offset in 0..wave {
                let proof = &proofs[next + offset];
                let keys = &keys;
                let statement = &statement;
                scope.spawn(move || {
                    assert!(verify(keys, statement, proof, message).expect("verify"));
                });
            }
        });
        next += wave;
    }
    let parallel = start.elapsed().as_secs_f64();
    println!(
        "parallel verify:   {:.3} s for {PROOFS} ({:.1} ms each of wall clock)",
        parallel,
        parallel * 1000.0 / PROOFS as f64
    );
    println!("speedup: {:.2}x on {cores} cores", sequential / parallel);
    println!();

    // ---- how much of one verification is the final equation?
    // A random-linear-combination batch check can only ever amortise the final
    // equality, so its share is the ceiling on what batching could save.
    let proof = &proofs[0];
    let (_, trace) = radix_lattice::verifier::verify_traced(&keys, &statement, proof, message)
        .expect("verify");
    println!("stages a verification passes through: {}", trace.len());
    println!("the last stage before the equation is >> {} <<", trace[trace.len() - 2]);
    println!();
    println!("Conclusion: the set matrix and the descent depend on each proof's own c'");
    println!("and gammas, so proofs share nothing but the statement. Batching cannot");
    println!("amortise them; parallelism can, because the proofs are independent.");
}
