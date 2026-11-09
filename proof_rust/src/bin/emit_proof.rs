//! Emit a Rust proof for the Python verifier to check.
//!
//! Writes `tests/fixtures/rust_proof.bin`: the proof bytes followed by the honest
//! public key, laid out exactly like `python_proof.bin` so one Python script can
//! check both.

use radix_lattice::prover::{prove, Rng};
use radix_lattice::sample::{dot, uniform_from};
use radix_lattice::statement::{
    masking_width, Keys, Statement, CHALLENGE_DIM, MATRIX_COLS,
};
use radix_lattice::{constant_poly, Poly, SLOTS};

const DEPTH: usize = 2;
const ROWS: usize = 4;
const HONEST: usize = 7;
const MESSAGE: &[u8] = b"hello from rust";

fn main() {
    let width = masking_width(DEPTH, ROWS).expect("width");
    let rows0: Vec<Vec<Poly>> = (0..CHALLENGE_DIM)
        .map(|row| {
            (0..width)
                .map(|column| uniform_from(b"K0", (row * width + column) as u32))
                .collect()
        })
        .collect();
    let b_rows: Vec<Vec<Poly>> = (0..ROWS + 2 * DEPTH + 1)
        .map(|row| {
            (0..width)
                .map(|column| uniform_from(b"K1", (row * width + column) as u32))
                .collect()
        })
        .collect();
    let keys = Keys::new(rows0, b_rows, DEPTH, ROWS).expect("keys");

    let matrix: Vec<Vec<Poly>> = (0..ROWS)
        .map(|row| {
            (0..MATRIX_COLS)
                .map(|column| uniform_from(b"A", (row * MATRIX_COLS + column) as u32))
                .collect()
        })
        .collect();
    let secret: Vec<Poly> = (0..MATRIX_COLS)
        .map(|index| {
            constant_poly(((index % 7) as i64 - 3).rem_euclid(radix_lattice::Q as i64) as u64)
        })
        .collect();
    let public: Vec<Poly> = matrix.iter().map(|row| dot(row, &secret)).collect();

    let mut ring: Vec<Vec<Poly>> = (0..SLOTS.pow(DEPTH as u32))
        .map(|key| {
            (0..ROWS)
                .map(|component| uniform_from(b"pk", (key * ROWS + component) as u32))
                .collect()
        })
        .collect();
    ring[HONEST] = public.clone();
    let statement = Statement::new(matrix, ring, DEPTH).expect("statement");

    let mut rng = Rng::new(2026);
    let proof = prove(&keys, &statement, &secret, HONEST, MESSAGE, &mut rng).expect("prove");

    let mut blob = proof.encode();
    for poly in &public {
        blob.extend_from_slice(&radix_lattice::codec::encode_poly(poly));
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("rust_proof.bin");
    std::fs::write(&path, &blob).expect("write fixture");
    println!("wrote {} bytes to {path:?}", blob.len());
}
