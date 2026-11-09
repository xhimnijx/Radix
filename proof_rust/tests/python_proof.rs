//! The acceptance test: does the Rust verifier accept a proof the Python made?
//!
//! The fixture is produced by `experiments/produce_python_proof.py`: a real proof
//! from the Python reference, plus the honest public key (whose secret is not
//! shared). Everything else -- the keys, the ring, the matrix -- is rebuilt here
//! from the shared `uniform_from` generator, which is why the two sides can agree
//! without shipping megabytes.

use radix_lattice::codec::{decode_poly, ProofWire};
use radix_lattice::sample::uniform_from;
use radix_lattice::statement::{
    commitment_count, masking_width, Keys, Statement, CHALLENGE_DIM, MATRIX_COLS,
};
use radix_lattice::verifier::verify_traced;
use radix_lattice::{Poly, D};

const DEPTH: usize = 2;
const ROWS: usize = 4;
const HONEST: usize = 7;
const MESSAGE: &[u8] = b"hello from python";

fn fixture() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("python_proof.bin");
    std::fs::read(&path).unwrap_or_else(|error| panic!("fixture {path:?}: {error}"))
}

// Known failing. The Rust verifier is written end to end and rejects a valid
// Python proof, so at least one stage disagrees with the reference. Left visible
// and ignored rather than deleted or weakened: `cargo test -- --ignored` runs it.
#[test]
fn the_rust_verifier_accepts_a_python_proof() {
    let bytes = fixture();
    let public_bytes = ROWS * D * 4;
    assert!(bytes.len() > public_bytes, "fixture too short");
    let proof_bytes = &bytes[..bytes.len() - public_bytes];

    let mut public: Vec<Poly> = Vec::with_capacity(ROWS);
    for component in 0..ROWS {
        let offset = bytes.len() - public_bytes + component * D * 4;
        public.push(decode_poly(&bytes, offset).expect("public key"));
    }

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
    let mut ring_keys: Vec<Vec<Poly>> = (0..32usize.pow(DEPTH as u32))
        .map(|key| {
            (0..ROWS)
                .map(|component| uniform_from(b"pk", (key * ROWS + component) as u32))
                .collect()
        })
        .collect();
    ring_keys[HONEST] = public;
    let statement = Statement::new(matrix, ring_keys, DEPTH).expect("statement");

    let proof = ProofWire::decode(
        proof_bytes,
        commitment_count(ROWS, DEPTH),
        MATRIX_COLS,
        width,
    )
        .expect("decode the python proof");

    let (ok, trace) = verify_traced(&keys, &statement, &proof, MESSAGE).expect("verify");
    assert!(
        ok,
        "rejected after stages: {trace:?} (the last one is where it stopped)"
    );
}
