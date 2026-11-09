//! Rust proves, Rust verifies.
//!
//! Self-consistency is the weaker of the two cross-checks -- a prover and verifier
//! that are wrong in the same way agree happily -- but it is the one that runs in
//! seconds, so it catches mistakes early. The stronger check is
//! `tests/python_verifies_rust.rs`, which hands a Rust proof to the Python verifier.

use radix_lattice::codec::ProofWire;
use radix_lattice::prover::{prove, Rng};
use radix_lattice::sample::uniform_from;
use radix_lattice::statement::{commitment_count, masking_width, Keys, Statement, CHALLENGE_DIM, MATRIX_COLS};
use radix_lattice::verifier::{verify, verify_traced};
use radix_lattice::sample::dot;
use radix_lattice::{constant_poly, Poly, D, SLOTS};

const DEPTH: usize = 2;
const ROWS: usize = 4;
const HONEST: usize = 7;
const MESSAGE: &[u8] = b"hello from rust";

struct Rig {
    keys: Keys,
    statement: Statement,
    secret: Vec<Poly>,
}

fn rig() -> Rig {
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

    // A small, deterministic secret so the public key is reproducible.
    let secret: Vec<Poly> = (0..MATRIX_COLS)
        .map(|index| constant_poly(((index % 7) as i64 - 3).rem_euclid(radix_lattice::Q as i64) as u64))
        .collect();
    let public: Vec<Poly> = matrix.iter().map(|row| dot(row, &secret)).collect();

    let mut ring: Vec<Vec<Poly>> = (0..SLOTS.pow(DEPTH as u32))
        .map(|key| {
            (0..ROWS)
                .map(|component| uniform_from(b"pk", (key * ROWS + component) as u32))
                .collect()
        })
        .collect();
    ring[HONEST] = public;
    let statement = Statement::new(matrix, ring, DEPTH).expect("statement");
    Rig {
        keys,
        statement,
        secret,
    }
}

#[test]
fn a_rust_proof_verifies_in_rust() {
    let rig = rig();
    let mut rng = Rng::new(1);
    let proof = prove(&rig.keys, &rig.statement, &rig.secret, HONEST, MESSAGE, &mut rng)
        .expect("prove");
    assert_eq!(
        proof.commitment.len(),
        commitment_count(ROWS, DEPTH),
        "commitment arity"
    );
    assert_eq!(proof.response.len(), masking_width(DEPTH, ROWS).unwrap());
    assert_eq!(proof.response_prime.len(), MATRIX_COLS);
    let (ok, trace) = verify_traced(&rig.keys, &rig.statement, &proof, MESSAGE).expect("verify");
    assert!(ok, "rust rejected its own proof after stages: {trace:?}");
}

#[test]
fn a_tampered_rust_proof_is_rejected() {
    let rig = rig();
    let mut rng = Rng::new(2);
    let mut proof = prove(&rig.keys, &rig.statement, &rig.secret, HONEST, MESSAGE, &mut rng)
        .expect("prove");

    // Flipping one response coefficient must break the final equation.
    proof.response[0][0] = (proof.response[0][0] + 1) % radix_lattice::Q;
    assert!(!verify(&rig.keys, &rig.statement, &proof, MESSAGE).expect("verify"));

    // And a different message must not verify against the same proof.
    let mut rng = Rng::new(3);
    let fresh = prove(&rig.keys, &rig.statement, &rig.secret, HONEST, MESSAGE, &mut rng)
        .expect("prove");
    assert!(verify(&rig.keys, &rig.statement, &fresh, b"another message").is_ok());
    assert!(!verify(&rig.keys, &rig.statement, &fresh, b"another message").unwrap());
}

#[test]
fn the_wire_round_trip_preserves_a_proof() {
    let rig = rig();
    let mut rng = Rng::new(4);
    let proof = prove(&rig.keys, &rig.statement, &rig.secret, HONEST, MESSAGE, &mut rng)
        .expect("prove");
    let bytes = proof.encode();
    let decoded = ProofWire::decode(
        &bytes,
        commitment_count(ROWS, DEPTH),
        MATRIX_COLS,
        masking_width(DEPTH, ROWS).unwrap(),
    )
    .expect("decode");
    assert_eq!(decoded, proof);
    assert!(verify(&rig.keys, &rig.statement, &decoded, MESSAGE).unwrap());
    let _ = D;
}
