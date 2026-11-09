//! Prover as a subprocess: read a request file, write a proof file.
//!
//! A subprocess rather than FFI because there are no crates available offline for
//! `pyo3`, and because the boundary is one call per proof: ~40 ms of process start
//! against ~500 ms of proving is not worth a build dependency.
//!
//! Request layout, all little-endian:
//!
//! ```text
//! u32 depth | u32 rows | u32 cols | u32 kappa | u32 width | u32 index | u32 message_len
//! message
//! rows0   : kappa * width polys
//! rows    : (rows + 2*depth + 1) * width polys
//! matrix  : rows * cols polys
//! ring    : 32^depth * rows polys
//! secret  : cols polys
//! ```
//!
//! The matrix and ring are passed **extended** when the caller wants a tagged
//! proof: `A_ext = [A; A']` and `(pk_j, T)` for every member. The prover does not
//! need to know that; it proves the statement it is given.

use radix_lattice::codec::{decode_poly, encode_challenge, encode_poly};
use radix_lattice::prover::{prove, Attempts, Rng};
use radix_lattice::sample::uniform_from;
use radix_lattice::statement::{Keys, Statement, CHALLENGE_DIM};
use radix_lattice::{Poly, D, SLOTS};

struct Reader<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> u32 {
        let value = u32::from_le_bytes([
            self.data[self.cursor],
            self.data[self.cursor + 1],
            self.data[self.cursor + 2],
            self.data[self.cursor + 3],
        ]);
        self.cursor += 4;
        value
    }

    fn bytes(&mut self, count: usize) -> &'a [u8] {
        let slice = &self.data[self.cursor..self.cursor + count];
        self.cursor += count;
        slice
    }

    fn poly(&mut self) -> Poly {
        let poly = decode_poly(self.data, self.cursor).expect("poly");
        self.cursor += D * 4;
        poly
    }

    fn polys(&mut self, count: usize) -> Vec<Poly> {
        (0..count).map(|_| self.poly()).collect()
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let request_path = args.next().expect("request path");
    let output_path = args.next().expect("output path");
    let seed: u64 = args.next().and_then(|value| value.parse().ok()).unwrap_or(2026);

    let data = std::fs::read(&request_path).expect("read request");
    let mut reader = Reader {
        data: &data,
        cursor: 0,
    };

    let depth = reader.u32() as usize;
    let rows = reader.u32() as usize;
    let cols = reader.u32() as usize;
    let kappa = reader.u32() as usize;
    let width = reader.u32() as usize;
    let index = reader.u32() as usize;
    let message_len = reader.u32() as usize;
    let message = reader.bytes(message_len).to_vec();

    assert_eq!(kappa, CHALLENGE_DIM, "kappa must match the manifest");

    let mut rows0 = Vec::with_capacity(kappa);
    for _ in 0..kappa {
        rows0.push(reader.polys(width));
    }
    let mut b_rows = Vec::with_capacity(rows + 2 * depth + 1);
    for _ in 0..rows + 2 * depth + 1 {
        b_rows.push(reader.polys(width));
    }
    let mut matrix = Vec::with_capacity(rows);
    for _ in 0..rows {
        matrix.push(reader.polys(cols));
    }
    let ring_size = SLOTS.pow(depth as u32);
    let mut ring = Vec::with_capacity(ring_size);
    for _ in 0..ring_size {
        ring.push(reader.polys(rows));
    }
    let secret = reader.polys(cols);

    let keys = Keys::new(rows0, b_rows, depth, rows).expect("keys");
    let statement = Statement::new(matrix, ring, depth).expect("statement");

    Attempts::reset();
    let mut rng = Rng::new(seed);
    let proof = match prove(&keys, &statement, &secret, index, &message, &mut rng) {
        Ok(proof) => proof,
        Err(error) => {
            eprintln!("prove failed: {error}");
            std::process::exit(2);
        }
    };

    std::fs::write(&output_path, proof.encode()).expect("write proof");
    eprintln!(
        "proved in {} attempts, {} bytes -> {output_path}",
        Attempts::get(),
        proof.encode().len()
    );

    // Silence unused-import warnings for helpers kept for symmetry with the tests.
    let _ = encode_challenge;
    let _ = encode_poly;
    let _ = uniform_from;
}
