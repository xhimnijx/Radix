//! Verifier as a subprocess: read a request and a proof, answer yes or no.
//!
//! Same request layout as `prove_request`, so `radix_testnet/rust_backend.py` builds
//! one serialiser for both directions. Exit code 0 means the proof verified, 1 means
//! it did not, 2 means the input was malformed -- keeping "the proof is wrong" and
//! "the request is wrong" distinguishable, which matters when a node is deciding
//! whether to reject a transaction or to log a bug.

use radix_lattice::codec::{decode_poly, ProofWire};
use radix_lattice::statement::{commitment_count, masking_width, Keys, Statement, CHALLENGE_DIM};
use radix_lattice::verifier::verify;
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

    fn polys(&mut self, count: usize) -> Vec<Poly> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(decode_poly(self.data, self.cursor).expect("poly"));
            self.cursor += D * 4;
        }
        out
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let request_path = args.next().expect("request path");
    let proof_path = args.next().expect("proof path");

    let data = std::fs::read(&request_path).expect("read request");
    let proof_bytes = std::fs::read(&proof_path).expect("read proof");

    let mut reader = Reader {
        data: &data,
        cursor: 0,
    };
    let depth = reader.u32() as usize;
    let rows = reader.u32() as usize;
    let cols = reader.u32() as usize;
    let kappa = reader.u32() as usize;
    let width = reader.u32() as usize;
    let _index = reader.u32();
    let message_len = reader.u32() as usize;
    let range_count = reader.u32() as usize;
    let message = reader.bytes(message_len).to_vec();

    if kappa != CHALLENGE_DIM {
        eprintln!("kappa must match the manifest");
        std::process::exit(2);
    }

    let mut rows0 = Vec::with_capacity(kappa);
    for _ in 0..kappa {
        rows0.push(reader.polys(width));
    }
    let mut b_rows = Vec::with_capacity(rows + 2 * depth + 1);
    for _ in 0..rows + 2 * depth + 1 {
        b_rows.push(reader.polys(width));
    }
    let mut range_rows = Vec::with_capacity(range_count);
    for _ in 0..range_count {
        range_rows.push(reader.polys(width));
    }
    let mut matrix = Vec::with_capacity(rows);
    for _ in 0..rows {
        matrix.push(reader.polys(cols));
    }
    let mut ring = Vec::with_capacity(SLOTS.pow(depth as u32));
    for _ in 0..SLOTS.pow(depth as u32) {
        ring.push(reader.polys(rows));
    }
    // The secret is not needed to verify, but it is in the request format; skip it.
    let _ = reader.polys(cols);

    let keys = match Keys::new(rows0, b_rows, depth, rows)
        .and_then(|keys| keys.with_range_rows(range_rows))
    {
        Ok(keys) => keys,
        Err(error) => {
            eprintln!("bad keys: {error}");
            std::process::exit(2);
        }
    };
    let statement = match Statement::new(matrix, ring, depth) {
        Ok(statement) => statement,
        Err(error) => {
            eprintln!("bad statement: {error}");
            std::process::exit(2);
        }
    };
    let expected_width = masking_width(depth, rows).unwrap_or(width);
    let proof = match ProofWire::decode(
        &proof_bytes,
        commitment_count(rows, depth) + range_count,
        cols,
        expected_width,
    ) {
        Ok(proof) => proof,
        Err(error) => {
            eprintln!("bad proof encoding: {error}");
            std::process::exit(2);
        }
    };

    match verify(&keys, &statement, &proof, &message) {
        Ok(true) => {
            println!("1");
        }
        Ok(false) => {
            println!("0");
            std::process::exit(1);
        }
        Err(error) => {
            eprintln!("verification error: {error}");
            std::process::exit(2);
        }
    }
}
