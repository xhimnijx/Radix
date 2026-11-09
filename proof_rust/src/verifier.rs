//! The verifier, mirroring `setmembership.verify`.
//!
//! Order is load-bearing everywhere: `w = B_0 z - c t_0` must be recomputed before
//! the head, `c'` must be drawn before `z'` is absorbed, and the alphas must come
//! after `h`. Each of those is a place where a plausible reimplementation produces
//! a proof that never verifies.

use crate::codec::ProofWire;
use crate::proof::{e1, final_x, gamma_elements, paper_to_slot, set_matrix};
use crate::sample::dot;
use crate::recursion::{reduce_matrix, Quartic};
use crate::statement::{
    draw, draw_ternary, head, masking_width, Keys, ProofError, Statement, CHALLENGE_DIM,
    MATRIX_COLS,
};
use crate::{add, l2_squared, mul_crt, slots, sub, zero, Poly, SLOTS};

fn quartic_is_zero(value: &Quartic) -> bool {
    value.iter().all(|entry| *entry == 0)
}

/// A unit at an irreducible-quartic modulus: every one of the 32 residues is non-zero.
pub fn is_unit(poly: &Poly) -> bool {
    slots(poly).iter().all(|residue| !quartic_is_zero(residue))
}

fn add_all(polys: impl IntoIterator<Item = Poly>) -> Poly {
    let mut total = zero();
    for poly in polys {
        total = add(&total, &poly);
    }
    total
}

/// The verifier's response bound: `beta^2 = s^2 * 2 * width * d`, with `s` the same
/// mask width the prover used.
pub fn response_bound(width: usize) -> f64 {
    let sigma = crate::statement::mask_std(width);
    sigma * sigma * 2.0 * width as f64 * crate::D as f64
}

/// Check a proof. Returns `false` for any malformed or dishonest input; never panics
/// on attacker-supplied bytes (the codec already rejects bad lengths).
pub fn verify(
    keys: &Keys,
    statement: &Statement,
    proof: &ProofWire,
    message: &[u8],
) -> Result<bool, ProofError> {
    let depth = keys.depth;
    let rows = statement.rows();
    let width = masking_width(depth, keys.row_count)?;

    if proof.response.len() != width || proof.response_prime.len() != MATRIX_COLS {
        return Ok(false);
    }

    // l2 bounds, as the paper states them.
    let bound = response_bound(width);
    if proof.response.iter().map(|p| l2_squared(p) as f64).sum::<f64>() > bound {
        return Ok(false);
    }
    let bound_prime = response_bound(MATRIX_COLS);
    if proof
        .response_prime
        .iter()
        .map(|p| l2_squared(p) as f64)
        .sum::<f64>()
        > bound_prime
    {
        return Ok(false);
    }

    // Both challenges must be units: the line-13 argument divides by c^2.
    let challenge = crate::lift_challenge(&proof.challenge);
    let challenge_prime = crate::lift_challenge(&proof.challenge_prime);
    if !is_unit(&challenge) || !is_unit(&challenge_prime) {
        return Ok(false);
    }

    // Fig. 9 line 03 inverted: w = B_0 z - c t_0.
    let mut w = Vec::with_capacity(CHALLENGE_DIM);
    for (index, row) in keys.rows0.iter().enumerate() {
        w.push(sub(&dot(row, &proof.response), &mul_crt(&challenge, &proof.commitment[index])));
    }

    let head_length = CHALLENGE_DIM + depth + rows + 1;
    let mut transcript = head(message, &w, &proof.commitment[..head_length]);
    if draw_ternary(&mut transcript, b"c-prime") != proof.challenge_prime {
        return Ok(false);
    }
    transcript.absorb(b"z-prime", &crate::statement::encode_vector(&proof.response_prime));

    // The paper's position -> commitment-slot map.
    let mut slot_of = vec![0usize; rows + 2 * depth + 2];
    for position in 1..=rows + 2 * depth + 1 {
        slot_of[position] = paper_to_slot(position, depth, rows)?;
    }

    // line 04: t_{m+i} -= (A z')_i
    let a_z: Vec<Poly> = statement
        .matrix
        .iter()
        .map(|row| dot(row, &proof.response_prime))
        .collect();
    let mut values = proof.commitment.clone();
    for index in 1..=rows {
        let at = slot_of[depth + index];
        values[at] = sub(&values[at], &a_z[index - 1]);
    }

    // line 05
    let mut f: Vec<Poly> = vec![zero(); rows + 2 * depth + 2];
    for position in 1..=rows + 2 * depth + 1 {
        f[position] = sub(
            &dot(&keys.rows[position - 1], &proof.response),
            &mul_crt(&challenge, &values[slot_of[position]]),
        );
    }

    // lines 06-09: the descent.
    let mut matrix = set_matrix(&challenge_prime, statement);
    let mut weights: Vec<Vec<Poly>> = vec![Vec::new(); depth + 1];
    for level in 1..depth {
        let count = if level == 1 { rows } else { 1 };
        let gamma: Vec<Poly> = (0..count).map(|_| draw(&mut transcript, b"gamma")).collect();
        weights[level] = gamma.clone();
        matrix = reduce_matrix(&gamma_elements(&gamma), &matrix, depth - level + 1)
            .map_err(|error| ProofError(error.0.clone()))?;
        transcript.absorb(
            b"t-level",
            &crate::codec::encode_poly(&proof.commitment[slot_of[depth + rows + level]]),
        );
    }

    let gamma_m: Vec<Poly> = (0..=depth).map(|_| draw(&mut transcript, b"gamma-m")).collect();
    let x_last = final_x(&matrix, &gamma_m, depth)?;
    let e1_sum = add_all(gamma_m[1..=depth].iter().cloned());

    // line 10
    let mut total = add(
        &mul_crt(&f[1], &f[depth + rows + 1]),
        &mul_crt(
            &challenge,
            &add_all(
                (0..rows).map(|index| mul_crt(&weights[1][index], &f[depth + index + 1])),
            ),
        ),
    );

    // line 11
    for level in 2..depth {
        total = add(
            &total,
            &add(
                &mul_crt(&f[level], &f[depth + rows + level]),
                &mul_crt(
                    &challenge,
                    &mul_crt(&weights[level][0], &f[depth + rows + level - 1]),
                ),
            ),
        );
    }

    // line 12, with e_1 at order c^2
    total = add(
        &total,
        &sub(
            &mul_crt(
                &challenge,
                &sub(
                    &mul_crt(&gamma_m[0], &f[rows + 2 * depth - 1]),
                    &add_all((0..depth).map(|index| mul_crt(&x_last[index], &f[index + 1]))),
                ),
            ),
            &mul_crt(&mul_crt(&challenge, &challenge), &mul_crt(&e1(), &e1_sum)),
        ),
    );

    // line 13
    let inner = sub(
        &sub(&total, &mul_crt(&challenge, &f[rows + 2 * depth])),
        &mul_crt(&mul_crt(&challenge, &challenge), &proof.h),
    );
    transcript.absorb(b"h", &crate::codec::encode_poly(&proof.h));
    let alphas: Vec<Poly> = (0..=depth).map(|_| draw(&mut transcript, b"alpha")).collect();
    transcript.absorb(
        b"t-psi",
        &crate::codec::encode_poly(&proof.commitment[proof.commitment.len() - 1]),
    );
    transcript.absorb(b"omega", &crate::codec::encode_poly(&proof.omega));
    if draw_ternary(&mut transcript, b"c") != proof.challenge {
        return Ok(false);
    }

    let lhs = sub(
        &add(
            &mul_crt(&alphas[0], &inner),
            &add_all((0..depth).map(|index| {
                mul_crt(
                    &alphas[index + 1],
                    &add(
                        &mul_crt(&f[index + 1], &f[index + 1]),
                        &mul_crt(&challenge, &f[index + 1]),
                    ),
                )
            })),
        ),
        &f[rows + 2 * depth + 1],
    );
    if lhs != proof.omega {
        return Ok(false);
    }

    // lines 14-15
    let prefix = crate::D / SLOTS;
    if proof.h[..prefix].iter().any(|value| *value != 0) {
        return Ok(false);
    }

    // A tagged proof must be checked as tagged; this port handles untagged only.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uniform_polynomial_is_a_unit_with_overwhelming_probability() {
        let poly = crate::sample::uniform_from(b"unit", 0);
        assert!(is_unit(&poly));
    }

    #[test]
    fn a_zero_polynomial_is_not_a_unit() {
        assert!(!is_unit(&zero()));
    }

    #[test]
    fn a_polynomial_vanishing_in_one_slot_is_not_a_unit() {
        // Build a polynomial that is zero in slot 0 and non-zero elsewhere.
        let mut values = [1u64; SLOTS];
        values[0] = 0;
        let poly = crate::proof::lift(&values);
        assert!(!is_unit(&poly));
    }

    #[test]
    fn the_response_bound_is_positive_and_scales_with_width() {
        assert!(response_bound(29) > 0.0);
        assert!(response_bound(33) > response_bound(29));
    }

    #[test]
    fn a_wrong_sized_proof_is_rejected() {
        use crate::statement::{Keys, Statement};
        let width = masking_width(2, 4).unwrap();
        let row = vec![[0u64; crate::D]; width];
        let keys = Keys::new(vec![row.clone(); CHALLENGE_DIM], vec![row; 9], 2, 4).unwrap();
        let matrix = vec![vec![[0u64; crate::D]; MATRIX_COLS]; 4];
        let keys_ring = vec![vec![[0u64; crate::D]; 4]; SLOTS.pow(2)];
        let statement = Statement::new(matrix, keys_ring, 2).unwrap();
        let proof = ProofWire {
            commitment: vec![[0u64; crate::D]; 1],
            h: [0u64; crate::D],
            omega: [0u64; crate::D],
            challenge: [0i64; crate::D],
            challenge_prime: [0i64; crate::D],
            response_prime: vec![[0u64; crate::D]; 1],
            response: vec![[0u64; crate::D]; 1],
        };
        assert_eq!(verify(&keys, &statement, &proof, b"m").unwrap(), false);
    }
}
