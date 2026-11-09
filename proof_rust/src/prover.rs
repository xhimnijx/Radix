//! The prover, mirroring `setmembership._prove_once`.
//!
//! Same pipeline as the verifier in reverse: commitments first, then `c'`, then the
//! descent computing `x` values and `y`s, then `h`, the alphas, `psi`/`omega`, and
//! finally `c`. The two rejection points (`z'` early, `z` last) mean a whole attempt
//! can be thrown away, so every attempt rebuilds its transcript from scratch --
//! reusing a transcript across attempts would silently produce proofs that verify
//! only sometimes.

use crate::codec::ProofWire;
use crate::recursion::{from_constants, matrix_vector, tensor, Quartic};
use crate::sample::dot;
use crate::statement::{
    CHALLENGE_DIM,
    Keys,
    MATRIX_COLS,
    ProofError,
    Statement,
    draw,
    draw_ternary,
    head,
    mask_std,
    masking_width,
    ring_digest,
};
use crate::{add, glue_crt, l2_squared, mul_crt, scalar, slots, sub, zero, Poly, D, Q, SLOTS};

const MAX_ATTEMPTS: usize = 64;

/// How many attempts the last `prove` needed. Instrumentation for the benchmark;
/// it is not part of the protocol and nothing reads it for correctness.
pub struct Attempts;

static ATTEMPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Attempts {
    pub fn reset() {
        ATTEMPTS.store(0, std::sync::atomic::Ordering::Relaxed);
    }
    pub fn get() -> usize {
        ATTEMPTS.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn bump() {
        ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// xoshiro256++: a small deterministic generator. The Python prover uses Mersenne
/// Twister; proofs do not need to match bit for bit, only to verify.
pub struct Rng {
    state: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        let mut state = [0u64; 4];
        let mut value = seed | 1;
        for slot in state.iter_mut() {
            value = value.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *slot = value;
        }
        Rng { state }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        let result = self.state[0]
            .wrapping_add(self.state[3])
            .rotate_left(23)
            .wrapping_add(self.state[0]);
        let t = self.state[1] << 17;
        self.state[2] ^= self.state[0];
        self.state[3] ^= self.state[1];
        self.state[1] ^= self.state[2];
        self.state[0] ^= self.state[3];
        self.state[2] ^= t;
        self.state[3] = self.state[3].rotate_left(45);
        result
    }

    /// Uniform in [0, 1).
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in `[-bound, bound]`, as a residue.
    fn small(&mut self, bound: i64) -> u64 {
        let span = (2 * bound + 1) as u64;
        let value = (self.next_u64() % span) as i64 - bound;
        (value.rem_euclid(Q as i64)) as u64
    }

    /// A sample from the shared discrete-Gaussian table.
    ///
    /// `width` selects the table; the distribution is the one Python reads from the
    /// same file, so the two implementations cannot drift.
    fn gaussian(&mut self, width: usize) -> u64 {
        crate::gaussian::sample(self, width)
    }
}

fn add_all(polys: impl IntoIterator<Item = Poly>) -> Poly {
    let mut total = zero();
    for poly in polys {
        total = add(&total, &poly);
    }
    total
}

fn centred_inner(left: &[Poly], right: &[Poly]) -> f64 {
    let mut total = 0.0;
    for (a, b) in left.iter().zip(right.iter()) {
        for index in 0..D {
            total += crate::centered(a[index]) as f64 * crate::centered(b[index]) as f64;
        }
    }
    total
}

fn l2_of(vector: &[Poly]) -> f64 {
    vector.iter().map(|poly| l2_squared(poly) as f64).sum()
}

/// The paper's `Rej1`: bimodal rejection, so the mask can stay narrow.
fn reject(response: &[Poly], product: &[Poly], sigma: f64, rng: &mut Rng) -> bool {
    let inner = centred_inner(response, product);
    if inner < 0.0 {
        return true;
    }
    let norm_sq = l2_of(product);
    let exponent = (-2.0 * inner + norm_sq) / (2.0 * sigma * sigma) - 1.5f64.sqrt().ln();
    rng.next_f64() > exponent.min(0.0).exp()
}

struct Attempt {
    proof: ProofWire,
}

/// One attempt. `None` means rejection sampling rejected it.
fn prove_once(
    keys: &Keys,
    statement: &Statement,
    secret: &[Poly],
    index: usize,
    message: &[u8],
    rng: &mut Rng,
) -> Result<Option<Attempt>, ProofError> {
    let depth = keys.depth;
    let rows = statement.rows();
    let width = masking_width(depth, keys.row_count)?;

    if statement.keys.len() != SLOTS.pow(depth as u32) {
        return Err(ProofError("the ring must have l^m keys".into()));
    }
    if index >= statement.keys.len() {
        return Err(ProofError("index is outside the ring".into()));
    }
    let public: Vec<Poly> = statement.matrix.iter().map(|row| dot(row, secret)).collect();
    if public != statement.keys[index] {
        return Err(ProofError("the secret does not open the claimed ring member".into()));
    }

    // r, y, y'
    let randomness: Vec<Poly> = (0..width).map(|_| {
        let mut poly = [0u64; D];
        for value in poly.iter_mut() {
            *value = rng.small(5);
        }
        poly
    }).collect();
    let sigma_main = mask_std(width);
    let sigma_prime = mask_std(MATRIX_COLS);
    let mask: Vec<Poly> = (0..width).map(|_| {
        let mut poly = [0u64; D];
        for value in poly.iter_mut() {
            *value = rng.gaussian(width);
        }
        poly
    }).collect();
    let mask_prime: Vec<Poly> = (0..MATRIX_COLS).map(|_| {
        let mut poly = [0u64; D];
        for value in poly.iter_mut() {
            *value = rng.gaussian(MATRIX_COLS);
        }
        poly
    }).collect();

    let w: Vec<Poly> = keys.rows0.iter().map(|row| dot(row, &mask)).collect();
    let w_prime: Vec<Poly> = statement.matrix.iter().map(|row| dot(row, &mask_prime)).collect();

    let index_vectors = crate::proof::index_vectors(index, depth)?;
    // The recursion works over M_q, so the one-hot blocks become constant quartics.
    let v_vectors: Vec<Vec<Quartic>> = index_vectors
        .iter()
        .map(|vector| vector.iter().map(|value| crate::recursion::constant(*value)).collect())
        .collect();
    let v_polys: Vec<Poly> = index_vectors
        .iter()
        .map(|vector| from_constants(vector).expect("32 entries"))
        .collect();

    // g has its first `d/l` *coefficients* zero -- not its first `d/l` slots. The
    // verifier checks the coefficient prefix, so building this from slots produces
    // a polynomial that fails lines 14-15 while every other stage passes.
    let mut g_poly = [0u64; D];
    for value in g_poly.iter_mut().skip(D / SLOTS) {
        *value = rng.next_u64() % Q;
    }

    let mut values: Vec<Poly> = vec![zero(); rows + 2 * depth + 2];
    for position in 1..=depth {
        values[position] = v_polys[position - 1];
    }
    for position in 1..=rows {
        values[depth + position] = w_prime[position - 1];
    }
    values[rows + 2 * depth] = g_poly;

    let mut commitment: Vec<Poly> = keys.rows0.iter().map(|row| dot(row, &randomness)).collect();
    let mut positions: Vec<usize> = (1..=depth + rows).collect();
    positions.push(rows + 2 * depth);
    for position in positions {
        let base = dot(&keys.rows[position - 1], &randomness);
        commitment.push(add(&base, &values[position]));
    }

    let mut transcript = head(message, &w, &commitment, &ring_digest(statement));
    let challenge_prime = draw_ternary(&mut transcript, b"c-prime");
    let lifted_prime = crate::lift_challenge(&challenge_prime);
    if !crate::verifier::is_unit(&lifted_prime) {
        return Ok(None);
    }

    let product_prime: Vec<Poly> = secret.iter().map(|poly| mul_crt(&lifted_prime, poly)).collect();
    let response_prime: Vec<Poly> = (0..MATRIX_COLS)
        .map(|index| add(&mask_prime[index], &product_prime[index]))
        .collect();
    if reject(&response_prime, &product_prime, sigma_prime, rng) {
        return Ok(None);
    }
    transcript.absorb(b"z-prime", &crate::statement::encode_vector(&response_prime));

    let set_matrix = crate::proof::set_matrix(&lifted_prime, statement);
    let x1: Vec<Poly> = (0..rows)
        .map(|index| sub(&w_prime[index], &dot(&statement.matrix[index], &response_prime)))
        .collect();

    let mut ys: Vec<Poly> = Vec::new();
    let mut weights: Vec<Vec<Poly>> = vec![Vec::new(); depth + 1];
    let mut xs: Vec<Poly> = Vec::new();
    let mut matrix = set_matrix;

    for level in 1..depth {
        let count = if level == 1 { rows } else { 1 };
        let gamma: Vec<Poly> = (0..count).map(|_| draw(&mut transcript, b"gamma")).collect();
        weights[level] = gamma.clone();
        matrix = crate::recursion::reduce_matrix(
            &crate::proof::gamma_elements(&gamma),
            &matrix,
            depth - level + 1,
        )
        .map_err(|error| ProofError(error.0.clone()))?;
        let tensor_factors = tensor(&v_vectors[level..])
            .map_err(|error| ProofError(error.0.clone()))?;
        let x_next = glue_crt_of(
            matrix_vector(&matrix, &tensor_factors)
                .map_err(|error| ProofError(error.0.clone()))?,
        );
        let y = if level == 1 {
            sub(
                &mul_crt(&v_polys[0], &x_next),
                &add_all((0..rows).map(|index| mul_crt(&x1[index], &gamma[index]))),
            )
        } else {
            sub(
                &mul_crt(&v_polys[level - 1], &x_next),
                &mul_crt(&xs[xs.len() - 1], &gamma[0]),
            )
        };
        ys.push(y);
        xs.push(x_next);
        let base = dot(&keys.rows[depth + rows + level - 1], &randomness);
        commitment.push(add(&base, &x_next));
        transcript.absorb(
            b"t-level",
            &crate::codec::encode_poly(&commitment[commitment.len() - 1]),
        );
    }

    let gamma_m: Vec<Poly> = (0..=depth).map(|_| draw(&mut transcript, b"gamma-m")).collect();
    let x_last = crate::proof::final_x(&matrix, &gamma_m, depth)?;
    let e1_sum = add_all(gamma_m[1..=depth].iter().cloned());
    let y_m = sub(
        &add_all((0..depth).map(|index| mul_crt(&v_polys[index], &x_last[index]))),
        &add(
            &mul_crt(&xs[xs.len() - 1], &gamma_m[0]),
            &mul_crt(&crate::proof::e1(), &e1_sum),
        ),
    );
    ys.push(y_m);
    let mut h_terms = vec![g_poly];
    h_terms.extend(ys.iter().cloned());
    let h = add_all(h_terms);
    transcript.absorb(b"h", &crate::codec::encode_poly(&h));
    let alphas: Vec<Poly> = (0..=depth).map(|_| draw(&mut transcript, b"alpha")).collect();

    let mut a_values: Vec<Poly> = vec![zero(); rows + 2 * depth + 2];
    for position in 1..=rows + 2 * depth + 1 {
        a_values[position] = dot(&keys.rows[position - 1], &mask);
    }

    let mut psi_levels: Vec<Poly> = Vec::new();
    let mut omega_levels: Vec<Poly> = Vec::new();
    for level in 1..depth {
        let body = if level == 1 {
            let gamma_term = add_all(
                (0..rows).map(|index| mul_crt(&weights[1][index], &a_values[depth + index + 1])),
            );
            let first = sub(&gamma_term, &mul_crt(&a_values[1], &xs[0]));
            sub(&first, &mul_crt(&a_values[depth + rows + 1], &v_polys[0]))
        } else {
            let first = sub(
                &mul_crt(&weights[level][0], &a_values[depth + rows + level - 1]),
                &mul_crt(&a_values[level], &xs[level - 1]),
            );
            sub(
                &first,
                &mul_crt(&a_values[depth + rows + level], &v_polys[level - 1]),
            )
        };
        psi_levels.push(body);
        omega_levels.push(mul_crt(
            &a_values[level],
            &a_values[depth + rows + level],
        ));
    }

    let psi_m = sub(
        &mul_crt(&gamma_m[0], &a_values[rows + 2 * depth - 1]),
        &add_all((0..depth).map(|index| mul_crt(&x_last[index], &a_values[index + 1]))),
    );
    psi_levels.push(psi_m);
    let psi_sm = sub(&add_all(psi_levels), &a_values[rows + 2 * depth]);
    let omega_sm = add_all(omega_levels);

    let psi_bin = add_all((0..depth).map(|index| {
        mul_crt(
            &alphas[index + 1],
            &mul_crt(
                &a_values[index + 1],
                &sub(&crate::constant_poly(1), &scalar(2, &v_polys[index])),
            ),
        )
    }));
    let omega_bin = add_all(
        (0..depth).map(|index| mul_crt(&alphas[index + 1], &mul_crt(&a_values[index + 1], &a_values[index + 1]))),
    );
    let psi = add(&mul_crt(&alphas[0], &psi_sm), &psi_bin);
    let omega = add(
        &add(&mul_crt(&alphas[0], &omega_sm), &omega_bin),
        &a_values[rows + 2 * depth + 1],
    );
    commitment.push(add(
        &dot(&keys.rows[rows + 2 * depth], &randomness),
        &psi,
    ));

    transcript.absorb(
        b"t-psi",
        &crate::codec::encode_poly(&commitment[commitment.len() - 1]),
    );
    transcript.absorb(b"omega", &crate::codec::encode_poly(&omega));
    let challenge = draw_ternary(&mut transcript, b"c");
    let lifted = crate::lift_challenge(&challenge);
    if !crate::verifier::is_unit(&lifted) {
        return Ok(None);
    }

    let product: Vec<Poly> = randomness.iter().map(|poly| mul_crt(&lifted, poly)).collect();
    let response: Vec<Poly> = (0..width).map(|index| add(&mask[index], &product[index])).collect();
    if reject(&response, &product, sigma_main, rng) {
        return Ok(None);
    }

    Ok(Some(Attempt {
        proof: ProofWire {
            commitment,
            h,
            omega,
            challenge,
            challenge_prime,
            response_prime,
            response,
        },
    }))
}

fn glue_crt_of(vector: Vec<Quartic>) -> Poly {
    let mut residues = [[0u64; 4]; SLOTS];
    for (index, element) in vector.iter().enumerate().take(SLOTS) {
        residues[index] = *element;
    }
    glue_crt(&residues)
}

/// Prove, retrying until rejection sampling accepts.
pub fn prove(
    keys: &Keys,
    statement: &Statement,
    secret: &[Poly],
    index: usize,
    message: &[u8],
    rng: &mut Rng,
) -> Result<ProofWire, ProofError> {
    for _ in 0..MAX_ATTEMPTS {
        Attempts::bump();
        if let Some(attempt) = prove_once(keys, statement, secret, index, message, rng)? {
            return Ok(attempt.proof);
        }
    }
    Err(ProofError("rejection sampling did not accept a proof".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rng_is_deterministic_and_in_range() {
        let mut one = Rng::new(42);
        let mut two = Rng::new(42);
        for _ in 0..10 {
            assert_eq!(one.next_u64(), two.next_u64());
        }
        let mut rng = Rng::new(7);
        for _ in 0..100 {
            assert!(rng.next_f64() < 1.0);
            assert!(rng.small(5) < Q);
        }
    }

    #[test]
    fn gaussian_samples_are_centred_with_the_right_width() {
        // A sampler with the wrong sigma would still be centred, so check both. The
        // tolerance on the mean is four standard errors; the one on the deviation is
        // about three.
        let mut rng = Rng::new(9);
        let count = 4000;
        let sigma = crate::gaussian::sigma(33);
        let samples: Vec<f64> = (0..count)
            .map(|_| crate::centered(rng.gaussian(33)) as f64)
            .collect();
        let mean = samples.iter().sum::<f64>() / count as f64;
        let variance = samples.iter().map(|x| x * x).sum::<f64>() / count as f64;
        let deviation = variance.sqrt();

        let standard_error = sigma / (count as f64).sqrt();
        assert!(mean.abs() < 4.0 * standard_error, "mean was {mean}");
        assert!(
            (deviation - sigma).abs() < 0.05 * sigma,
            "deviation was {deviation}, expected about {sigma}"
        );
    }
}
