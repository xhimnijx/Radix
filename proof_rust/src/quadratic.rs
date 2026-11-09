//! The quadratic equation's coefficient maps, mirroring `quadratic.py`.
//!
//! `F(c)` is the product form whose `c^2` coefficient carries the binaryness
//! constraint. These functions build and extract that coefficient; they are the
//! algebra the verifier's final check rests on.

use crate::sample::dot;
use crate::{add, mul_crt, scalar, sub, Poly, Q};

pub const INVERSE_TWO: u64 = (Q + 1) / 2;

/// `t = <b, r> + value`, the row-wise BDLOP component.
pub fn commit(b: &Poly, randomness: &Poly, value: &Poly) -> Poly {
    add(&dot(&[*b], &[*randomness]), value)
}

/// `f = <b, z> - c t`, which equals `<b, y> - c value`.
pub fn masked_response(b: &Poly, z: &Poly, t: &Poly, challenge: &Poly) -> Poly {
    sub(&dot(&[*b], &[*z]), &mul_crt(challenge, t))
}

/// `F_1 = f_1 f_3 + c gamma f_2`.
pub fn product_form(first: &Poly, third: &Poly, second: &Poly, gamma: &Poly, challenge: &Poly) -> Poly {
    let left = mul_crt(first, third);
    let scaled = mul_crt(&mul_crt(challenge, gamma), second);
    add(&left, &scaled)
}

/// Second divided difference: `(F(2) - 2F(1) + F(0)) / 2`.
pub fn quadratic_coefficient(at_zero: &Poly, at_one: &Poly, at_two: &Poly) -> Poly {
    let twice = scalar(2, at_one);
    let difference = sub(at_two, &twice);
    scalar(INVERSE_TWO, &add(&difference, at_zero))
}

/// `y_1 = v_1 . x_2 - gamma . x_1`, equation (20) at `k = m = 1`.
pub fn expected_quadratic_coefficient(v_one: &Poly, x_two: &Poly, gamma: &Poly, x_one: &Poly) -> Poly {
    sub(&mul_crt(v_one, x_two), &mul_crt(gamma, x_one))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::uniform_from;

    #[test]
    fn a_masked_response_equals_dot_minus_challenge_times_commitment() {
        let b = uniform_from(b"b", 0);
        let r = uniform_from(b"r", 0);
        let v = uniform_from(b"v", 0);
        let c = uniform_from(b"c", 0);
        let t = commit(&b, &r, &v);
        let y = uniform_from(b"y", 0);
        let z = add(&y, &mul_crt(&c, &r));

        // f = <b, z> - c t must equal <b, y> - c v, which is the whole point of
        // masking the opening: the commitment cancels and only the message survives.
        let left = masked_response(&b, &z, &t, &c);
        let right = sub(&dot(&[b], &[y]), &mul_crt(&c, &v));
        assert_eq!(left, right);
    }

    #[test]
    fn the_second_divided_difference_extracts_the_c2_coefficient() {
        // F(c) = c^2 * k for a fixed k: (F(2) - 2F(1) + F(0))/2 == k.
        let k = uniform_from(b"k", 0);
        let at = |c: u64| scalar(c * c, &k);
        assert_eq!(quadratic_coefficient(&at(0), &at(1), &at(2)), k);
    }

    #[test]
    fn inverse_two_is_a_genuine_inverse() {
        assert_eq!((2u128 * INVERSE_TWO as u128 % Q as u128) as u64, 1);
    }

    #[test]
    fn the_coefficient_matches_the_python_reference() {
        // python: experiments/port_vectors.py
        //   quadratic.quadratic_coefficient(a0, a1, a2) digest == cf184ee96560b0a761b8649d182416b8
        let a0 = uniform_from(b"a0", 0);
        let a1 = uniform_from(b"a1", 0);
        let a2 = uniform_from(b"a2", 0);
        let coefficient = quadratic_coefficient(&a0, &a1, &a2);
        let mut digest = [0u8; 16];
        crate::sha3::shake256(&crate::codec::encode_poly(&coefficient), &mut digest);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "cf184ee96560b0a761b8649d182416b8");
    }

    #[test]
    fn the_expected_coefficient_matches_the_python_reference() {
        // python: digest == e512cc05e803a60bfc9efccde3752480
        let a0 = uniform_from(b"a0", 0);
        let a1 = uniform_from(b"a1", 0);
        let a2 = uniform_from(b"a2", 0);
        let a3 = uniform_from(b"a3", 0);
        let value = expected_quadratic_coefficient(&a0, &a1, &a2, &a3);
        let mut digest = [0u8; 16];
        crate::sha3::shake256(&crate::codec::encode_poly(&value), &mut digest);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "e512cc05e803a60bfc9efccde3752480");
    }

    #[test]
    fn the_expected_coefficient_is_linear_in_its_inputs() {
        let v_one = uniform_from(b"v1", 0);
        let x_two = uniform_from(b"x2", 0);
        let gamma = uniform_from(b"g", 0);
        let x_one = uniform_from(b"x1", 0);
        let expected = expected_quadratic_coefficient(&v_one, &x_two, &gamma, &x_one);
        let direct = sub(&mul_crt(&v_one, &x_two), &mul_crt(&gamma, &x_one));
        assert_eq!(expected, direct);
    }
}
