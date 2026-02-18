use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive, Zero};
use pyo3::prelude::*;
use rand::Rng;

/// Pollard's rho algorithm for integer factorization
/// Returns a non-trivial factor of pq
fn pollard_rho(n: &BigUint) -> BigUint {
    let two = BigUint::from(2u32);
    let one = BigUint::one();

    if n.is_even() {
        return two;
    }

    let mut rng = rand::thread_rng();

    // Try different starting values and constants if needed
    for _ in 0..10 {
        let x_start: u32 = rng.gen_range(2..1000);
        let c: u32 = rng.gen_range(1..100);

        let mut x = BigUint::from(x_start);
        let mut y = x.clone();
        let c_big = BigUint::from(c);
        let mut d = BigUint::one();

        while d.is_one() {
            // x = (x^2 + c) mod n
            x = (&x * &x + &c_big) % n;

            // y = (y^2 + c) mod n, twice (Floyd's cycle-finding)
            y = (&y * &y + &c_big) % n;
            y = (&y * &y + &c_big) % n;

            // d = gcd(|x - y|, n)
            let diff = if x > y { &x - &y } else { &y - &x };
            d = diff.gcd(n);
        }

        if d != *n && d != one {
            return d;
        }
    }

    // Fallback: simple trial division for small factors
    for i in 3..10000u32 {
        let i_big = BigUint::from(i);
        if (n % &i_big).is_zero() {
            return i_big;
        }
    }

    // Last resort: return n itself (shouldn't happen for valid PQ)
    n.clone()
}

/// Find a non-trivial factor using Pollard's rho algorithm
#[pyfunction]
#[pyo3(text_signature = "(pq, /)")]
pub fn factorize(_py: Python, pq: i128) -> PyResult<i128> {
    if pq <= 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "pq must be positive",
        ));
    }

    let pq_big = BigUint::from(pq as u128);
    let factor = pollard_rho(&pq_big);

    // Convert back to i128
    let result = factor.to_i128().unwrap_or(pq);

    Ok(result)
}
