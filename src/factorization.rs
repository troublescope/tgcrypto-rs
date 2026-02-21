use num_integer::Integer;
use pyo3::prelude::*;
use rand::Rng;

#[inline(always)]
fn pollard_rho_u128(n: u128) -> u128 {
    if n % 2 == 0 { return 2; }
    if n % 3 == 0 { return 3; }

    let mut rng = rand::rng();

    for _ in 0..10 {
        let x_start = rng.random_range(2..std::cmp::min(n, 1000000));
        let c = rng.random_range(1..std::cmp::min(n, 1000));

        let mut x = x_start;
        let mut y = x;
        let mut d = 1;

        while d == 1 {
            // x = (x*x + c) % n
            x = (u128::wrapping_mul(x, x).wrapping_add(c)) % n;

            // y = (y*y + c) % n, twice
            y = (u128::wrapping_mul(y, y).wrapping_add(c)) % n;
            y = (u128::wrapping_mul(y, y).wrapping_add(c)) % n;

            let diff = if x > y { x - y } else { y - x };
            d = diff.gcd(&n);
        }

        if d != n && d != 1 {
            return d;
        }
    }

    // Trial division fallback for small factors
    let limit = std::cmp::min(n, 10000);
    for i in (3..limit).step_by(2) {
        if n % i == 0 { return i; }
    }

    n
}

/// Find a non-trivial factor using Pollard's rho algorithm
#[pyfunction]
#[pyo3(signature = (pq, /))]
pub fn factorize(pq: i128) -> PyResult<i128> {
    if pq <= 1 {
        return Ok(pq);
    }

    let n = pq as u128;
    let factor = pollard_rho_u128(n);

    Ok(factor as i128)
}
