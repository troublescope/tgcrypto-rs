use pyo3::prelude::*;
use rug::{Integer, Assign};
use rand_xorshift::XorShiftRng;
use rand::SeedableRng;
use rand::Rng;

fn pollard_rho(n: &Integer) -> Integer {
    if n.is_even() {
        return Integer::from(2);
    }
    if n.is_divisible(&Integer::from(3)) {
        return Integer::from(3);
    }

    let mut rng = XorShiftRng::from_entropy();
    
    for _ in 0..20 {
        let mut x = Integer::from(rng.gen_range(2..1000000));
        let mut y = x.clone();
        let c = Integer::from(rng.gen_range(1..1000));
        let mut d = Integer::from(1);

        let mut x2 = Integer::new();
        let mut diff = Integer::new();

        while d == 1 {
            // x = (x*x + c) % n
            x2.assign(&x * &x + &c);
            x.assign(x2.modulo_ref(n));

            // y = (y*y + c) % n, twice
            x2.assign(&y * &y + &c);
            y.assign(x2.modulo_ref(n));
            x2.assign(&y * &y + &c);
            y.assign(x2.modulo_ref(n));

            diff.assign(&x - &y);
            diff.abs_mut();
            d.assign(diff.gcd_ref(n));
        }

        if d != *n && d != 1 {
            return d;
        }
    }

    n.clone() // Should not happen for semiprimes
}

/// Find a non-trivial factor using Pollard's rho algorithm
#[pyfunction]
#[pyo3(signature = (pq, /))]
pub fn factorize(pq: i128) -> PyResult<i128> {
    if pq <= 1 {
        return Ok(pq);
    }

    let n = Integer::from(pq);
    let factor = pollard_rho(&n);

    Ok(factor.to_i128().unwrap_or(0))
}
