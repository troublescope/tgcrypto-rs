use ::sha1::{Digest, Sha1};
use ::sha2::Sha256;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Compute SHA-1 hash
#[pyfunction]
#[pyo3(signature = (data, /))]
pub fn sha1<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    // For small data, the overhead of releasing GIL might be higher than hashing.
    // However, to be safe and consistent with other crypto functions, we allow threads.
    // SHA-1 is fast, but 1MB+ buffers exist.
    let result = py.allow_threads(|| {
        let mut hasher = Sha1::new();
        hasher.update(data);
        hasher.finalize()
    });
    // result is GenericArray<u8, U20>, which is effectively [u8; 20]
    Ok(PyBytes::new(py, &result))
}

/// Compute SHA-256 hash
#[pyfunction]
#[pyo3(signature = (data, /))]
pub fn sha256<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let result = py.allow_threads(|| {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    });
    // result is GenericArray<u8, U32>, effectively [u8; 32]
    Ok(PyBytes::new(py, &result))
}
