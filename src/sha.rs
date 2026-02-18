use ::sha1::{Digest, Sha1};
use ::sha2::Sha256;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Compute SHA-1 hash
#[pyfunction]
#[pyo3(signature = (data, /))]
pub fn sha1<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let result = py.detach(|| {
        let mut hasher = Sha1::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.to_vec()
    });
    Ok(PyBytes::new(py, &result))
}

/// Compute SHA-256 hash
#[pyfunction]
#[pyo3(signature = (data, /))]
pub fn sha256<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let result = py.detach(|| {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.to_vec()
    });
    Ok(PyBytes::new(py, &result))
}
