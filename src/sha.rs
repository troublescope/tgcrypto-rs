use ::sha1::{Digest, Sha1};
use ::sha2::Sha256;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Compute SHA-1 hash
#[pyfunction]
#[pyo3(text_signature = "(data, /)")]
pub fn sha1(py: Python, data: &[u8]) -> PyResult<PyObject> {
    let result = py.allow_threads(|| {
        let mut hasher = Sha1::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.to_vec()
    });
    Ok(PyBytes::new(py, &result).into())
}

/// Compute SHA-256 hash
#[pyfunction]
#[pyo3(text_signature = "(data, /)")]
pub fn sha256(py: Python, data: &[u8]) -> PyResult<PyObject> {
    let result = py.allow_threads(|| {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        result.to_vec()
    });
    Ok(PyBytes::new(py, &result).into())
}
