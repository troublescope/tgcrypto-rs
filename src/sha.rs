use ::sha1::{Digest, Sha1};
use ::sha2::Sha256;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Compute SHA-1 hash
#[pyfunction]
#[pyo3(signature = (data, /))]
pub fn sha1<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = PyBytes::new_bound_with(py, 20, |out| {
        py.allow_threads(|| {
            let mut hasher = Sha1::new();
            hasher.update(data);
            out.copy_from_slice(&hasher.finalize());
        });
        Ok(())
    })?;
    Ok(bytes)
}

/// Compute SHA-256 hash
#[pyfunction]
#[pyo3(signature = (data, /))]
pub fn sha256<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = PyBytes::new_bound_with(py, 32, |out| {
        py.allow_threads(|| {
            let mut hasher = Sha256::new();
            hasher.update(data);
            out.copy_from_slice(&hasher.finalize());
        });
        Ok(())
    })?;
    Ok(bytes)
}
