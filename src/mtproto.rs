use ::sha1::{Digest, Sha1};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Generate session ID from auth key
/// The session ID is the first 8 bytes of SHA1(auth_key) in reverse byte order
#[pyfunction]
#[pyo3(text_signature = "(auth_key, /)")]
pub fn get_session_id(py: Python, auth_key: &[u8]) -> PyResult<PyObject> {
    let session_id = py.allow_threads(|| {
        let mut hasher = Sha1::new();
        hasher.update(auth_key);
        let hash = hasher.finalize();

        // Take first 8 bytes and reverse them (little-endian)
        let mut session_id = [0u8; 8];
        session_id.copy_from_slice(&hash[..8]);
        session_id.reverse();
        session_id
    });

    Ok(PyBytes::new(py, &session_id).into())
}
