use pyo3::prelude::*;

mod aes;
mod factorization;
mod mtproto;
mod rsa;
mod sha;

#[pymodule]
fn tgcrypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sha::sha1, m)?)?;
    m.add_function(wrap_pyfunction!(sha::sha256, m)?)?;
    m.add_function(wrap_pyfunction!(aes::ige256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes::ige256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes::ctr256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes::ctr256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes::cbc256_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes::cbc256_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(rsa::rsa_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(factorization::factorize, m)?)?;
    m.add_function(wrap_pyfunction!(mtproto::get_session_id, m)?)?;
    Ok(())
}
