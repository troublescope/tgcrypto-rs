use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyByteArray};
use ctr::cipher::{StreamCipher, StreamCipherSeek};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[inline(always)]
fn xor_block(a: &mut [u8], b: &[u8]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// AES-256-IGE Encryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, /))]
pub fn ige256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV size must be exactly 32 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }

    let cipher = Aes256::new(key.into());
    let mut iv1: [u8; 16] = iv[..16].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

    let bytes = PyBytes::new_bound_with(py, data.len(), |out| {
        py.allow_threads(|| {
            for (i, chunk) in data.chunks_exact(16).enumerate() {
                let offset = i * 16;
                let block_out = &mut out[offset..offset+16];
                block_out.copy_from_slice(chunk);
                
                let old_input: [u8; 16] = chunk.try_into().unwrap();

                xor_block(block_out, &iv1);
                cipher.encrypt_block(block_out.into());
                xor_block(block_out, &iv2);

                iv1.copy_from_slice(block_out);
                iv2 = old_input;
            }
        });
        Ok(())
    })?;

    Ok(bytes)
}

/// AES-256-IGE Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, /))]
pub fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key size must be exactly 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV size must be exactly 32 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }

    let cipher = Aes256::new(key.into());
    let mut iv1: [u8; 16] = iv[16..32].try_into().unwrap();
    let mut iv2: [u8; 16] = iv[..16].try_into().unwrap();

    let bytes = PyBytes::new_bound_with(py, data.len(), |out| {
        py.allow_threads(|| {
            for (i, chunk) in data.chunks_exact(16).enumerate() {
                let offset = i * 16;
                let block_out = &mut out[offset..offset+16];
                block_out.copy_from_slice(chunk);
                
                let old_input: [u8; 16] = chunk.try_into().unwrap();

                xor_block(block_out, &iv1);
                cipher.decrypt_block(block_out.into());
                xor_block(block_out, &iv2);

                iv1.copy_from_slice(block_out);
                iv2 = old_input;
            }
        });
        Ok(())
    })?;

    Ok(bytes)
}

/// AES-256-CTR Encryption/Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, state, /))]
pub fn ctr256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: Bound<'py, PyAny>,
    state: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key size must be exactly 32 bytes"));
    }

    let iv_bytes: &[u8] = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV size must be exactly 16 bytes"));
    }

    let state_bytes: &[u8] = state.extract()?;
    if state_bytes.len() != 1 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("State size must be exactly 1 byte"));
    }
    let ks_pos = state_bytes[0] as u64;
    if ks_pos > 15 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("State value must be in the range [0, 15]"));
    }

    let mut iv_array = [0u8; 16];
    iv_array.copy_from_slice(iv_bytes);

    let bytes = PyBytes::new_bound_with(py, data.len(), |out| {
        let (final_iv, final_ks_pos) = py.allow_threads(|| {
            let mut cipher = Aes256Ctr::new_from_slices(key, &iv_array).unwrap();
            cipher.seek(ks_pos);
            out.copy_from_slice(data);
            cipher.apply_keystream(out);
            
            let total_pos = ks_pos + data.len() as u64;
            let blocks = total_pos / 16;
            let rem = (total_pos % 16) as u8;
            
            let mut iv_new = iv_array;
            let mut carry = blocks;
            for i in (0..16).rev() {
                let (val, c) = iv_new[i].overflowing_add((carry & 0xFF) as u8);
                iv_new[i] = val;
                carry = (carry >> 8) + (c as u64);
                if carry == 0 { break; }
            }
            
            (iv_new, rem)
        });

        if let Ok(state_ba) = state.downcast::<PyByteArray>() {
            if state_ba.len() > 0 {
                unsafe { state_ba.as_bytes_mut()[0] = final_ks_pos };
            }
        }
        if let Ok(iv_ba) = iv.downcast::<PyByteArray>() {
            if iv_ba.len() == 16 {
                unsafe { iv_ba.as_bytes_mut().copy_from_slice(&final_iv) };
            }
        }
        Ok(())
    })?;

    Ok(bytes)
}

/// AES-256-CTR Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, state, /))]
pub fn ctr256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: Bound<'py, PyAny>,
    state: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    ctr256_encrypt(py, data, key, iv, state)
}

/// AES-256-CBC Encryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, /))]
pub fn cbc256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key size must be exactly 32 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }
    let iv_bytes: &[u8] = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV size must be exactly 16 bytes"));
    }

    let bytes = PyBytes::new_bound_with(py, data.len(), |out| {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(iv_bytes);
        
        let final_iv = py.allow_threads(|| {
            let mut cipher = cbc::Encryptor::<Aes256>::new_from_slices(key, &iv_array).unwrap();
            out.copy_from_slice(data);
            for chunk in out.chunks_exact_mut(16) {
                cipher.encrypt_block_mut(chunk.into());
            }
            
            let mut last_iv = [0u8; 16];
            if !out.is_empty() {
                last_iv.copy_from_slice(&out[out.len() - 16..]);
            } else {
                last_iv = iv_array;
            }
            last_iv
        });

        if let Ok(iv_ba) = iv.downcast::<PyByteArray>() {
            if iv_ba.len() == 16 {
                unsafe { iv_ba.as_bytes_mut().copy_from_slice(&final_iv) };
            }
        }
        Ok(())
    })?;

    Ok(bytes)
}

/// AES-256-CBC Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, /))]
pub fn cbc256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: &[u8],
    iv: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    if data.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data must not be empty"));
    }
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key size must be exactly 32 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }
    let iv_bytes: &[u8] = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV size must be exactly 16 bytes"));
    }

    let bytes = PyBytes::new_bound_with(py, data.len(), |out| {
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};
        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(iv_bytes);

        let final_iv = py.allow_threads(|| {
            let mut last_iv = [0u8; 16];
            if !data.is_empty() {
                last_iv.copy_from_slice(&data[data.len() - 16..]);
            } else {
                last_iv = iv_array;
            }

            let mut cipher = cbc::Decryptor::<Aes256>::new_from_slices(key, &iv_array).unwrap();
            out.copy_from_slice(data);
            for chunk in out.chunks_exact_mut(16) {
                cipher.decrypt_block_mut(chunk.into());
            }
            last_iv
        });

        if let Ok(iv_ba) = iv.downcast::<PyByteArray>() {
            if iv_ba.len() == 16 {
                unsafe { iv_ba.as_bytes_mut().copy_from_slice(&final_iv) };
            }
        }
        Ok(())
    })?;

    Ok(bytes)
}
