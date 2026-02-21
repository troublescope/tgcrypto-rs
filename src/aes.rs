use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyByteArray};

#[inline(always)]
fn xor_blocks(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

#[inline(always)]
fn xor_assign(a: &mut [u8], b: &[u8]) {
    for (i, v) in a.iter_mut().enumerate() {
        *v ^= b[i];
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
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV must be 32 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }

    let result = py.allow_threads(|| {
        let cipher = Aes256::new(key.into());
        let mut iv1: [u8; 16] = iv[..16].try_into().unwrap();
        let mut iv2: [u8; 16] = iv[16..32].try_into().unwrap();

        let mut out = vec![0u8; data.len()];
        
        for (i, chunk) in data.chunks_exact(16).enumerate() {
            let mut block: [u8; 16] = chunk.try_into().unwrap();
            let old_input = block;

            xor_blocks(&mut block, &iv1);
            cipher.encrypt_block((&mut block).into());
            xor_blocks(&mut block, &iv2);

            out[i*16..(i+1)*16].copy_from_slice(&block);

            iv1 = block;
            iv2 = old_input;
        }
        out
    });

    Ok(PyBytes::new(py, &result))
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
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"));
    }
    if iv.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV must be 32 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }

    let result = py.allow_threads(|| {
        let cipher = Aes256::new(key.into());
        let mut iv1: [u8; 16] = iv[16..32].try_into().unwrap();
        let mut iv2: [u8; 16] = iv[..16].try_into().unwrap();

        let mut out = vec![0u8; data.len()];

        for (i, chunk) in data.chunks_exact(16).enumerate() {
            let block: [u8; 16] = chunk.try_into().unwrap();
            let mut decrypted = block;

            xor_blocks(&mut decrypted, &iv1);
            cipher.decrypt_block((&mut decrypted).into());
            xor_blocks(&mut decrypted, &iv2);

            out[i*16..(i+1)*16].copy_from_slice(&decrypted);

            iv1 = decrypted;
            iv2 = block;
        }
        out
    });

    Ok(PyBytes::new(py, &result))
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
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"));
    }

    let mut iv_array = [0u8; 16];
    let iv_bytes: &[u8] = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV must be 16 bytes"));
    }
    iv_array.copy_from_slice(iv_bytes);

    let state_bytes: &[u8] = state.extract().unwrap_or(&[]);
    let mut ks_pos = if !state_bytes.is_empty() { state_bytes[0] as usize } else { 0 };

    let (out_vec, final_iv, final_ks_pos) = py.allow_threads(|| {
        let cipher = Aes256::new(key.into());
        let mut out = data.to_vec();
        let mut keystream = [0u8; 16];
        let mut data_pos = 0;
        let data_len = out.len();

        // Handle initial partial block
        if ks_pos > 0 {
            keystream = iv_array;
            cipher.encrypt_block((&mut keystream).into());
            let rem = 16 - ks_pos;
            let take = std::cmp::min(rem, data_len);
            xor_assign(&mut out[..take], &keystream[ks_pos..ks_pos+take]);
            data_pos += take;
            ks_pos = (ks_pos + take) % 16;

            if ks_pos == 0 {
                for j in (0..16).rev() {
                    iv_array[j] = iv_array[j].wrapping_add(1);
                    if iv_array[j] != 0 { break; }
                }
            }
        }

        // Process full blocks
        while data_pos + 16 <= data_len {
            keystream = iv_array;
            cipher.encrypt_block((&mut keystream).into());
            
            xor_assign(&mut out[data_pos..data_pos+16], &keystream);
            data_pos += 16;

            for j in (0..16).rev() {
                iv_array[j] = iv_array[j].wrapping_add(1);
                if iv_array[j] != 0 { break; }
            }
        }

        // Handle final partial block
        if data_pos < data_len {
            keystream = iv_array;
            cipher.encrypt_block((&mut keystream).into());
            let rem = data_len - data_pos;
            xor_assign(&mut out[data_pos..], &keystream[..rem]);
            ks_pos = rem;
        }

        (out, iv_array, ks_pos)
    });

    // Update state and IV in-place if they are bytearrays
    if let Ok(state_ba) = state.downcast::<PyByteArray>() {
        if state_ba.len() > 0 {
            unsafe { state_ba.as_bytes_mut()[0] = final_ks_pos as u8 };
        }
    }
    if let Ok(iv_ba) = iv.downcast::<PyByteArray>() {
        if iv_ba.len() == 16 {
            unsafe { iv_ba.as_bytes_mut().copy_from_slice(&final_iv) };
        }
    }

    Ok(PyBytes::new(py, &out_vec))
}

/// AES-256-CTR Decryption (CTR is symmetric)
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
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"));
    }
    let iv_bytes: &[u8] = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV must be 16 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }

    let (result, final_iv) = py.allow_threads(|| {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(iv_bytes);
        let mut cipher = cbc::Encryptor::<Aes256>::new_from_slices(key, &iv_array).unwrap();
        
        let mut out = data.to_vec();
        for chunk in out.chunks_exact_mut(16) {
            cipher.encrypt_block_mut(chunk.into());
        }
        
        if !out.is_empty() {
            iv_array.copy_from_slice(&out[out.len() - 16..]);
        }
        (out, iv_array)
    });

    if let Ok(iv_ba) = iv.downcast::<PyByteArray>() {
        if iv_ba.len() == 16 {
            unsafe { iv_ba.as_bytes_mut().copy_from_slice(&final_iv) };
        }
    }

    Ok(PyBytes::new(py, &result))
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
    if key.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"));
    }
    let iv_bytes: &[u8] = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("IV must be 16 bytes"));
    }
    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Data length must be a multiple of 16"));
    }

    let (result, final_iv) = py.allow_threads(|| {
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};
        let mut iv_array = [0u8; 16];
        iv_array.copy_from_slice(iv_bytes);
        let mut cipher = cbc::Decryptor::<Aes256>::new_from_slices(key, &iv_array).unwrap();
        
        let mut last_iv = [0u8; 16];
        if !data.is_empty() {
            last_iv.copy_from_slice(&data[data.len() - 16..]);
        } else {
            last_iv.copy_from_slice(&iv_array);
        }

        let mut out = data.to_vec();
        for chunk in out.chunks_exact_mut(16) {
            cipher.decrypt_block_mut(chunk.into());
        }
        (out, last_iv)
    });

    if let Ok(iv_ba) = iv.downcast::<PyByteArray>() {
        if iv_ba.len() == 16 {
            unsafe { iv_ba.as_bytes_mut().copy_from_slice(&final_iv) };
        }
    }

    Ok(PyBytes::new(py, &result))
}
