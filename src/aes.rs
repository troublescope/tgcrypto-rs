use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit};
use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyByteArray};

#[inline]
fn xor_blocks(a: &mut [u8; 16], b: &[u8; 16]) {
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
    key: Bound<'py, PyAny>,
    iv: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Convert key (bytes or bytearray) to Vec<u8>
    let key_bytes: Vec<u8> = key.extract()?;
    if key_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Key must be 32 bytes",
        ));
    }

    // Convert iv (bytes or bytearray) to Vec<u8>
    let iv_bytes: Vec<u8> = iv.extract()?;
    if iv_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "IV must be 32 bytes",
        ));
    }

    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Data length must be a multiple of 16",
        ));
    }

    let result = py.detach(|| {
        let cipher = Aes256::new(key_bytes.as_slice().into());
        // For encryption: iv1 = iv[0:16], iv2 = iv[16:32]
        let mut iv1: [u8; 16] = iv_bytes[..16].try_into().unwrap();
        let mut iv2: [u8; 16] = iv_bytes[16..].try_into().unwrap();

        let mut result = vec![0u8; data.len()];

        for (i, chunk) in data.chunks(16).enumerate() {
            let mut block: [u8; 16] = chunk.try_into().unwrap();
            let old_input = block;  // Save original input for iv2 update

            // XOR with iv1
            xor_blocks(&mut block, &iv1);
            // AES encrypt
            cipher.encrypt_block((&mut block).into());
            // XOR with iv2
            xor_blocks(&mut block, &iv2);

            result[i*16..(i+1)*16].copy_from_slice(&block);

            // Update IVs: iv1 = output, iv2 = original input
            iv1 = block;
            iv2 = old_input;
        }

        result
    });

    Ok(PyBytes::new(py, &result))
}

/// AES-256-IGE Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, /))]
pub fn ige256_decrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: Bound<'py, PyAny>,
    iv: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Convert key (bytes or bytearray) to Vec<u8>
    let key_bytes: Vec<u8> = key.extract()?;
    if key_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Key must be 32 bytes",
        ));
    }

    // Convert iv (bytes or bytearray) to Vec<u8>
    let iv_bytes: Vec<u8> = iv.extract()?;
    if iv_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "IV must be 32 bytes",
        ));
    }

    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Data length must be a multiple of 16",
        ));
    }

    let result = py.detach(|| {
        let cipher = Aes256::new(key_bytes.as_slice().into());
        // For decryption: iv2 = iv[0:16], iv1 = iv[16:32] (SWAPPED!)
        let mut iv1: [u8; 16] = iv_bytes[16..].try_into().unwrap();
        let mut iv2: [u8; 16] = iv_bytes[..16].try_into().unwrap();

        let mut result = vec![0u8; data.len()];

        for (i, chunk) in data.chunks(16).enumerate() {
            let block: [u8; 16] = chunk.try_into().unwrap();
            let old_input = block;  // Save original input (ciphertext) for iv1 update

            let mut decrypted = block;
            // XOR with iv1 first (matches C implementation)
            xor_blocks(&mut decrypted, &iv1);
            // AES decrypt
            cipher.decrypt_block((&mut decrypted).into());
            // XOR with iv2
            xor_blocks(&mut decrypted, &iv2);

            result[i*16..(i+1)*16].copy_from_slice(&decrypted);

            // Update IVs: iv1 = output (decrypted), iv2 = original input (ciphertext)
            // This matches the C implementation: memcpy(iv1, &out[i], ...); memcpy(iv2, chunk, ...);
            iv1 = decrypted;
            iv2 = old_input;
        }

        result
    });

    Ok(PyBytes::new(py, &result))
}

/// AES-256-CTR Encryption/Decryption
/// This matches the pyaes implementation where state[0] is the position in the keystream block
#[pyfunction]
#[pyo3(signature = (data, key, iv, state, /))]
pub fn ctr256_encrypt<'py>(
    py: Python<'py>,
    data: Bound<'py, PyAny>,
    key: Bound<'py, PyAny>,
    iv: Bound<'py, PyAny>,
    state: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Convert key (bytes or bytearray) to Vec<u8>
    let key_bytes: Vec<u8> = key.extract()?;
    if key_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Key must be 32 bytes",
        ));
    }

    // Convert data (bytes or bytearray) to Vec<u8>
    let data_bytes: Vec<u8> = data.extract()?;

    // Convert iv (bytes or bytearray) to Vec<u8>
    let iv_bytes: Vec<u8> = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "IV must be 16 bytes",
        ));
    }

    // Extract state position (state[0] is position in keystream block 0-15)
    let state_bytes: Vec<u8> = state.extract().unwrap_or_default();
    let mut ks_pos = if !state_bytes.is_empty() { state_bytes[0] as usize } else { 0 };

    let out = py.detach(|| {
        let cipher = Aes256::new(key_bytes.as_slice().into());
        let mut out = data_bytes;
        let mut iv_array: [u8; 16] = iv_bytes.try_into().unwrap();
        let mut keystream = [0u8; 16];
        let mut keystream_valid = false;

        // Optimized loop: process full blocks if aligned
        // For now, keep the byte loop but it can be optimized
        // Let's at least avoid the keystream generation check every byte if possible
        
        for i in 0..out.len() {
            if ks_pos == 0 || !keystream_valid {
                keystream = iv_array;
                cipher.encrypt_block((&mut keystream).into());
                keystream_valid = true;
            }

            out[i] ^= keystream[ks_pos];
            ks_pos += 1;

            if ks_pos >= 16 {
                ks_pos = 0;
                // Increment IV as big-endian 128-bit counter
                // Unrolling or optimizing this loop could help slightly
                for j in (0..16).rev() {
                    iv_array[j] = iv_array[j].wrapping_add(1);
                    if iv_array[j] != 0 {
                        break;
                    }
                }
                keystream_valid = false;
            }
        }

        (out, iv_array, ks_pos)
    });

    let (out_bytes, final_iv, final_state) = out;

    // Update state bytearray
    if let Ok(state_bytes_obj) = state.cast_into::<PyByteArray>() {
        if state_bytes_obj.len() > 0 {
            let slice = unsafe { state_bytes_obj.as_bytes_mut() };
            slice[0] = final_state as u8;
        }
    }

    // Update IV bytearray
    if let Ok(iv_bytes_obj) = iv.cast_into::<PyByteArray>() {
        if iv_bytes_obj.len() == 16 {
            let slice = unsafe { iv_bytes_obj.as_bytes_mut() };
            slice.copy_from_slice(&final_iv);
        }
    }

    Ok(PyBytes::new(py, &out_bytes))
}

/// AES-256-CTR Decryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, state, /))]
pub fn ctr256_decrypt<'py>(
    py: Python<'py>,
    data: Bound<'py, PyAny>,
    key: Bound<'py, PyAny>,
    iv: Bound<'py, PyAny>,
    state: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    // CTR mode is symmetric
    ctr256_encrypt(py, data, key, iv, state)
}

/// AES-256-CBC Encryption
#[pyfunction]
#[pyo3(signature = (data, key, iv, /))]
pub fn cbc256_encrypt<'py>(
    py: Python<'py>,
    data: &[u8],
    key: Bound<'py, PyAny>,
    iv: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Convert key (bytes or bytearray) to Vec<u8>
    let key_bytes: Vec<u8> = key.extract()?;
    if key_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Key must be 32 bytes",
        ));
    }

    // Convert iv (bytes or bytearray) to Vec<u8>
    let iv_bytes: Vec<u8> = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "IV must be 16 bytes",
        ));
    }

    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Data length must be a multiple of 16",
        ));
    }

    let (result, final_iv) = py.detach(|| {
        let mut iv_array: [u8; 16] = iv_bytes.try_into().unwrap();
        let mut cipher = cbc::Encryptor::<Aes256>::new_from_slices(&key_bytes, &iv_array).unwrap();
        
        // Single copy: Input -> Result Vec
        let mut result = data.to_vec();
        
        // Process in place
        for chunk in result.chunks_mut(16) {
            cipher.encrypt_block_mut(chunk.into());
        }
        
        // Final IV is the last ciphertext block
        if !result.is_empty() {
            iv_array.copy_from_slice(&result[result.len() - 16..]);
        }
        
        (result, iv_array)
    });

    // Update IV bytearray
    if let Ok(iv_bytes_obj) = iv.cast_into::<PyByteArray>() {
        if iv_bytes_obj.len() == 16 {
            let slice = unsafe { iv_bytes_obj.as_bytes_mut() };
            slice.copy_from_slice(&final_iv);
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
    key: Bound<'py, PyAny>,
    iv: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Convert key (bytes or bytearray) to Vec<u8>
    let key_bytes: Vec<u8> = key.extract()?;
    if key_bytes.len() != 32 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Key must be 32 bytes",
        ));
    }

    // Convert iv (bytes or bytearray) to Vec<u8>
    let iv_bytes: Vec<u8> = iv.extract()?;
    if iv_bytes.len() != 16 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "IV must be 16 bytes",
        ));
    }

    if data.len() % 16 != 0 {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "Data length must be a multiple of 16",
        ));
    }

    let (result, final_iv) = py.detach(|| {
        let iv_array: [u8; 16] = iv_bytes.try_into().unwrap();
        let mut cipher = cbc::Decryptor::<Aes256>::new_from_slices(&key_bytes, &iv_array).unwrap();
        
        // Final IV is the last ciphertext block (from original data)
        let mut last_iv = [0u8; 16];
        if !data.is_empty() {
            last_iv.copy_from_slice(&data[data.len() - 16..]);
        } else {
            last_iv = iv_array;
        }

        // Single copy: Input -> Result Vec
        let mut result = data.to_vec();
        for chunk in result.chunks_mut(16) {
            cipher.decrypt_block_mut(chunk.into());
        }
        
        (result, last_iv)
    });

    // Update IV bytearray
    if let Ok(iv_bytes_obj) = iv.cast_into::<PyByteArray>() {
        if iv_bytes_obj.len() == 16 {
            let slice = unsafe { iv_bytes_obj.as_bytes_mut() };
            slice.copy_from_slice(&final_iv);
        }
    }

    Ok(PyBytes::new(py, &result))
}
