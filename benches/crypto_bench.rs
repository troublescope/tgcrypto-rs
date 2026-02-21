use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tgcrypto::{ige256_encrypt, ige256_decrypt, ctr256_encrypt, factorize, sha256};
use pyo3::prelude::*;
use pyo3::types::PyByteArray;

fn aes_bench(c: &mut Criterion) {
    let key = [0u8; 32];
    let iv = [0u8; 32];
    let data = vec![0u8; 1024 * 1024]; // 1MB

    c.bench_function("ige256_encrypt_1mb", |b| {
        Python::with_gil(|py| {
            b.iter(|| {
                ige256_encrypt(py, black_box(&data), black_box(&key), black_box(&iv)).unwrap()
            })
        })
    });

    c.bench_function("ige256_decrypt_1mb", |b| {
        Python::with_gil(|py| {
            b.iter(|| {
                ige256_decrypt(py, black_box(&data), black_box(&key), black_box(&iv)).unwrap()
            })
        })
    });

    c.bench_function("ctr256_encrypt_1mb", |b| {
        Python::with_gil(|py| {
            let iv_py = PyByteArray::new_bound(py, &iv[..16]).into_any();
            let state = PyByteArray::new_bound(py, &[0u8]).into_any();
            b.iter(|| {
                ctr256_encrypt(py, black_box(&data), black_box(&key), black_box(iv_py.clone()), black_box(state.clone())).unwrap()
            })
        })
    });
}

fn hash_bench(c: &mut Criterion) {
    let data = vec![0u8; 1024 * 1024]; // 1MB

    c.bench_function("sha256_1mb", |b| {
        Python::with_gil(|py| {
            b.iter(|| {
                sha256(py, black_box(&data)).unwrap()
            })
        })
    });
}

fn factorize_bench(c: &mut Criterion) {
    // A typical 128-bit PQ from MTProto
    let pq = 159987483562304910234857612349875612349i128; 

    c.bench_function("factorize_128", |b| {
        b.iter(|| {
            factorize(black_box(pq)).unwrap()
        })
    });
}

criterion_group!(benches, aes_bench, hash_bench, factorize_bench);
criterion_main!(benches);
