# tgcrypto-rs

A high-performance Rust implementation of the `tgcrypto` Python extension module for [Pyrogram](https://pyrogram.org).

This module provides cryptographic primitives required for Telegram's MTProto protocol, implemented in Rust for optimal performance and security.

## Features

- **AES-256-IGE** encryption/decryption
- **AES-256-CTR** encryption/decryption
- **AES-256-CBC** encryption/decryption
- **SHA-1** hashing
- **SHA-256** hashing
- **RSA** encryption with Telegram server public keys
- **Pollard's rho** integer factorization for MTProto handshake
- **MTProto helpers** (session ID generation)

## Recent Updates

- **PyO3 0.28+**: Updated to the latest PyO3 for better performance and support for Python 3.13.
- **Modern Dependencies**: Updated all cryptographic and utility crates to their latest stable versions.
- **Enhanced Type Hints**: Improved `.pyi` file for better IDE support.
- **Modern CI/CD**: Updated GitHub Actions to use latest tools and secure publishing.

## Performance Comparison

Benchmarks were performed on 64KB data chunks (Android, AArch64).

| Operation | Official (C) | Rust (Current) | Ratio |
|-----------|--------------|----------------|-------|
| AES-IGE   | 0.53 ms      | 2.92 ms        | 0.18x |
| AES-CTR   | 0.66 ms      | 2.97 ms        | 0.22x |
| AES-CBC   | 0.50 ms      | 2.77 ms        | 0.18x |
| SHA1      | N/A          | 0.15 ms        | -     |
| SHA256    | N/A          | 0.30 ms        | -     |
| RSA Enc.  | N/A          | 0.64 ms        | -     |
| Fact.     | N/A          | 0.004 ms       | -     |

*Note: The official C implementation uses highly optimized assembly for AES on ARM, whereas this Rust implementation currently uses the standard `aes` crate. Future optimizations may close this gap.*

## Installation

### Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs))
- Python 3.8+
- `maturin` for building Python extensions

```bash
pip install maturin
```

### Build and Install

```bash
cd pyrogram-tgcrypto
maturin develop --release
```

This will compile the Rust code and install the `tgcrypto` module into your current Python environment.

## Usage

Once installed, the module can be imported directly in Python:

```python
import tgcrypto

# AES-256-IGE
encrypted = tgcrypto.ige256_encrypt(data, key, iv)
decrypted = tgcrypto.ige256_decrypt(encrypted, key, iv)

# AES-256-CTR
encrypted = tgcrypto.ctr256_encrypt(data, key, iv, state)
decrypted = tgcrypto.ctr256_decrypt(encrypted, key, iv, state)

# AES-256-CBC
encrypted = tgcrypto.cbc256_encrypt(data, key, iv)
decrypted = tgcrypto.cbc256_decrypt(encrypted, key, iv)

# Hashing
sha1_hash = tgcrypto.sha1(data)
sha256_hash = tgcrypto.sha256(data)

# RSA encryption
encrypted = tgcrypto.rsa_encrypt(data, fingerprint)

# Factorization
factor = tgcrypto.factorize(pq)

# Session ID
session_id = tgcrypto.get_session_id(auth_key)
```

## API Reference

### `ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes`
Encrypt data using AES-256 in IGE mode.
- `data`: Must be a multiple of 16 bytes
- `key`: Must be 32 bytes
- `iv`: Must be 32 bytes

### `ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes`
Decrypt data using AES-256 in IGE mode.

### `ctr256_encrypt(data: bytes, key: bytes, iv: bytes, state: int) -> bytes`
Encrypt data using AES-256 in CTR mode.
- `data`: Any length
- `key`: Must be 32 bytes
- `iv`: Must be 16 bytes
- `state`: Counter state offset

### `ctr256_decrypt(data: bytes, key: bytes, iv: bytes, state: int) -> bytes`
Decrypt data using AES-256 in CTR mode.

### `cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes`
Encrypt data using AES-256 in CBC mode.
- `data`: Must be a multiple of 16 bytes
- `key`: Must be 32 bytes
- `iv`: Must be 16 bytes

### `cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes`
Decrypt data using AES-256 in CBC mode.

### `sha1(data: bytes) -> bytes`
Compute SHA-1 hash of data. Returns 20 bytes.

### `sha256(data: bytes) -> bytes`
Compute SHA-256 hash of data. Returns 32 bytes.

### `rsa_encrypt(data: bytes, fingerprint: int) -> bytes`
Encrypt data using RSA with Telegram server public key.
- `data`: Data to encrypt
- `fingerprint`: Telegram server key fingerprint (e.g., `-4344800451088585951`)

Returns 256-byte encrypted data.

### `factorize(pq: int) -> int`
Find a non-trivial factor of a semiprime number using Pollard's rho algorithm.
Used in MTProto key exchange.

### `get_session_id(auth_key: bytes) -> bytes`
Generate session ID from authentication key.
Returns 8 bytes.

## Performance

This Rust implementation provides significant performance improvements over pure Python implementations:

- **AES operations**: ~10-50x faster
- **Hashing**: ~5-20x faster
- **Factorization**: ~100x+ faster for large numbers

The GIL is released during heavy cryptographic operations, allowing true parallelism in multi-threaded applications.

## Security

This implementation uses well-audited cryptographic crates:
- `aes` - AES block cipher
- `ctr` - CTR mode
- `cbc` - CBC mode
- `sha1` - SHA-1 hash
- `sha2` - SHA-2 family hashes
- `num-bigint` - Big integer arithmetic

No unsafe code is used for cryptographic operations.

## License

LGPL-3.0-or-later (same as original tgcrypto)

## Acknowledgments

- Original tgcrypto by Dan (<https://github.com/delivrance>)
- Pyrogram project (<https://github.com/pyrogram/pyrogram>)
