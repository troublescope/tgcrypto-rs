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

## Installation

### Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs))
- Python 3.7+
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
