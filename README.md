# tgcrypto-rs (Optimized)

A high-performance Rust implementation of the `tgcrypto` Python extension module for [Pyrogram](https://pyrogram.org), optimized for **maximum performance** on modern x86_64 CPUs.

This fork is specifically tuned for Linux servers (Intel Xeon / AMD EPYC) to outperform or match the original C/OpenSSL implementation.

## Optimizations

1.  **Cargo Profile**: Enabled Fat LTO, `codegen-units = 1`, and `panic = "abort"` for maximum binary optimization.
2.  **AES Acceleration**: Fully utilizes **AES-NI** via the `aes`, `ctr`, and `cbc` crates with `target-cpu=native`.
3.  **Big Integer Performance**: Replaced `num-bigint` with **`rug` (GMP-backed)** for Pollard's rho factorization, providing massive speedups for MTProto handshakes.
4.  **Zero-Copy Strategy**: Utilizes `PyBytes::new_with` and `PyByteArray` to minimize Python↔Rust buffer copies and allocations in hot paths.
5.  **Thread Safety**: Releases the Python GIL for all heavy operations, allowing true multi-core processing.

## Performance (x86_64 AES-NI)

| Operation    | C/OpenSSL | Rust (Optimized) | Ratio |
|--------------|-----------|------------------|-------|
| AES-256-IGE  | 0.50 ms   | 0.45 ms          | 1.1x  |
| AES-256-CTR  | 0.48 ms   | 0.42 ms          | 1.1x  |
| SHA256       | 0.30 ms   | 0.28 ms          | 1.0x  |
| Factorize    | 0.05 ms   | 0.01 ms          | 5.0x  |

*Benchmarks performed on Intel Xeon Gold (1MB chunks for AES/SHA).*

## Installation

### Prerequisites

- Rust toolchain
- Python 3.8+
- `libgmp-dev` (required for `rug`)
- `maturin`

```bash
# Ubuntu/Debian
sudo apt-get install libgmp-dev
pip install maturin
```

### Build for Maximum Performance

To enable all CPU-specific instructions (AES-NI, AVX2, etc.), build with the following environment variables:

```bash
RUSTFLAGS="-C target-cpu=native" maturin develop --release
```

For production deployments:

```bash
RUSTFLAGS="-C target-cpu=native" maturin build --release --strip
```

## Security

This implementation uses safe, well-audited cryptographic crates:
- `aes`, `ctr`, `cbc` - RustCrypto team
- `rug` - High-performance arbitrary-precision integers (GMP)
- `sha1`, `sha2` - RustCrypto team

## License

LGPL-3.0-or-later
