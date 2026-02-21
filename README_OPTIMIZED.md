# Optimized tgcrypto-rs

This version of `tgcrypto-rs` has been heavily optimized for performance on x86_64 CPUs (AVX2/AES-NI).

## Key Changes

1.  **Cargo Profile**:
    -   Enabled Fat LTO (Link Time Optimization)
    -   Set codegen units to 1 (better optimization at cost of compile time)
    -   Aborts on panic (smaller binary, no unwinding overhead)
    -   Strip symbols
    -   Overflow checks disabled in release

2.  **CPU Optimization**:
    -   Added `.cargo/config.toml` to force `-C target-cpu=native`. This enables AVX2, AES-NI, and other instruction sets available on the build machine.
    -   **Important**: Build on the target machine or use `RUSTFLAGS="-C target-cpu=skylake"` (or similar) if building for a different machine.

3.  **Code Optimization**:
    -   **AES-IGE/CTR/CBC**: Removed unnecessary heap allocations (`Vec<u8>`). Switched to stack-allocated arrays where possible.
    -   **Threading**: Used `py.allow_threads` appropriately to release GIL for heavy operations without overhead for tiny ones (like `get_session_id`).
    -   **SHA**: Eliminated `Vec` return types, returning Python bytes directly from stack arrays.
    -   **Factorization**: Replaced `num-bigint` with `u128` arithmetic for Pollard's rho, which is orders of magnitude faster and allocation-free for `i128` inputs.
    -   **RSA**: Switched to `rug` (GMP bindings) for modular exponentiation. This provides significant speedup over `num-bigint`.

4.  **Dependencies**:
    -   Added `rug` (requires `libgmp-dev` or `gmp` package).
    -   Added `criterion` for benchmarking.

## Build Instructions

### Prerequisites

Ensure you have Rust and GMP installed:

```bash
# Ubuntu/Debian
sudo apt install build-essential libgmp-dev python3-dev

# RHEL/CentOS
sudo dnf install gcc gmp-devel python3-devel

# Alpine
apk add build-base gmp-dev python3-dev
```

### Building

To build the optimized wheel:

```bash
maturin build --release
```

Or manually with cargo:

```bash
cargo build --release
```

### Benchmarking

Run the criterion benchmarks to verify performance:

```bash
cargo bench
```

## expected Performance Impact

-   **AES-IGE**: ~20-50% speedup due to LTO and buffer reuse.
-   **AES-CTR**: ~30% speedup from block-level processing and reduced overhead.
-   **Factorization**: >10x speedup (u128 vs BigInt).
-   **RSA**: ~2-5x speedup (GMP vs num-bigint).
-   **SHA**: Minor speedup from reduced allocation.

## Comparison Notes

-   **Before**: Heavy use of `Vec<u8>` and `BigUint` caused frequent heap allocations and cache pressure. `num-bigint` is pure Rust but slower than GMP for large number arithmetic.
-   **After**: Stack allocation dominates hot paths. `target-cpu=native` allows the compiler to vectorise loops using AVX2.
