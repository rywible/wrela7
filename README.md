# wrela

wrela is a language whose compilation unit is a sealed, bootable machine image.
This repository contains the language specification and the beginnings of its
self-contained compiler toolchain.

The public command will be `wrela`. Release archives will include the compiler,
the LLVM code-generation backend, the LLD COFF linker, target descriptions, the
standard library, and required licenses. Installing LLVM or LLD separately is
not part of the user contract.

## Development

The initial workspace builds without LLVM while the frontend and WIR take
shape:

```text
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
WRELA_TOOLCHAIN_ROOT="$PWD" cargo run -- doctor
cargo xtask help
```

Compiler layers are ordinary workspace crates and can be developed in
isolation, for example:

```text
cargo test -p wrela-syntax
cargo test -p wrela-sema
cargo test -p wrela-wir-passes
cargo test -p wrela-wir-codec
cargo test -p wrela-link-efi
```

LLVM/LLD acquisition and distribution assembly will live behind `cargo xtask`
and use the exact revision recorded in [`toolchain/llvm.lock.toml`](toolchain/llvm.lock.toml).

See the [language specification](docs/language/README.md) and the
[toolchain architecture](docs/toolchain-architecture.md).
