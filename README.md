# wrela

wrela is a language whose compilation unit is a sealed, bootable machine image.
This repository contains the language specification and the beginnings of its
self-contained compiler toolchain.

The public command will be `wrela`. Release archives will include the compiler,
the LLVM code-generation backend, the LLD COFF linker, the AArch64 target,
runtime and UEFI firmware, QEMU for full-image tests, the standard library, and
required licenses. Installing those components separately is not part of the
user contract.

## Development

The workspace builds without LLVM by default. The fastest loop is a named slice:

```text
cargo xtask slices
cargo xcheck semantic
cargo xtest flow
cargo xlint backend
cargo xcheck wrela-sema
```

Each command accepts either a named boundary or one exact workspace crate, and
Cargo builds only its dependency closure. The architecture gate also rejects a
declared workspace edge with no source use and any interface crate without
contract tests. Extra Cargo/test arguments can follow
`xcheck` and `xtest`, for example `cargo xtest ir -- interrupt_route`.
Full handoff gates are:

```text
cargo xtest all
cargo xlint all
cargo xfmt
WRELA_TOOLCHAIN_ROOT="$PWD" cargo run -- doctor
cargo xarch
cargo xtask help
```

Compiler layers are ordinary workspace crates and can be developed in
isolation, for example:

```text
cargo test -p wrela-syntax
cargo test -p wrela-sema
cargo test -p wrela-semantic-wir
cargo test -p wrela-flow-wir
cargo test -p wrela-machine-wir
cargo test -p wrela-flow-wir-codec
cargo test -p wrela-link-efi
```

LLVM/LLD acquisition and distribution assembly will live behind `cargo xtask`
and use the exact revision recorded in [`toolchain/llvm.lock.toml`](toolchain/llvm.lock.toml).

See the [language specification](docs/language/README.md), the
[toolchain architecture](docs/toolchain-architecture.md), and the enforceable
[crate contracts](docs/crate-contracts.md).
