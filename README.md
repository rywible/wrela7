# wrela

wrela is a language whose compilation unit is a sealed, bootable machine image.
This repository contains the language specification and the in-progress
self-contained revision-0.1 compiler toolchain.

The public command will be `wrela`. Release archives will include the compiler,
the LLVM code-generation backend, the LLD COFF linker, the AArch64 target,
runtime and UEFI firmware, QEMU for full-image tests, the standard library, and
required licenses. Installing those components separately is not part of the
user contract.

## Development

The workspace builds without LLVM by default. The trustworthy focused loop is
one locked, offline gate for a named slice or exact workspace crate:

```text
cargo xtask slices
cargo xgate semantic
cargo xgate wrela-sema
```

`xgate` prints and validates its selected roots, reviewed workspace and external
dependency closures, immediate boundaries, checked-in fixture families, native
requirements, commands, and timing budget. It then runs package-scoped rustfmt,
`cargo check --all-targets`, unfiltered unit/contract tests, Clippy with warnings
denied, and architecture validation. Arbitrary extra arguments and test filters
are rejected so a caller cannot turn acceptance into a zero-test filtered run.
Non-native `--full` gates report that no additional check applies only after
fast verification succeeds; native `--full` gates invoke the applicable
LLVM or distribution path and fail honestly while that path is unavailable.

`cargo xcheck`, `cargo xtest`, and `cargo xlint` remain available as granular
developer commands and accept either a named boundary or one exact crate. They
are not substitutes for `xgate`; `xcheck` and `xtest` continue to accept explicit
Cargo/test arguments for local diagnosis. Full repository handoff gates are:

```text
cargo xgate all
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

LLVM/LLD acquisition and distribution assembly live behind `cargo xtask` and
use the exact revision recorded in [`toolchain/llvm.lock.toml`](toolchain/llvm.lock.toml).

The supported public command shapes currently include:

```text
wrela check <wrela.toml> <IMAGE> [--target aarch64-qemu-virt-uefi]
            [--profile <PROFILE>] [--warnings-as-errors]
            [--maximum-diagnostics <COUNT>]
wrela build <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY]
            [--target aarch64-qemu-virt-uefi] [--profile <PROFILE>]
            [--warnings-as-errors] [--maximum-diagnostics <COUNT>]
wrela test <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY]
           [--comptime | --integration | --images | --name-contains <TEXT>]
           [--target aarch64-qemu-virt-uefi] [--profile <PROFILE>]
           [--warnings-as-errors] [--maximum-diagnostics <COUNT>]
wrela lint <wrela.toml> <IMAGE> [--target aarch64-qemu-virt-uefi]
           [--profile <PROFILE>] [--warnings-as-errors]
           [--maximum-diagnostics <COUNT>]
wrela format [--check] <wrela.toml> <FILE>...
wrela doctor
```

These commands are real for the explicitly supported minimum semantic surface;
they are not a claim that the full language specification is implemented.
`wrela doctor` reports a complete installation healthy only after bounded
content, compatibility, target/runtime/firmware, and running-frontend identity
verification; the presence table alone is not a success condition.

See the [language specification](docs/language/README.md), the
[toolchain architecture](docs/toolchain-architecture.md), and the enforceable
[crate contracts](docs/crate-contracts.md).
