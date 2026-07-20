# wrela

wrela is a language whose compilation unit is a sealed, bootable machine image.
This repository contains the language specification and the in-progress
self-contained revision-0.1 compiler toolchain.

The public command will be `wrela`. wrela does not bundle or acquire LLVM,
LLD, or QEMU: the native backend links against the LLVM already installed on
the developer's machine, the EFI linker shells out to the system `lld-link`,
and full-image tests invoke the system `qemu-system-aarch64` and system EDK2
firmware. The compiler, the AArch64 target's runtime object, and the standard
library remain wrela's own sealed artifacts.

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
fast verification succeeds; native `--full` gates run `cargo test` with the
`wrela-backend/bundled-backend` feature enabled, which builds and links
against the system LLVM/LLD (and, for the `testing`/`cli` slices, exercises
the system `qemu-system-aarch64` and firmware) and fails honestly when those
are unavailable on disk.

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

`xtask` no longer acquires or builds LLVM, LLD, or QEMU: enable the native
backend with the `wrela-backend/bundled-backend` Cargo feature, which links
`wrela-codegen-llvm` against the system LLVM (via `.cargo/config.toml`'s
`LLVM_SYS_221_PREFIX`, pointed at the on-disk install) and links
`wrela-link-efi` against the system `lld-link` (override with
`WRELA_LLD_LINK`).

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
content, compatibility, target/runtime, and running-frontend identity
verification; the presence table alone is not a success condition. QEMU and
firmware are resolved from the developer's system and are not part of the
sealed installation this checks.

See the [language specification](docs/language/README.md), the
[toolchain architecture](docs/toolchain-architecture.md), and the enforceable
[crate contracts](docs/crate-contracts.md).
