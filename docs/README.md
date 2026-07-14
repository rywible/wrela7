# wrela documentation

The language specification lives in [`language/README.md`](language/README.md).

The specification describes the intended language and runtime contract. It is a
design specification: examples are compiler-facing requirements, but no claim is
made here that a conforming compiler already exists.

Implementation documentation:

- [`toolchain-architecture.md`](toolchain-architecture.md) defines the compiler
  workspace and the self-contained distribution contract.
- [`crate-contracts.md`](crate-contracts.md) defines every crate's public
  boundary and the dependency graph enforced by `cargo xtask architecture-check`.
