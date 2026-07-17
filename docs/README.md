# wrela documentation

The language specification lives in [`language/README.md`](language/README.md).

The specification describes the intended language and runtime contract. It is a
design specification: examples are compiler-facing requirements, but no claim is
made here that a conforming compiler already exists.

Implementation documentation:

- [`toolchain-architecture.md`](toolchain-architecture.md) defines the compiler
  workspace and the self-contained distribution contract.
- [`design/linux-engine-host-launchers.md`](design/linux-engine-host-launchers.md)
  defines the greenfield shared Linux engine and thin Darwin/Linux launcher
  direction.
- [`crate-contracts.md`](crate-contracts.md) defines every crate's public
  boundary and the dependency graph enforced by `cargo xtask architecture-check`.
- [`implementation-plan.md`](implementation-plan.md) is the dependency-aware
  path from the current implementation to revision 0.1.
- [`requirements-to-tests.md`](requirements-to-tests.md) records the normative
  requirement families and the evidence that must prove them.
- [`verification.md`](verification.md) is the append-only maintainer record of
  focused, integration, native, and release verification runs.
