# Compiler crates

The workspace is split at sealed, independently testable data contracts.

```text
manifest/lock/provider -> package-loader -> source/package graph
  -> syntax (lossless typed AST)
  -> hir-lower -> resolved HIR
  -> sema -> sealed AnalyzedImage
  -> semantic-lower -> SemanticWir
  -> flow-lower -> FlowWir
  -> private FlowWir codec/backend boundary
  -> flow-opt -> optimized FlowWir
  -> machine-lower -> AArch64 MachineWir
  -> LLVM COFF + target runtime -> EFI linker -> .efi + report
```

`wrela-compiler` is the sole wide composition root. It injects every phase
trait and bounded host capability into the small public `wrela-driver` API;
lower crates never depend back on either orchestration implementation state.
`wrela-engine` is the executable authority boundary around that composition
root: it accepts only canonical engine-protocol records plus explicit private
staging/toolchain capabilities and emits only a validated response stream. The
current crate is a one-request process slice; a reproducible static AArch64
Linux binary, appliance execution, and thin host launchers remain separate
distribution consumers.

Manifest-declared comptime tests can import and execute the implemented subset
of ordinary production `comptime fn` declarations during semantic analysis.
The runtime integration/image route shares the ordinary backend, protocol, and
target-owned QEMU design. Selected generated-test runtime assertions now reach
native ABI2 objects, but current packaged-QEMU execution and non-test/actor
assertion supervision remain open; `wrela-test-model`, `wrela-test-protocol`,
and `wrela-test-runner` own that execution boundary.

The syntax model is an AST with a lossless token/trivia table. There is no CST
or LSP crate. `wrela-format` and `wrela-lint` consume the weakest sufficient
frontend layer.

Inkwell is private and optional in `wrela-codegen-llvm`. Raw LLD FFI is confined
to `wrela-lld-sys`. `wrela-runtime-abi` defines the small compiler-owned ABI;
the digest-checked implementation object is shipped in the AArch64 target.

See [`docs/crate-contracts.md`](../docs/crate-contracts.md) for every crate's
input/output contract and the exact dependency allowlist enforced by
`cargo xtask architecture-check`.

For focused acceptance, use `cargo xgate <slice-or-crate>`. It runs scoped
formatting, all-target checks, unfiltered tests, Clippy, and architecture/closure
validation under locked offline Cargo resolution. `cargo xtask slices` is the
authoritative inventory of packages, resolved closures, boundaries, real
checked-in fixtures, native requirements, fast/full commands, and timing
budgets. `cargo xcheck`, `cargo xtest`, and `cargo xlint` remain granular
diagnostic commands. Phase outputs bind validated data and their report
together; machine lowering borrows optimized FlowWir, so retaining report
inputs never clones an image-sized IR.
