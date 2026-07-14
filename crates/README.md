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

Comptime tests execute in semantic analysis. Runtime integration and manifest
image tests compile through the same pipeline and boot under the target-owned
QEMU profile; `wrela-test-model`, `wrela-test-protocol`, and
`wrela-test-runner` own that boundary.

The syntax model is an AST with a lossless token/trivia table. There is no CST
or LSP crate. `wrela-format` and `wrela-lint` consume the weakest sufficient
frontend layer.

Inkwell is private and optional in `wrela-codegen-llvm`. Raw LLD FFI is confined
to `wrela-lld-sys`. `wrela-runtime-abi` defines the small compiler-owned ABI;
the digest-checked implementation object is shipped in the AArch64 target.

See [`docs/crate-contracts.md`](../docs/crate-contracts.md) for every crate's
input/output contract and the exact dependency allowlist enforced by
`cargo xtask architecture-check`.

For focused work, use `cargo xcheck <slice-or-crate>`,
`cargo xtest <slice-or-crate>`, and `cargo xlint <slice-or-crate>`.
`cargo xtask slices` lists narrow syntax/HIR/semantic/Flow/Machine/artifact
boundaries as well as end-to-end groups. Phase outputs bind validated data and
their report together; machine lowering borrows optimized FlowWir, so retaining
report inputs never clones an image-sized IR.
