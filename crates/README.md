# Compiler crates

The workspace is organized around independently runnable layer contracts.

## Frontend

```text
wrela-source
  → wrela-syntax
  → wrela-hir-lower → wrela-hir
  → wrela-sema
  → wrela-wir-lower → wrela-wir
  → wrela-wir-passes
```

`wrela-diagnostics` and `wrela-target` are shared contracts, not miscellaneous
utility crates. Semantic subanalyses remain inside `wrela-sema` while they share
a fixed point.

## Backend

```text
wrela-wir-codec → wrela-wir-passes → wrela-codegen-llvm → COFF
                                                    COFF → wrela-link-efi → .efi
                                                              ↓
                                                        wrela-lld-sys
```

Inkwell is an optional, exact dependency of `wrela-codegen-llvm` and nowhere
else. Raw C++/LLD FFI is permitted only in `wrela-lld-sys`. The default workspace
build activates neither private native dependency.

## Composition

- `wrela-driver` composes frontend layers for the public CLI.
- `wrela-backend` decodes and re-verifies WIR, then composes codegen, linking,
  and image reporting in a private process.
- `wrela-backend-protocol` carries versioned process messages without exposing
  compiler or LLVM data structures.
- `wrela-toolchain` locates only components in the atomic installation.

Data-model crates must not depend on their producers or consumers. New
cross-layer dependencies should follow the arrows above and be justified in
[`docs/toolchain-architecture.md`](../docs/toolchain-architecture.md).

