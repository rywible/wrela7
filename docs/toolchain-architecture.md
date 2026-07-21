# Toolchain architecture

This document is the human-facing map of the sealed compilation pipeline. The
authoritative package boundaries are in
[`docs/crate-contracts.md`](crate-contracts.md) and are enforced by
`cargo xtask architecture-check` / `cargo xarch`.

## Phase map

Source packages enter through the manifest and package-loader, then travel a
single sealed pipeline:

```text
manifest / package-loader -> source / package graph
  -> syntax (lossless typed AST; no CST or LSP)
  -> hir-lower -> resolved HIR
  -> sema -> sealed AnalyzedImage
  -> semantic-lower -> SemanticWir
  -> flow-lower -> FlowWir
  -> private FlowWir codec / backend boundary
  -> flow-opt -> optimized FlowWir
  -> machine-lower -> AArch64 MachineWir
  -> LLVM COFF (optional feature) + target runtime object
  -> EFI linker (lld-link today) -> .efi + image report
```

`wrela-compiler` is the sole wide composition root. It injects every phase
trait and bounded host capability into the small public `wrela-driver` API.
Lower crates never depend back on either orchestration implementation.
`wrela-cli` is the sole consumer of that composition root.

## Backend process and protocol

Image construction crosses a process boundary:

1. The frontend seals a backend request (FlowWir payload, target identity,
   profile, resource limits) and launches the installed `wrela-backend`
   under the verified toolchain root.
2. The backend validates the request, lowers through MachineWir, emits
   AArch64 COFF (LLVM lane today), links the PE32+ EFI image with the
   digest-checked runtime object, and writes a machine-readable image
   report.
3. The frontend reconciles the report against the sealed request and
   publishes build / test artifacts.

Raw LLD FFI stays confined to `wrela-lld-sys`. The compiler-owned ABI surface
lives in `wrela-runtime-abi`; the digest-checked runtime object ships with
the AArch64 QEMU-virt UEFI target under
`toolchain/targets/aarch64-qemu-virt-uefi/`.

## Test and doctor surfaces

- `wrela check` / `wrela lint` / `wrela build` / `wrela test` are the public
  commands for the supported minimum semantic surface.
- `wrela doctor` verifies installation content, compatibility, target /
  runtime digests, and running-frontend identity. System QEMU and firmware
  are resolved from the host and are not part of the sealed installation.
- Focused acceptance uses `cargo xgate <slice-or-crate>`. The slice inventory
  is `cargo xtask slices`.

## Oracle track (roadmap)

LLVM, lld-link, and QEMU are temporary differential oracles. The world-class
roadmap replaces them with a native machine model (`wrela-virt`), native
AArch64 codegen, and a native EFI linker, then deletes the oracles once
retirement criteria pass. Until then, hermetic tests must not depend on
symlinked host paths: host-controlled paths are canonicalized before
toolchain verification, while installation roots still reject symlinks.
