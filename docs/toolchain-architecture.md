# Toolchain architecture

This document describes the installed compiler and distribution. Exact Rust
crate inputs, outputs, and dependency edges are normative in
[Compiler crate contracts](crate-contracts.md).

## 1. Installation model

Wrela is one atomic, content-addressed toolchain. The public executable never
searches `PATH` for LLVM, LLD, QEMU, firmware, a runtime, targets, or the
standard library.

```text
<root>/
├── bin/
│   └── wrela
├── libexec/wrela/
│   ├── wrela-backend
│   └── qemu-system-aarch64
├── share/wrela/
│   ├── toolchain.toml
│   ├── std/
│   ├── licenses/
│   └── targets/
│       └── aarch64-qemu-virt-uefi/
│           ├── target.toml
│           ├── firmware/
│           │   ├── QEMU_EFI.fd
│           │   └── QEMU_VARS.fd
│           └── runtime/
│               └── wrela-runtime-aarch64.obj
└── VERSION
```

`WRELA_TOOLCHAIN_ROOT` is an explicit development/test override. Production
discovery derives `<root>` from `<root>/bin/wrela`. Each shipped component and
target has an exact digest in `toolchain.toml`; the compiler, backend protocol,
SemanticWir/FlowWir/MachineWir model versions, FlowWir wire format, runtime ABI,
build-profile/target/report/test-plan/test-report/scenario schemas, test
event/frame versions, language revision, standard library, target, firmware,
and emulator compatibility are checked before a build or test starts.
The driver hashes every declared path and seals a `VerifiedToolchain`; backend
and test consumers cannot accept discovery paths or a merely decoded manifest.

## 2. AArch64-only full-image target

Revision 0.1 ships only `aarch64-qemu-virt-uefi`. It emits an ARM64 PE/COFF UEFI
application with the `aarch64-unknown-uefi` LLVM triple and LLD COFF
`/machine:arm64`. There is no hosted target and no x86 target.

The target package contains three separated contracts:

- semantic: AArch64, 64-bit little-endian pointers, UEFI 2.11, DMA/IOMMU facts,
  and target-owned MMIO/GIC identities;
- backend: LLVM/COFF identity, entry/subsystem, safe linker policy, the target
  runtime object/runtime ABI, and exact GICv3 exception-entry/vector/stack/SIMD
  policy; its CPU/features are fixed to
  `cortex-a57,+reserve-x18`, matching QEMU and UEFI's X18 prohibition;
- runner: a versioned QEMU `virt` machine, `cortex-a57`, deterministic TCG,
  memory/vCPU count, firmware components, virtio FAT boot medium, and framed
  PL011 test transport.

The QEMU `virt` machine type is versioned in the target instead of using the
moving `virt` alias. The QEMU binary and both firmware files are shipped and
digest-checked, so a developer's installed emulator or firmware cannot alter a
test.

## 3. Compilation pipeline

```text
manifest/lock/package provider
  -> immutable source graph
  -> lossless typed AST
  -> resolved normalized HIR
  -> whole-image semantic fixed point
  -> SemanticWir
  -> FlowWir typed SSA
  -> canonical private FlowWir bytes
  -> private backend revalidation
  -> optimized FlowWir
  -> AArch64 MachineWir
  -> LLVM AArch64 COFF
  -> generated object + target runtime object
  -> LLD ARM64 EFI image
  -> measured canonical image report
```

### Frontend process boundary

`wrela-compiler` is the production composition root. It owns package
acquisition, source input, syntax, HIR, semantic analysis, SemanticWir/FlowWir
lowering, FlowWir serialization, diagnostics, cache decisions, test-group
fan-out, and the private backend process lifetime. `wrela-driver` owns only the
stable public command/event/outcome vocabulary. The composition root writes
inputs under a private per-build directory and sends only controlled relative
paths in the backend protocol.

The frontend/backend boundary is `ValidatedFlowWir`. The message and FlowWir
frames have separate exact versions and limits. The backend compares the
embedded `BuildIdentity` with the request, re-hashes the exact canonical frame
against the request digest, and independently validates every IR reference and
invariant before optimization or LLVM initialization.

### Three named representations

`SemanticWir` is structured, specialized language semantics: ownership, actors,
async, regions, complete scope/cleanup plans, hardware transitions, image graph,
source summary, startup/shutdown order, and proofs are still source-shaped.

`FlowWir` is target-layout-independent typed SSA. Control flow, state machines,
cleanup, admission, scheduling, logical capacity, checkpoints, hardware effects,
test-harness emission, source/report facts, and proof IDs are explicit. Ordinary
optimization stays in FlowWir and produces a sealed `OptimizedFlowWir`; passes
do not create arbitrary new IR names.

`MachineWir` fixes the AArch64 ABI, data layout, stack/frame slots, sections,
symbols, memory semantics, runtime calls, and every undefined-behavior-bearing
fact. LLVM performs a mechanical translation of validated MachineWir.

Every transition receives explicit resource policy. Besides arena and
instruction counts, seals bound aggregate variable-length edges, UTF-8/binary
payload, recursive depth, diagnostics, optimizer reports, object/map/image
measurements, and canonical report bytes. The composition root rejects drift
between frontend/backend FlowWir limits and between semantic/test-plan limits.

## 4. Runtime boundary

Most scheduling, actor, state-machine, region, and cleanup behavior is generated
as ordinary MachineWir. The target runtime object implements only the closed
compiler-owned `wrela-runtime-abi` surface:

- UEFI image entry/exit and fatal termination;
- CPU idle and local interrupt mask/restore;
- proved DMA cache maintenance;
- deterministic record/replay event transfer; and
- full-image test event/terminal transfer.

Source cannot name these intrinsics. Each MachineWir module records its sorted
requirements. The linker requires exactly one runtime object whose target digest
and ABI version match the target package. No default or dynamic library is
allowed.

## 5. LLVM and LLD isolation

The public crates build without LLVM. `wrela-codegen-llvm` enables Inkwell only
through its private `llvm` feature. It builds only LLVM's AArch64 target with
the statically pinned LLVM/LLD revision. X86, Clang, LLDB, MLIR, Polly, examples,
tests, and developer tools are not release components.

Inkwell/LLVM contexts, modules, values, target machines, and error handles stay
inside `wrela-codegen-llvm`. Raw LLD arguments and native FFI stay inside
`wrela-link-efi`/`wrela-lld-sys`. The safe linker constructs the complete fixed
policy: ARM64 machine, EFI subsystem and entry, no default libraries,
reproducible mode, explicit outputs, generated objects, and one target runtime.
It requires a deterministic map and a bounded inspector to re-open the emitted
PE32+ image, verify ARM64/EFI/entry/relocation facts, hash the bytes, and return
canonical final section/symbol measurements before link success is sealed.

LLVM attributes such as `noalias`, `inbounds`, non-null, alignment, and overflow
flags may be emitted only from proof-bearing MachineWir facts. Backend
peepholes cannot justify a language-level proof or a hard image bound.

## 6. Test architecture

There are three user test forms and two execution mechanisms:

1. `@test comptime fn` is a pure unit test executed by the same finite compiler
   evaluator used for comptime.
2. `@test fn` or `@test async fn` is an integration test linked into a generated
   full-image harness.
3. A manifest image test selects a declared `@image` root, a host scenario, a
   deterministic seed when needed, and finite boot/shutdown/output/event limits.

Discovery returns a `ValidatedTestPlan` with dense group IDs and fixed-size
content-addressed monomorphized function keys. The plan retains the exact limit
policy used to seal it. Each runtime group is compiled independently from its
declared image root or compiler-generated harness root, but remains bound to
the same build/target identity. Report sealing rechecks per-event, per-group,
and whole-report payload limits from that plan.

Both runtime forms run the emitted AArch64 EFI image under the target's QEMU
profile. They do not use a hosted standard library, host calls, or a second
runtime semantics. The compiler and guest emit one stable framed event schema;
the host rejects sequence gaps, corruption, overflow, missing/duplicate terminal
events, undeclared tests, and infrastructure failures.

Before QEMU starts, the executor reverifies its program and hashes the sealed
EFI artifact, firmware code, and firmware-variable template while copying them
to distinct private per-run paths. The EFI and code copies are read-only; only
the variable-store copy is writable. A stale digest/size never launches QEMU,
and a run cannot mutate the shipped toolchain installation.

The final test report separates assertion/test outcomes from discovery,
compile, link, boot, runtime, shutdown, timeout, crash, and protocol failures.
Reproducibility evidence records image, firmware, emulator, invocation, and
event-stream digests when those stages occurred; it never fabricates an image
or invocation identity for a pre-link failure.

## 7. Reproducible package and build inputs

`wrela.toml` declares the package identity, language revision, explicit module
paths, dependency aliases/requirements, finite build profiles, full images, and
image-test scenarios. `wrela.lock` fixes the complete package closure by
identity, locator, manifest digest, source digest, and exact dependency edges.

The compiler composition root injects the only package provider and SHA-256
implementation. The loader rejects undeclared or missing sources/scenarios and produces one
source-graph digest over canonical lockfile bytes, manifests, and canonical
source/scenario package-path-digest tuples. Filesystem walks and implicit
registry/network resolution are forbidden.

`BuildIdentity` binds compiler, language revision, target identity/package,
standard library, source graph, canonical profile, and a canonical request
digest covering the selected image, command intent, and test selection. A
multi-artifact test request additionally keys each output by its canonical
group/root and FlowWir digest. A cache hit must preserve diagnostics and target
semantics.

## 8. Reports and publication

The image report is built from named phase outputs and final measurements. It
contains logical topology, capacities, proof why-chains, actor lowering, stack/
frame/work/checkpoints, hardware/recovery, startup/shutdown, IR/wire/runtime ABI
versions, optimizer decisions, runtime requirements, sections/symbols,
target-variable reservations/exclusions, canonical request and FlowWir digests,
and final image digest.

The backend publishes an EFI artifact and its report atomically only after:

1. backend success;
2. emitted section/size inspection;
3. report/artifact build-identity agreement;
4. SHA-256 computation; and
5. output-directory policy checks.

A failed or cancelled build may retain a private debug directory by explicit
policy, but cannot leave a published success artifact.

Test reports pass through a bounded canonical codec and must decode to the exact
validated report and re-encode byte-for-byte before publication. The composition
host exposes one sealed atomic-file operation for test reports and formatter
output. Test reports use create-new semantics; formatting compares the current
source digest under the replacement lock, so a concurrent edit is never lost.
Publication receipts must repeat the requested path, byte count, and digest.

## 9. Distribution build

`cargo xtask architecture-check` enforces the exact workspace inventory and
dependency graph plus the LLVM/QEMU/firmware/AArch64 target-pin consistency.
Focused `cargo xcheck`, `cargo xtest`, and `cargo xlint` slices exercise one
producer/consumer boundary (or one exact crate) with only its Cargo dependency
closure; `cargo xfmt` is the formatting handoff gate. Development/test profiles
retain line-table backtraces while avoiding full debug-info link and disk cost.
The dependency allowlist rejects unused speculative edges; notably the public
driver does not depend on filesystem-aware toolchain discovery. Large codecs,
formatting, package acquisition, linking, and test execution share explicit
cancellation, while per-file and aggregate limits remain distinct so focused
iterations do not inherit whole-workspace allocations.
The composition root also injects an optional-by-behavior artifact cache: a
miss is always legal, while a hit is accepted only after build/key/size/digest
verification and the artifact's normal canonical decoder. Phase-local query
caches stay behind their phase traits and can reuse the explicit change sets.
The distribution task will:

1. fetch pinned LLVM/LLD, QEMU, firmware, and other native inputs;
2. verify cryptographic digests and release attestations;
3. build only required AArch64/static components;
4. build public frontend and private backend;
5. install standard library, target, runtime, firmware, emulator, manifests,
   licenses, and notices into a staging tree;
6. validate every installed digest and compatibility version;
7. run architecture/unit/corruption tests;
8. compile, inspect, and boot AArch64 conformance/test images with public
   `PATH` cleared; and
9. archive the exact tested tree without rearranging it.

Host release artifacts may exist for supported macOS, Linux, and Windows host
architectures. Host architecture does not add a Wrela target or change source
semantics; every revision 0.1 artifact still targets the pinned AArch64 machine.
