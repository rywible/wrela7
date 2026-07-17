# Toolchain architecture

This document describes the installed compiler and distribution. Exact Rust
crate inputs, outputs, and dependency edges are normative in
[Compiler crate contracts](crate-contracts.md).

The current release implementation assembles a Darwin-native toolchain. The
greenfield cross-host replacement is specified in
[Linux engine and host launchers](design/linux-engine-host-launchers.md): one
immutable Linux compiler payload is invoked directly on Linux and through a
thin Virtualization.framework launcher on Apple Silicon. Until its conformance
gates pass, that document is implementation direction rather than a shipped
capability; no compatibility layer for the Darwin-native bootstrap is planned.

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
│   │   └── wrela-core-0.1/
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
and emulator identities are checked before a build or test starts. These
numbers reject stale or corrupt inputs; the greenfield toolchain reads only its
exact current formats and carries no compatibility or migration readers.
The driver hashes every declared path and seals a `VerifiedToolchain`; backend
and test consumers cannot accept discovery paths or a merely decoded manifest.
Toolchain-manifest schema 1 uses canonical tree digest v1 (`WRELTRE\0`, version
1) for the standard-library component and target-package directory, and raw
SHA-256 for executable components and individually declared target files. A
change to either interpretation requires a manifest schema bump.

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
  memory/vCPU count, no implicit default NIC, firmware components, virtio FAT
  boot medium, and framed PL011 test transport.

The QEMU `virt` machine type is versioned in the target instead of using the
moving `virt` alias. The QEMU binary and both firmware files are shipped and
digest-checked, so a developer's installed emulator or firmware cannot alter a
test. Launches pass `-nic none`: the target has no network device in its runner
contract and never depends on QEMU's ambient default NIC or its optional EFI
ROM payload.

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

The current actor producer is narrower than that full representation. It carries
the parsed stateless-service subset through SemanticWir v5, FlowWir/wire v7, and
MachineWir v7: one immediate ordinary unit-returning async-helper activation per
non-reentrant actor turn or single-slot task entry, with an exact source plan,
activation `TaskFrame` region, maximum-live/cancellation facts,
cleanup/capacity/function proof links, and an immediate strict-linear
`AsyncCall`/`Suspend` delivery. Machine lowering erases the activation token only
after retaining those facts, emits the helper as a private internal call, and
turns the suspend into its exact resume edge. The task entry runs once on the
successful image-entry path. The actor turn is native-emittable but deliberately
dormant because no mailbox admission/dispatch operation exists. Machine lowering
also maps every sealed mailbox, root-frame, and activation-frame region
one-to-one to a distinct aligned zero-initialized byte-array global, private
symbol, and canonical writable region section. The current source fixture closes
and emits exactly 96 writable bytes; its mailbox uses the bounded scalar subset's
fixed 16-byte slot. This is bounded compiler and object evidence, not a recurring
scheduler, general message ABI, or runtime-execution claim.

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
requirements. The linker requires exactly one runtime object whose target
digest and ABI version match the target package. The frontend/backend protocol
also carries the frontend-verified runtime SHA-256 and byte length; the private
backend independently re-opens and COFF-inspects those same bytes before
linking. No default or dynamic library is allowed.

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
The shared LLD boundary requires exactly one direct output before native work
and, on the supported Unix host, seals the resulting PE through a no-follow
descriptor as the same one-link mode-`0600` regular file before success.
It requires a deterministic map and a bounded inspector to re-open the emitted
PE32+ image, verify ARM64/EFI/entry/relocation facts, hash the bytes, and return
canonical final section/symbol measurements before link success is sealed.

LLVM attributes such as `noalias`, `inbounds`, non-null, alignment, and overflow
flags may be emitted only from proof-bearing MachineWir facts. Backend
peepholes cannot justify a language-level proof or a hard image bound.

`cargo xtask llvm` owns native acquisition and construction. Its canonical
schema-2 lock pins the LLVM release tag, source commit, HTTPS archive byte count
and SHA-256, the singleton `lld`/`AArch64`/static configuration, and the exact
Inkwell version/features. The task verifies the archive before a single-pass,
bounded extraction that rejects traversal, special members, and unreviewed
links; stages the already-hashed CMake contract; and configures with explicit,
fingerprinted host tools and bounded jobs rather than a public `PATH`. The
published prefix is keyed by every declared input, including the running
bootstrap executable and measured host closure, and contains a canonical
receipt over every directory/file mode, normalized timestamp, and regular-file
byte. `toolchain/llvm.outputs.toml` independently pins the exact expected tree
for that input/host. Reuse measures and matches this trusted digest before it
may execute cached `llvm-config`, then requires the AArch64 code-generator and
LLD COFF archives plus exact cleared-environment version, targets,
static-linkage, and host answers. The one-shot maintainer `--record-output`
route can create the lock only from a fresh exclusive build; ordinary missing,
stale, forged, or mutated caches fail closed.

## 6. Test architecture

MachineWir v7 retains the lifecycle invariant introduced by version 6. Machine lowering owns
the target-specific UEFI entry prologue because FlowWir
does not expose firmware parameters. Every generated image entry—ordinary
image entry or generated test harness—must call
`wrela_rt_v2_image_enter(image_handle, system_table)` exactly once before any
image-body operation. The call uses the two synthesized UEFI parameters in
their original order. A zero `EFI_STATUS` is the sole edge into the original
body; a nonzero status is returned unchanged from the public UEFI entry. The
MachineWir validator independently requires this dominating shape, rejects an
omitted, duplicate, reordered, or bypassable transition, and requires the
matching runtime requirement, external symbol, and lowering-report use. The
minimum-image fast path follows the same contract rather than treating an empty
body as permission to skip runtime activation.

The generated-test transport has the same fail-closed status discipline after
activation. Each returning `wrela_rt_v2_test_emit(address, length)` ends its
MachineWir block, and that call's own `EFI_STATUS` is switched exactly once.
Zero alone reaches a parameter-free continuation; every nonzero value reaches
an empty single-predecessor failure block and is returned unchanged from the
public UEFI entry. The continuation is also single-predecessor, so later frame
emission or `TestFinish` cannot enter by bypassing that guard. Machine lowering
meters two blocks plus the switch-case and return edges per emit, while the
MachineWir consumer rejects ignored, borrowed, remapped, or bypassable status
values before LLVM. This closes compiler-generated protocol transport failure
propagation. It does not implement runtime `assert`, turn an ordinary
`@test fn` into a source-level unit test, or prove that a generated test image
has executed under QEMU.

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

The remainder of this subsection is the required runtime-test architecture,
not a claim that ordinary source runtime assertions or every generated harness
currently executes end to end. Once enabled, both runtime forms run the emitted
AArch64 EFI image under the target's QEMU profile. They do not use a hosted
standard library, host calls, or a second
runtime semantics. The compiler and guest emit one stable framed event schema;
one group-derived frame/string/event/stream policy governs command construction,
live observation, and final decoding. The host rejects sequence gaps,
corruption, overflow, partial reserved frames on successful exit,
missing/duplicate terminal events, cross-group or undeclared tests, and
infrastructure failures.

Before QEMU starts, the executor reverifies its program and hashes the sealed
EFI artifact, firmware code, and firmware-variable template while copying them
to distinct private per-run paths. The EFI and code copies are read-only; only
the variable-store copy is writable. A stale digest/size never launches QEMU,
and a run cannot mutate the shipped toolchain installation.

Explicit shutdown uses only a private command-bound QMP Unix socket. Greeting,
capability, and quit replies are depth/count/byte bounded and unambiguous. Every
exit path synchronously reaps the private process group and removes staged
inputs, QMP endpoints, and private parent directories; cleanup failure or
unexpected residue is itself an infrastructure failure.

The final test report separates assertion/test outcomes from discovery,
compile, link, boot, runtime, shutdown, timeout, crash, and protocol failures.
Reproducibility evidence records image, firmware, emulator, invocation, and
event-stream digests when those stages occurred; it never fabricates an image
or invocation identity for a pre-link failure.

## 7. Reproducible package and build inputs

`wrela.toml` declares the package identity, language revision, explicit module
paths, dependency aliases/requirements, finite build profiles, full images, and
image-test scenarios. `wrela.lock` fixes the complete package closure by
identity, locator, manifest digest, source digest, and exact dependency edges;
every entry must be reachable from its declared root.

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

The `standard_library` digest in `BuildIdentity` identifies the complete
verified toolchain component. The exact semantic package is separately selected
by the root package's reserved direct dependency alias `core`; its package ID
and content are already bound by the source graph. The verified manifest's
nonempty standard-library index independently pins that package's full
`PackageIdentity`, direct-child toolchain locator, and canonical manifest
digest, preventing a package substitution inside an otherwise selected
installation. Compiler phases must not compare the component digest with one
package's `source_digest`.

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
The current local-build implementation operationalizes the first artifact at
`<authorized-output>/.wrela-cache-v1`: its key binds the complete
`BuildIdentity`, artifact kind, cache schema, and FlowWir subject; entries are
private, bounded, digest-sealed, canonically decoded, revalidated, and compared
with the fresh producer model before the reopened bytes become the private
backend input. Missing, stale, corrupt, oversized, noncanonical, or
identity-mismatched entries are ordinary misses and recompute. This does not
constitute semantic/HIR `ChangeSet` reuse, which requires separate proof that
unchanged producer results are actually reused and equal a clean recomputation.
The distribution task will:

1. fetch pinned LLVM/LLD, QEMU, firmware, and other native inputs;
2. verify cryptographic digests and release attestations;
3. build only required AArch64/static components;
4. build public frontend and private backend;
5. install standard library, target, runtime, firmware, emulator, manifests,
   licenses, and notices into a staging tree;
6. validate every installed digest, current schema, and component identity;
7. run architecture/unit/corruption tests;
8. compile, inspect, and boot AArch64 conformance/test images with public
   `PATH` cleared; and
9. archive the exact tested tree without rearranging it.

The revision-0.1 host plan covers Apple Silicon macOS and Linux arm64/x86_64.
Additional host packages are future work, not compatibility promises. Host
architecture does not add a Wrela target or change source semantics; every
revision-0.1 artifact still targets the pinned AArch64 machine.
