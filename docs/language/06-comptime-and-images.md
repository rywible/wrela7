# Comptime and images

## 1. Compile-time evaluation

`comptime` runs ordinary typed wrela code during the build. It is not a textual
preprocessor and does not introduce a second expression language.

It serves four primary roles:

- constructing the image graph;
- specializing generic types and constant control flow;
- producing deterministic baked artifacts such as a small filesystem or font
  atlas; and
- validating device contracts, capacities, and post-layout reports.

```wrela
comptime fn ring_bytes(depth: usize) -> usize:
    return align_up(depth * VirtqDesc.size, 4096)

const QDEPTH = 128
const RING_BYTES = ring_bytes(QDEPTH)
```

## 2. Purity and determinism

Compile-time code MUST be deterministic for a fixed compiler revision, target,
source graph, declared build inputs, and step budget. It cannot:

- perform filesystem, network, console, or device I/O;
- read host environment variables or undeclared files;
- inspect wall time, random state, process identity, or host addresses;
- touch MMIO, DMA, IRQ, or runtime capabilities;
- depend on hash-table iteration with unspecified order; or
- invoke runtime-only code.

Large or external inputs enter through the build system as declared,
content-addressed byte values. Comptime may transform those values but cannot
discover new host inputs.

```wrela
# `font_source` is a declared build input with a content hash.
atlas = comptime rasterize(font_source, sizes=[12, 16, 24])
```

Comptime evaluation emulates the **target**, not the host. Integer widths,
endianness, layout, alignment, and floating-point behavior are target semantics.
Cross-compilation must produce the same result on different build hosts.

## 3. Finite evaluation budget

The compiler does not claim to decide program termination. Every comptime
evaluation runs under finite step and memory quotas supplied by the build
profile. A backward branch, call, allocation in the evaluator, or other charged
operation consumes budget.

Exceeding a quota is a build error with the hottest evaluation stack and loop:

```text
error[comptime-budget]: evaluation exceeded 100000 steps
  while evaluating `extentfs_mkfs`
  82% of charged steps occurred at image/mkfs.wr:73
  help: raise the declared build quota or move this artifact step into the build system
```

Raising a quota changes build configuration, not language soundness. The
compiler must still allow the user to interrupt evaluation and must not allow
recursion or type-expression evaluation to escape quota accounting.

## 4. Comptime values and runtime data

A compile-time value may become runtime data only when it has a concrete target
layout and contains no evaluator-only handles. Serialized values are immutable
and placed in image read-only data unless an image constructor explicitly copies
them into mutable initial state.

Pointers into compiler memory, host handles, open files, evaluator closures, and
undeclared target addresses cannot cross the phase boundary.

String literals, lookup tables, seed filesystem bytes, register-layout
metadata, and initialized plain structs can cross when their target layout is
known.

## 5. Secrets

`Secret[T]` marks data that must not be serialized into an image. Comptime
tainting preserves `Secret` through transformations. Attempting to place a
secret-derived value in read-only data, a seed artifact, a diagnostic, or the
image graph is a build error.

A secret-derived value also cannot control a comptime branch, loop count,
allocation/capacity, type or constant argument, error/success outcome, generated
name, layout decision, or whether a declaration/image node exists. These are
observable image outputs. Revision 0.1 provides no comptime declassification; a
secret may only be transformed by operations whose result remains `Secret` and
then passed to an external secure provisioning artifact that is not serialized
or inspected by Wrela.

Secrets are provisioned at boot or first run through a target-defined secure
channel. Signing keys used by an external packaging step do not enter wrela
comptime.

```text
error[secret]: value derived from `disk_encryption_key` would be baked into image data
```

## 6. Specialization

Generic type arguments, generic constant arguments, `comptime if`, and
attribute arguments are resolved before runtime code generation.

```wrela
comptime if MODE == DriverMode.irq:
    bind_interrupts()
comptime else:
    suppress_interrupts()
```

An eliminated branch contributes no runtime code, wait-for edge, ISR entry,
frame field, or effect. Every surviving generic instantiation is monomorphized.
Every interface call resolves to a direct concrete call or an explicit branch
over a closed enum.

Any configuration that changes the actor, task, ISR, capability, or effect
graph MUST be a comptime type/constant argument of the affected class or image
node. It cannot be duplicated as a runtime value or a second image-builder
option. This makes the specialized graph used by validation identical to the
graph that reaches code generation.

Runtime reflection and runtime type construction are absent. Type values exist
only at comptime.

## 7. Attributes and generated names

Attributes take typed comptime values and attach metadata to an existing
declaration. Revision 0.1 has no arbitrary AST macro expansion. Compiler and
tool attributes may generate internal symbols, but those symbols are hygienic,
cannot capture source locals, and retain source spans pointing to the
responsible declaration.

Attribute interpretation occurs in fixed phases. An attribute cannot inspect a
layout report before layout or mutate code during the post-layout assertion
pass.

## 8. Image construction

Exactly one reachable public `@image comptime fn` returns the `Image` value for
a build. It declares the target and creates the complete typed runtime graph.

```wrela
module appliance.image

from drivers.virtio.block import BlkDriver, VirtioBlock
from storage.service import DmaBlock, Storage
from apps.notes import Notes

const BLOCK_MODE: DriverMode = DriverMode.irq

@image
pub comptime fn build() -> Image:
    img = Image(
        name="wrela-storage",
        target=Target.aarch64_qemu_virt_uefi,
    )

    block_device = img.device(
        VirtioBlock,
        transport=VirtioMmioTransport(base=0x0a00_0000, irq=0x30),
        required_features=[VirtioFeature.flush],
        optional_features=[VirtioFeature.ring_reset],
    )

    disk = img.driver(
        BlkDriver[BLOCK_MODE],
        device=block_device,
        queue_depth=128,
        dma=DmaPoolSpec[BlockDma](capacity=256.KiB),
    )

    cache_payloads = img.dma_payloads[DmaBlock](
        device=disk,
        brand=BlockPayloads,
        count=4096,
    )

    storage = img.service(
        Storage,
        disk=disk.handle(),
        blocks=take cache_payloads,
        mailbox=16,
    )

    notes = img.app(
        Notes,
        storage=storage.handle(),
        mailbox=4,
    )

    img.supervise(
        children=[disk, storage, notes],
        strategy=Restart.one_for_one,
        intensity=RestartIntensity(max=3, within=seconds(10)),
    )

    img.seed_disk(comptime extentfs_mkfs(
        files=[SeedFile(ino=7, data=b"hello from the build\n")],
    ))

    img.check_layout(fits_in_64_mib)
    return img.seal()

@layout_assert
comptime fn fits_in_64_mib(report: ImageReport):
    assert report.peak_memory < 64.MiB
```

Image construction describes:

- actor instances and typed handles;
- device contracts and driver ownership;
- IRQ or polling mode;
- mailbox and child-task capacity constraints;
- region and DMA pool capacities;
- target and boot profile;
- supervisor topology and restart intensity;
- a restart provision for every linear constructor dependency;
- declared build inputs and baked artifacts;
- declared profile-guidance inputs and their content hashes, when used; and
- post-layout requirements.

Every pool-producing builder call mints one fresh nominal brand and binds its
optional source display name to that identity. A brand name may appear on exactly
one pool node; reusing it, constructing it as a zero-sized value, or passing it
as the brand of another pool is a build error naming both nodes. Omitting
`brand=` creates an anonymous brand that tooling gives a stable
content-addressed display name.

Image dependency edges are classified. A **construction edge** transfers a
linear value or requires an initialized dependency and must form a DAG. A
**handle edge** installs an `Actor[T]` identity and may be cyclic because actor
storage/identities are allocated before any initializer runs. Boot first
allocates every actor and mailbox and mints handles, then initializes drivers and
other actors in the topological order of construction edges, then atomically
opens all successfully initialized mailboxes. No actor call is admitted during
initialization. Apps may depend on services/drivers; services may depend on
services/drivers; drivers may depend only on target capabilities, sealed runtime
services, and explicitly driver-safe service handles. Role violations or a
construction-edge cycle are build errors showing the path.

It does not read the actual device. A device declaration is a build contract;
boot verifies real hardware before entering runtime.

### 8.1 Restart provisions

The image graph records how every linear constructor argument is recreated on
restart. A device binding provides `remint(device_binding)`, legal only after
the old device epoch is quiescent. A declared pool provides
`reclaim(pool_brand, count)`: generated teardown returns the exact branded
handles, then initialization redraws the declared count. A sealed immutable
dependency may use `retain`. User-defined strict resources require an explicit
provision contract.

The builder normally derives these entries from `device=`, DMA/`iso` pool, and
actor dependency arguments, but the resulting manifest is explicit and shown by
tooling. A linear constructor argument without one recovery source is a build
error. `one_for_all` and `rest_for_one` provisioning is ordered so all affected
owners tear down before any handle is redrawn; a capability or pool slot is
never duplicated across actor epochs.

## 9. Capability minting

`img.driver(...)` records an exclusive binding. During target boot, that binding
is the only path that can mint the branded runtime `DeviceCap`, `IrqCap`, MMIO
mapping, and DMA provenance values for the driver.

The compile-time `DeviceDecl` is not a runtime capability. It cannot perform
I/O, be serialized into an app message as authority, or stand in for runtime
feature negotiation.

The compiler rejects:

- two drivers claiming the same exclusive device or vector;
- a driver whose declared requirements exceed the target contract;
- an app/service field that would receive hardware authority;
- an IRQ binding unsupported by the target, including PCI INTx in revision 0.1;
  and
- a pool reachable by a device not listed in its provenance set.

## 10. Fixed build phases

A conforming compiler performs the following logical phases. It may parallelize
or fuse implementations only when results and diagnostics are equivalent.

### Phase 1: parse and collect declarations

The compiler parses every imported module, validates package/module paths,
collects declaration headers, and constructs module strongly connected
components. No user comptime code runs.

### Phase 2: resolve signatures and compile-time code

Names, visibility, orphan/coherence constraints, generic parameter kinds,
declaration signatures, constant dependencies, attribute names, and comptime
function bodies are resolved and type-checked. Semantic cycles in constants,
layouts, and signatures are rejected. Runtime bodies are parsed and name
resolved sufficiently to discover referenced declarations, but are not yet
checked under an unspecialized comptime branch.

### Phase 3: evaluate image-root constants and construct the image

The target emulator evaluates constants and attributes needed by the unique
image constructor, then evaluates that constructor and baked artifacts under
quotas. A `comptime if` whose condition depends on an ordinary generic parameter
is retained as a typed pending branch. The result is a signature-checked image
root graph plus registered post-layout checks.

### Phase 4: instantiate and type-check specialized bodies

Reachability begins at the image graph and target ABI. For each reachable
ordinary generic instantiation, the compiler substitutes type/constant
arguments, evaluates its pending `comptime if` conditions, and type/effect-checks
only surviving bodies. Region-brand parameters are checked but erased. Interface
selection and overlap are resolved at each instantiation. This phase repeats
until no new reachable instantiation exists; a recursive substitution cycle
without an already completed identical instance is an error.

### Phase 5: close semantic graphs and validate invariants

The compiler closes concrete actor message sums, removes unreachable code, and
checks access/exclusivity, definite initialization, view provenance/escape,
actor message legality, unified wait-for acyclicity, capability provenance, ISR
effects, DMA states, cleanup DAGs, and typed error propagation over the
specialized graph. Declared profile guidance MAY affect representation and
layout but is a hashed input and cannot change language semantics.

### Phase 6: infer regions and resource bounds

The compiler assigns regions and computes task activation bounds, frame
liveness/interference, logical mailbox capacities, queue/request permits, pool
occupancy, sync stack depth, ISR stack requirements, work budgets, priority
inversion, and masked-interrupt bounds. Final physical frame and mailbox sizes
are determined from these proofs in phase 7. Unprovable required bounds fail
here.

### Phase 7: optimize and lay out the image

The compiler performs semantics-preserving whole-image WIR optimization,
including required state-sensitive frame layout, mailbox representation,
continuation forwarding, and proved actor fast paths. It then places static
objects, generated runtime tables, baked artifacts, zero-filled reservations,
task frames, stacks, mailboxes, and pool backing memory. It produces a read-only
`ImageReport` that exposes the optimized physical layout and its logical source
model.

An optimization used to meet a hard footprint or timing assertion is no longer
optional for that artifact: its proof and result are part of the build report.
Backend peepholes that run after the report cannot be used to justify a
language-level safety or capacity proof.

### Phase 8: run post-layout assertions

Functions marked `@layout_assert` receive only `ImageReport`. They may inspect
layout, footprint, specialization, and timing summaries. They cannot emit code,
change capacities, add actors, or cause another layout pass. Failure is a build
error, so there is no phase-ordering fixpoint.

### Phase 9: emit and link

The compiler lowers runtime code, emits target objects and metadata, links the
bootable artifact, and verifies that the emitted section sizes match the report.

## 11. Content-addressed evaluation

The compiler SHOULD cache pure comptime results by compiler revision, target,
function body, arguments, imported constant dependencies, declared build-input
hashes, and relevant quota/profile settings.

A cache hit must be observationally identical to evaluation, including target
semantics and diagnostics. Cache keys cannot include unstable host paths or
timestamps.

Small deterministic tasks such as mkfs, font rasterization, protocol-table
generation, and shader preprocessing are appropriate comptime uses. Very large
artifact generation belongs in the hermetic build system and enters comptime as
a declared hashed input.

## 12. Bootable output

The reference revision 0.1 target is an x86-64 PE32+ UEFI application. The
worked virtio-MMIO appliance uses the separate conforming
`aarch64_qemu_virt_uefi` target because QEMU's `virt` platform defines its first
transport at 0x0a000000 with SPI 16 (GIC INTID 48 / 0x30). Addresses and IRQs
belong to a target package and cannot be copied across machine profiles. Other
targets may conform if they implement the same language invariants.

The generated UEFI entry:

1. receives firmware image/system-table handles;
2. validates the target boot contract, performs all firmware-backed discovery,
   and allocates/reserves every reported image, stack, table, and memory-map
   buffer;
3. initializes memory that does not require further firmware allocation;
4. calls `GetMemoryMap` into the preallocated buffer and immediately calls
   `ExitBootServices` with that map key, with no intervening boot-service call;
5. on `EFI_INVALID_PARAMETER`, repeats only `GetMemoryMap` and
   `ExitBootServices` using the same preallocated buffer until one successful
   exit or the target's finite retry bound is exhausted; no other failure is
   retried;
6. installs target fault and interrupt state;
7. mints capabilities and runs typed driver initialization;
8. initializes actors and supervisors in generated dependency order; and
9. enters the event loop and never returns.

“Exit exactly once” means one successful transition; attempts using stale map
keys are permitted by the bounded retry protocol. Comptime moves deterministic
construction out of boot, but actual device reset, feature negotiation,
memory-map acquisition, secret provisioning, and hardware validation remain
runtime boot operations.

A poll-mode build contains no unused ISR/vector path for that device. A sealed
enum branch eliminated by comptime contributes no code or static data.

## 13. Compiler, target, and library boundary

The language/compiler is responsible for:

- access, view, move, region, and effect checking;
- comptime evaluation and specialization;
- state-machine and frame lowering;
- whole-image analyses and layout;
- atomic park/wake integration; and
- enforcing sealed target capability operations.

The target package is responsible for:

- boot, stacks, interrupt entry, MMIO, DMA/cache ordering, idle, reset, and
  fault-fatal paths; and
- the unforgeable constructors at the hardware boundary.

The standard library supplies actors/mailboxes, scheduler policy, bounded
collections, request/nursery scopes, queue protocols, virtio drivers, filesystems,
and application facilities in ordinary wrela wherever the sealed boundary does
not require target support. Libraries may be replaced, but replacements must
satisfy the same sealed effects and invariants.
