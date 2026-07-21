# Comptime and images

## 1. Compile-time evaluation

`comptime` evaluates ordinary typed wrela code during the build. It is not a
textual preprocessor and does not introduce a second expression language.

There is no comptime function color. A plain `fn` is phase-neutral: it may run
at runtime, or be called from a comptime context when its transitive call
closure is comptime-legal (section 2). `comptime` survives in source only as
`comptime if`, `comptime assert`, and a prefix `comptime` expression that
forces evaluation of the following expression at the enclosing comptime
boundary.

Comptime contexts include:

- const initializers and generic const arguments;
- `comptime if` conditions and a prefix `comptime` expression;
- `@image` and `@layout_assert` bodies, evaluated only by the compiler
  (section 8); and
- a comptime-tier test body (section 12).

```wrela
fn ring_bytes(depth: usize) -> usize:
    return align_up(depth * VirtqDesc.size, 4096)

const QDEPTH = 128
const RING_BYTES = ring_bytes(QDEPTH)
```

Legality is checked at the comptime call boundary — the point where a comptime
context calls a plain `fn` — against that function's complete transitive call
closure. A violation is diagnosed with the offending call path from the
boundary to the illegal operation. Within one package, legality is inferred
without any annotation. A comptime context may call another package's `pub
fn` only when that function declares the verified `@comptime` marker (§2.1);
crossing a package boundary without one is a build error naming the boundary.

## 2. Comptime legality: purity and determinism

A call closure is comptime-legal only when it is deterministic for a fixed
compiler revision, target, source graph, declared build inputs, and step
budget. It cannot:

- perform filesystem, network, console, or device I/O;
- read host environment variables or undeclared files;
- inspect wall time, random state, process identity, or host addresses;
- touch MMIO, DMA, IRQ, or runtime capabilities;
- depend on hash-table iteration with unspecified order; or
- invoke async, actor, or ISR operations.

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

### 2.1 Cross-package legality

Comptime legality is inferred purely from a function's body when the calling
comptime context and the callee share one package. A comptime context outside
the callee's package may call its `pub fn` only if the declaring package
attaches `@comptime` to that function:

```wrela
# declared in package `fontlib`
@comptime
pub fn rasterize(source: FontSource, sizes: [usize]) -> Atlas:
    ...
```

`@comptime` is a contract the declaring package signs, not a promise the
caller makes on its behalf. The compiler verifies it by checking the
function's complete transitive call closure for comptime-legality — the same
rules as this section — at the *declaring* package, not merely at each call
site. A change inside `fontlib` that breaks that closure is diagnosed as a
build error in `fontlib` itself, before it can silently break every
downstream comptime caller. An unmarked `pub fn` remains comptime-legal for
in-package callers; it is simply invisible to comptime contexts outside its
own package.

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

When the bounded evaluator runs one comptime-tier `@test fn`, section 12
catches step, memory, and call-depth exhaustion at that test boundary and
records a failed comptime case. Quota exhaustion during ordinary build
evaluation remains a build error.

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
comptime if MODE == DriverMode.Irq:
    bind_interrupts()
comptime else:
    suppress_interrupts()
```

An eliminated branch contributes no runtime code, wait-for edge, ISR entry,
frame field, or effect. Every surviving generic instantiation is monomorphized.
Every interface call resolves to a direct concrete call or an explicit branch
over a closed enum.

Any configuration that changes the actor, task, ISR, capability, or effect
graph MUST be a comptime type/constant argument of the affected struct or
image node. It cannot be duplicated as a runtime value or a second image-builder
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

`@image` attaches to a plain `fn` returning `Image`. Exactly one reachable
public `@image fn` returns the `Image` value for a build. It declares the
target and creates the complete typed runtime graph. The constructor is
evaluated only by the compiler and is never emitted as runtime code; a
runtime reference to it is a build error. After the graph is sealed, the
compiler generates a distinct runtime image entry whose provenance names the
constructor; generated test harness entries use a separate provenance kind.

```wrela
module appliance.image

from drivers.virtio.block import BlkDriver, VirtioBlock
from storage.service import DmaBlock, Storage
from apps.notes import Notes

const BLOCK_MODE: DriverMode = DriverMode.Irq

@image
pub fn build() -> Image:
    img = Image(
        name="wrela-storage",
        target=Target.aarch64_qemu_virt_uefi,
    )

    block_device = img.device(
        VirtioBlock,
        transport=VirtioMmioTransport(base=0x0a00_0000, irq=0x30),
        required_features=[VirtioFeature.Flush],
        optional_features=[VirtioFeature.RingReset],
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
        strategy=Restart.OneForOne,
        intensity=RestartIntensity(max=3, within=seconds(10)),
    )

    img.seed_disk(comptime extentfs_mkfs(
        files=[SeedFile(ino=7, data=b"hello from the build\n")],
    ))

    img.check_layout(fits_in_64_mib)
    return img.seal()

@layout_assert
fn fits_in_64_mib(report: ImageReport):
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
error. `OneForAll` and `RestForOne` provisioning is ordered so all affected
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
declaration signatures, constant dependencies, attribute names, and bodies
referenced from comptime contexts are resolved and type-checked. Semantic
cycles in constants, layouts, and signatures are rejected. Runtime bodies are
parsed and name resolved sufficiently to discover referenced declarations, but
are not yet checked under an unspecialized comptime branch.

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

### Phase 7: lower, optimize, and lay out the image

The compiler first seals `SemanticWir`, preserving specialized language
operations and proofs, then lowers it to target-independent typed-SSA
`FlowWir`. Semantics-preserving whole-image optimization remains in FlowWir and
produces a separately sealed optimized value. The compiler then lowers to
AArch64 `MachineWir`, fixing ABI, data layout, stack/frame objects, sections,
runtime intrinsics, and proof-bearing backend facts. Required state-sensitive
frame layout, mailbox representation, continuation forwarding, and proved actor
fast paths are recorded as optimization/layout decisions. It then places static
objects, generated runtime tables, baked artifacts, zero-filled reservations,
task frames, stacks, mailboxes, and pool backing memory. It produces a read-only
`ImageReport` that exposes the optimized physical layout and its logical source
model.

An optimization used to meet a hard footprint or timing assertion is no longer
optional for that artifact: its proof and result are part of the build report.
Backend peepholes that run after the report cannot be used to justify a
language-level safety or capacity proof.

### Phase 8: run post-layout assertions

`@layout_assert` attaches to a plain `fn` that receives only `ImageReport`. It
is evaluated only by the compiler at this phase; a runtime reference to it is
a build error. It may inspect layout, footprint, specialization, and timing
summaries. It cannot emit code, change capacities, add actors, or cause
another layout pass. Failure is a build error, so there is no phase-ordering
fixpoint.

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

## 12. Tests

`@test` attaches to a plain `fn`. wrela has two test execution tiers: a
comptime-tier test, whose closure may run in the build evaluator, and a
runtime/image test, which runs as a generated image test (section 12.2). Tier
selection follows the closure's comptime-legality (section 2): a
comptime-legal closure runs comptime-tier (section 12.1) unless the test
declares `@test(runtime)`, which forces the runtime/image tier regardless of
legality. Bare `@test` is unchanged: it runs comptime-tier whenever legality
allows it.

### 12.1 Comptime-tier tests

Both production and test modules are discovered by the same deterministic
sorted walk of `source_root` described in
[Source language](02-source-language.md); there is no hidden test-only source
loader or separate manifest listing. For example, `src/app/math.wr` and
`src/app/math_test.wr` are both ordinary modules beneath `source_root`:

```wrela
# src/app/math.wr
module app.math

pub fn add(left: u32, right: u32) -> u32:
    return left + right
```

```wrela
# src/app/math_test.wr
module app.math_test

from app.math import add

@test
fn add_combines_two_values():
    result: u32 = add(20, 22)
    comptime assert result == 42, "add returned the wrong value"
```

Discovery selects `@test fn` declarations from manifest-declared modules in
the root package; it does not run `@test` declarations from dependencies. A
selected test whose complete transitive call closure is comptime-legal
(section 2) and that does not declare `@test(runtime)` evaluates in the build
evaluator against the ordinary resolved declarations — the compiler does not
substitute a fixture, host callback, or second evaluator implementation. A
test whose closure is not comptime-legal, or that declares `@test(runtime)`,
is a runtime/image test instead (section 12.2).

Evaluation is deterministic and left-to-right, uses only the sealed source
graph and declared build profile, and has no runtime or ambient-host effects.
Every test receives a fresh, isolated invocation frame with a bounded
source-aware call stack.

A false `comptime assert` is a failed case naming its phase, stable message,
and source identity. Exhausting the evaluator's step, memory, or call-depth
quota at a test boundary is likewise a failed case — not a build error —
naming the exhausted resource and a source-aware call stack, as is a checked
arithmetic error. These case failures publish the canonical test report and
make the command unsuccessful; they are not reclassified as infrastructure
failures. Outside a test boundary, an assertion or quota failure keeps its
ordinary build-error classification.

A source-shape error — an unsupported signature, an invalid call target or
argument, a type mismatch, an uninitialized or moved-from use, and similar —
aborts discovery with an ordinary compiler diagnostic instead of publishing a
report. Publication is atomic: cancellation or an aborted discovery yields
neither a partial plan nor a partial report.

Discovery, evaluation, and reporting consume one canonical, sealed test plan.
Tests are identified by canonical `package@version::module::function` name,
independent of the invoking workspace or output path.

### 12.2 Runtime and image test design

A zero-argument `@test fn` or `@test async fn` whose closure is not
comptime-legal, or that declares `@test(runtime)`, is a runtime/image
(integration) test. Discovery constructs a
generated, bounded `@image` harness containing the selected tests under the
same runtime/standard-library/target semantics as an ordinary image. Each
test has a statically allocated activation, stack/frame, event, output, and
timeout bound. The harness reports assertion/log/terminal events through the
compiler-owned test runtime intrinsic; it is not a hosted executable and
cannot call host libraries.

An image test is declared in `wrela.toml`. It selects an existing declared
`@image` root, a host scenario, finite boot/shutdown/event/output time and size
bounds, and an optional deterministic seed. It tests boot, image wiring,
drivers, scheduling, teardown, and protocol behavior without changing the image
language semantics.

Discovery produces one canonical, build-bound plan. Test IDs, scenario IDs,
and independently compiled image-group IDs are dense within that plan;
generated runtime tests additionally carry a fixed-size content identity for
the exact monomorphized function. The plan retains finite ceilings for test and
group counts, scenario steps, plan/report payload, events, process output, and
wall-clock execution. Compilation and reporting consume the sealed plan rather
than reconstructing selection from display names.

The scenario is a declared, digest-bound, schema-versioned TOML input returned
by package loading and included in the source-graph identity. Revision 0.1
scenario steps may send or expect bounded framed PL011 bytes, expect a typed
test event, expect emulator exit, or request bounded shutdown. Every wait has a
nonzero host timeout. Scenario waits do not advance, replace, or redefine guest
language time; the process executor applies them to the live QEMU session.

The canonical scenario schema is closed: unknown keys, duplicate keys, unknown
step kinds, invalid hex, empty byte sequences, zero waits, and trailing data are
errors. Wait budgets use checked addition. A scenario must observe either one
`run-finished` event or one final process exit; it cannot perform another action
after exit, and a referenced test ID must belong to the consuming image group.
A representative scenario is:

```toml
schema = 1
name = "boots-and-serves"

[[step]]
kind = "expect-test-event"
event = "run-started"
timeout_ns = 30000000000

[[step]]
kind = "send-serial"
bytes_hex = "70696e670a"

[[step]]
kind = "expect-serial"
bytes_hex = "706f6e670a"
timeout_ns = 1000000000

[[step]]
kind = "request-shutdown"
timeout_ns = 5000000000

[[step]]
kind = "expect-exit"
code = 0
timeout_ns = 5000000000
```

`event` is one of `run-started`, `test-started`, `log`, `assertion-failed`,
`test-finished`, `heartbeat`, or `run-finished`. An event step may additionally
name a discovered test ID and a nonempty message substring where that event has
text. Steps execute in file order. The codec enforces manifest and per-step byte
limits before constructing a test plan.

Both runtime forms compile and link an ordinary AArch64 UEFI application and
boot it under the complete runner contract of
`aarch64-qemu-virt-uefi`. The target contract pins the versioned QEMU `virt`
machine, CPU, TCG policy, vCPU/memory configuration, UEFI firmware, boot medium,
and PL011 transport. The emulator, firmware, target runtime, target package, and
test image are digest-checked build/test inputs. A toolchain cannot substitute a
hosted target, native host execution, a mock standard library, or a second
runtime semantics for an integration or image test.

Guest/compiler events use one versioned, bounded, checksummed frame format with
strictly increasing sequence numbers and exactly one terminal run event. The
host distinguishes assertion/test failure from discovery, compile, link, boot,
timeout, crash, protocol, and shutdown infrastructure failure. Missing QEMU or
firmware is an infrastructure error, never an implicit skip or pass. The test
report records image, complete target-package (including firmware), emulator,
invocation, and event-stream digests.

## 13. Bootable output

The revision 0.1 target set contains only the
`aarch64-qemu-virt-uefi` ARM64 PE/COFF UEFI full-image target (spelled
`Target.aarch64_qemu_virt_uefi` in source). The worked virtio-MMIO appliance
uses QEMU's `virt` platform, whose first
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

## 14. Compiler, target, and library boundary

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
