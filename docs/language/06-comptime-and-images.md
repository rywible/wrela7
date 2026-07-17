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

When the bounded evaluator runs one `@test comptime fn`, section 12 catches
step, memory, and call-depth exhaustion at that test boundary and records a
failed comptime case. Quota exhaustion during ordinary build evaluation remains
a build error.

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
The constructor is evaluated only by the compiler and is never emitted as a
runtime function. After the graph is sealed, the compiler generates a distinct
runtime image entry whose provenance names the constructor; generated test
harness entries use a separate provenance kind.

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

## 12. Tests

The complete revision 0.1 design reserves three test forms with two execution
semantics. The first implementation claim is intentionally narrower: genuine
source-level comptime unit tests over ordinary production functions. Test-plan
construction, report rendering, QEMU orchestration, or a fixture containing
only `comptime assert true` is not evidence that this source-unit contract is
implemented.

### 12.1 Bounded source-level comptime unit tests

This subsection describes the implemented bounded surface. It is a narrower
delivery claim than the complete revision 0.1 design, and it remains supported
only while the named source, workspace, and public-CLI gates recorded in the
requirements matrix and verification log pass.

The root package manifest declares both production and test modules in the
ordinary module graph; there is no hidden test-only source loader. For example:

```toml
[[module]]
name = "app.math"
path = "app/math.wr"

[[module]]
name = "app.math_test"
path = "app/math_test.wr"
```

```wrela
# src/app/math.wr
module app.math

pub comptime fn add(left: u32, right: u32) -> u32:
    return left + right
```

```wrela
# src/app/math_test.wr
module app.math_test

from app.math import add

@test
comptime fn add_combines_two_values():
    result: u32 = add(20, 22)
    comptime assert result == 42, "add returned the wrong value"
```

Discovery selects `@test comptime fn` declarations from manifest-declared
modules in the root package. It does not silently run `@test` declarations from
dependencies. A selected test may import a public, module-level production
`comptime fn`, pass supported values, consume its result, and exercise further
direct user-function calls made by that production function. Every callee is
the ordinary resolved HIR declaration; the compiler does not replace it with a
fixture, host callback, or second evaluator implementation.

The active scalar subset is `unit`, `bool`, and the target integer types `u8`,
`u16`, `u32`, `u64`, `u128`, `usize`, `i8`, `i16`, `i32`, `i64`, `i128`, and
`isize`. The active aggregate subset is a nominal, nongeneric `struct` whose
fields are all active scalar types, have no defaults or attributes,
and require no interface specialization. Such a flat structure may cross a
module boundary through a public type and public fields; may be used as a
parameter, local, or result; may be constructed with every field supplied
exactly once; and may be projected to a scalar field. Multi-field constructors
require named arguments and bind them by declaration name independent of source
order. A one-field constructor may use its sole positional argument. Privacy,
nominal identity, duplicate, missing, and unknown fields are checked rather
than inferred from equal layouts.

Within that subset, test and callee bodies may use typed parameters, typed or
inferred locals, local initialization and reassignment, `if`/`elif`/`else` and
`comptime if`, explicit and implicit unit returns, direct nested calls with
positional or declaration-matched named arguments, integer
unary/arithmetic/wrapping/bitwise/shift operations, scalar comparisons, and
short-circuit `not`/`and`/`or`. A bare flat-structure parameter is a read, as in
the ordinary parameter contract. Producing an independently owned value from
it requires `copy`. Assignment and return move an owned non-scalar local unless
`copy` is written; every continuing branch must leave a later-read local
initialized. Use after move and an attempted ownership-producing use of a bare
read parameter are rejected before evaluation. Integer widths, signed
two's-complement ordering, checked and wrapping overflow, division/remainder,
and shifts follow sections 5.1 and 8 of chapter 02. The exact most-negative
signed literal is admitted without first requiring its unnegated magnitude to
fit; this includes inferred `i64::MIN` and explicitly typed signed minima.
`usize` and `isize` use the selected target width rather than the compiler host
width.

Evaluation is deterministic and left-to-right, uses only the sealed source
graph and declared build profile, and has no runtime or ambient-host effects.
Every test receives fresh invocation frames. Calls preserve parameter/local
isolation and a bounded source-aware stack containing each callee and call site.
Steps and abstract evaluator memory are charged in host-independent units. The
effective evaluator step limit is
`min(semantic evaluator_steps, profile comptime_steps)`, and its effective
memory limit is
`min(semantic evaluator_bytes, profile comptime_memory_bytes)`. Active call
depth is checked separately at
`min(profile comptime_call_depth, 32)`; 32 is the reviewed host-safe envelope
for active Wrela invocation frames. The complete retained host-recursion shape
from active calls plus nested syntax is independently capped at the fixed
cumulative envelope 48. This prevents otherwise legal call and per-function
syntax maxima from multiplying beyond the reviewed host stack until evaluation
moves to an explicit continuation stack. Aggregate-aware evaluator frames made
the former 96-unit envelope unsafe on the deliberately small regression stack.
The conservative 1-MiB-stack proof now genuinely admits 48 and rejects 49 with
the stable comptime resource-limit classification; the language-visible
active-call cap remains 32.

Flat structures have canonical evaluator accounting of 32 bytes for the value
header plus 32 bytes per scalar field. Construction, copy, projection,
replacement, discarded temporaries, and successful frame teardown poll their
complete logical field traversal. Payload retention is released only after the
corresponding bounded cleanup succeeds, so exact and one-under step and memory
limits remain deterministic across compiler hosts.

The other evaluator-owned payloads follow the same rule. Text is one explicitly
polled allocation. An evaluated Image stores the image name and all installed
actor names in one contiguous string arena, while actor records contain only
copyable checked ranges into that arena. Replacement, discarded temporaries,
successful frame cleanup, and image-install snapshots poll every logical actor
or text chunk before crediting released quota; the remaining host destruction
is constant-work even when cancellation interrupts cleanup. Arena appends and
copies are chunk-polled, hidden project-sized value cloning is unavailable, and
quota release uses checked subtraction that fails closed on an internal
accounting mismatch.

Canonical semantic ordering is also cancellation-aware. Every production sort
in the analyzer uses a bounded stable merge/index sort with fallible scratch,
polled comparisons/copy-back/permutation, and byte-polled string comparison.
The exact scratch bound is accepted, the first over-bound input is rejected
before scratch fill, and cancellation at the final comparison prevents result
publication.

Before execution, one bounded static checker validates the selected test and
its complete direct-call closure, including operations in untaken branches and
short-circuit right operands. Its work and storage ceilings are each the
semantic `fact_edges` limit, and its effective syntax depth is
`min(semantic constant_depth, 32)`. It publishes a type-check proof only after
that closure succeeds; the proof names every checked declaration source and
records the checker's exact work count. Before constructing a source-aware
closure diagnostic, the checker charges its code, message, and stack labels
against both the semantic `diagnostic_bytes` and `test_bytes` ceilings. A label
costs its exact UTF-8 message bytes plus 64 canonical logical structural bytes;
that logical charge is target-independent quota accounting, not a claim about
one host allocator's layout. These checker ceilings are semantic analysis
ceilings, not extra manifest comptime allowances. For every effective bound,
the exact limit is accepted and the first over-limit operation fails.
Cancellation is polled during static closure checking, diagnostic measurement
and copying, discovery, expression/statement execution, calls, and bounded
model/report construction.

Semantic text materialized around this vertical is bounded at its source size:
float-spelling normalization used by ordinary scalar analysis and actor-derived
fact text check `fact_bytes` before allocation, reserve fallibly, and poll
cancellation while copying each 64-byte source chunk. Exact size is admitted
and the first extra byte fails. These bounded support paths do not add floats or
actors to the comptime unit-test value subset.

A false `comptime assert` is a failed case with phase `comptime`, its stable
message, and source identity. Step, memory, active-call-depth, or cumulative
host-recursion exhaustion is also a failed comptime case with code
`semantic-comptime-resource-limit`, the applicable stable resource name and
limit, and a source-aware stack. These case failures publish the canonical test
report and make the command unsuccessful; they are not reclassified as
infrastructure failures. Checked arithmetic errors are likewise failed
comptime cases and retain the stable `semantic-comptime-arithmetic` code plus
their source-aware call stack.

Source-shape failures remain source diagnostics: unsupported signatures,
invalid call targets or arguments, scalar type mismatches, invalid integer
literals, invalid or uninitialized locals, and missing returns use
`semantic-comptime-signature-not-supported`,
`semantic-comptime-call-target`, `semantic-comptime-call-argument`,
`semantic-comptime-type-mismatch`, `semantic-comptime-integer-literal`,
`semantic-comptime-local`, `semantic-comptime-uninitialized`, and
`semantic-comptime-missing-return`, respectively. Only an operation that is
outside the implemented evaluator subset uses
`semantic-comptime-operation-not-implemented`; it is not a catch-all for type,
call, or quota errors. Any such source diagnostic aborts discovery and
publishes no report that could be mistaken for a completed run. Exhausting a
pre-execution semantic checker/model ceiling also aborts without a report;
diagnostic construction that exceeds either output ceiling retains the stable
`diagnostic bytes` or `test plan or results` resource classification.
Cancellation likewise aborts the operation and atomically publishes neither a
partial plan nor a partial report. Outside a test boundary, an assertion or
evaluator-quota failure retains its ordinary build-error classification.

Unsupported aggregate shapes use
`semantic-comptime-aggregate-not-supported`. Constructor and field-shape
failures, cross-module private-field access, use after an aggregate move, and an
attempt to move a bare read parameter retain their more specific stable
diagnostics, including `semantic-comptime-constructor-argument`,
`semantic-comptime-field-private`, `semantic-comptime-use-after-move`, and
`semantic-comptime-borrowed-value-move`. They are source diagnostics, not
failed test cases or quota failures.

The public comptime-only route is:

```text
wrela test <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY] --comptime
```

It discovers and evaluates the genuine source tests, then publishes the same
bounded canonical report schema used by the test system. Comptime cases carry
no fabricated runtime duration or image execution. Their names are canonical
`package@version::module::function` names and their dense IDs are assigned only
after selection. The independent name-filter route is, for example:

```text
wrela test <wrela.toml> <IMAGE> [OUTPUT-DIRECTORY] --name-contains app.math_test::add_combines_two_values
```

`--comptime` and `--name-contains` are mutually exclusive selection modes and
must not appear in the same invocation. `--name-contains <TEXT>` filters the
canonical names before plan sealing, so the checked-in selection gate invokes
the same imported production functions rather than selecting synthetic model
fixtures. Canonical report bytes do not bind absolute workspace or output
paths.

This bounded vertical is not general unit-testing support. Class construction
and values, receiver or associated methods, generic functions or structures,
nested or otherwise non-flat aggregates, aggregate equality, floating point,
loops and loop control, and other comptime forms remain follow-on evaluator
work. `Result`/`Ok`/`Err` are not in the active core subset, so a returned `Err`
is not currently a supported test outcome; when that core type is implemented,
`Result[unit, E]` test returns require their own stable failure representation
and gates. Runtime `assert` lowering, generated runtime-image unit tests, and
ordinary or async runtime test execution are also explicit follow-on work and
cannot be inferred from comptime report success.

### 12.2 Runtime and image test design

A zero-argument `@test fn` or `@test async fn` is reserved as an integration
test. The complete implementation constructs a generated, bounded `@image`
harness containing the selected tests and the same
runtime/standard-library/target semantics as an ordinary image. Each test has a
statically allocated activation, stack/frame, event, output, and timeout bound.
The harness reports assertion/log/terminal events through the compiler-owned
test runtime intrinsic; it is not a hosted executable and cannot call host
libraries. This design is not an implemented runtime-unit claim until runtime
assertion lowering and source-to-image end-to-end gates pass.

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
