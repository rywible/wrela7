# Wrela core model

> Part 1 of the Wrela design sketch. Companions:
> [image-runtime.md](image-runtime.md) — targets, provenance, boot, the
> runtime graph, the executor, and doorbells.
> [examples/virtio-appliance.wr](examples/virtio-appliance.wr) — the worked
> virtio appliance (drivers, tasks, image).
>
> This is aspirational design, not current compiler input.

## The thesis

Wrela is an appliance-image language, and its central property is this:

**The compiler sees the entire appliance.** Every device, driver, task,
capability, suspended frame, byte of memory, and edge of the authority graph
is known at image build time. There is no dynamism left to defeat the
analysis — no heap, no threads, no interrupt handlers, no dynamic task
creation, no runtime hardware discovery, no blocking primitives.

Safety comes from deleting whole categories of dynamism rather than from
checking them. The static runtime graph is the proof artifact; the language
rules below exist to keep that graph statically visible. The compiler's
computed memory demand is a proof, not a hope.

Concretely, a Wrela image:

- targets one fixed hardware contract, validated at boot, failing early if
  the expected device is missing or wrong — no broad discovery;
- runs boot code with high machine authority that binds drivers imperatively
  and returns a smaller runtime object graph — kernel code never receives
  the platform root, PCI root, raw memory, firmware, CPU setup, or generic
  MMIO authority;
- expresses privileged operations as methods on capability classes, never as
  globally callable functions;
- has no blocking I/O: every device operation is a submitted request that
  completes later — durability, arrival, and expiry are all completions;
- writes sequential-looking logic with async/await, which compiles to
  statically sized state machines resumed by one generated executor loop;
- has no interrupt handlers, only doorbells: a device interrupt may do
  exactly one thing — end a halted CPU's sleep;
- implements bounded containers (List, Ring, Option, Result, Bytes) as
  ordinary stdlib Wrela code over one sharp compiler-provided primitive,
  `Storage[T, N]` —
  not as a hidden C++ runtime;
- exposes no pointers, address-of, pointer arithmetic, nullable references,
  ambient heap, or stored borrows in source.

## The load-bearing assumption

**The runtime is single-threaded, cooperative, and non-reentrant.**

This is not an omission; it is the property that lets Wrela drop lifetime
variables and a general borrow checker. No interrupt or second thread can
enter a Wrela object. Tasks interleave only at await points, and no loan may
live across an await (R10), so the only aliasing that can ever occur is the
aliasing visible inside a single synchronous call tree — and that is
controlled by the loan law (R3). The one true asynchronous actor in the
system is DMA hardware, and it is quarantined to device-owned memory by R8.
SMP would require a Send-equivalent and is explicitly out of scope for V1.

## Threat model and theorem boundary

Wrela's V1 theorem is a **memory-safety and bounded-memory theorem**, not a
blanket security claim. The build trusts the compiler and sealed intrinsic
packages; the target package is accepted only with a versioned certificate
described in `architecture.md`; and driver code is trusted for device protocol
correctness. Isolating a broken driver/device from other drivers additionally
requires a distinct certified IOMMU domain. Kernel
and service code are not trusted with driver authority merely because they are
part of the image: capability effects are checked transitively across wrappers
and interfaces.

Devices are treated as hostile producers of field values for bounds, enum,
length, and ownership-selection purposes. A transport that does not return an
authenticated generation (virtio split rings, for example) cannot let software
prove that a very late duplicate completion belongs to a newly reused slot.
Such transports therefore require a target-certified **protocol-compliant
completion** assumption in addition to field guards. The compiler guarantees
that malformed fields cannot directly forge CPU values, and that descriptor
construction cannot intentionally name memory outside its provenance domain;
it does not guarantee that a malicious disk really persisted data or that a
malicious NIC delivered an authentic packet.
Containment of a device that ignores its programmed descriptors requires a
target-certified IOMMU/vIOMMU domain; without one, obedience to the programmed
DMA aperture is an explicit device assumption. Source-level provenance alone
cannot constrain a physically malicious bus master.

V1 does not claim tenant isolation, confidentiality between tasks intentionally
wired together, availability against trusted code deliberately invoking a
fatal path, resistance to timing/speculation side channels, secure boot, or
image authenticity. Those are separate target and deployment properties. The
generated target-fatal path is available only to driver, boot, fault, and
executor code; kernel and service code require an explicitly wired `PanicSink`.

## The mental model

Three words cover the user-facing ontology:

- **value** — transparent data (`primitive type`, `type`, `enum`,
  `bitflags`). Read-only when lent; machine scalars materialize freely when
  observed (R4). What you compute with.
- **object** — encapsulated state (`class`). Usable when lent: lending an
  object means "use this on my behalf." What you operate.
- **wire** — foreign bytes. Inert until parsed through an explicit guard.
  What you must not trust.

An `interface` is not a fourth kind, and it is not a value: it is a
compile-time contract that implementing classes must satisfy, monomorphized
and erased (R7). Code written against an interface is generic code; by
runtime, only concrete objects remain.

Nothing copies implicitly — everything moves, and duplicating an aggregate
is always an explicit call (R4). Everything else in the language is a rule
about how these three kinds move, loan, suspend, and cross the device
boundary.

## The rules

Rule numbers are stable: text everywhere says "R9", never "the token rule".

### Values and loans

**R1. Declaration forms.** There are exactly these kinds of user declaration:

| form             | meaning                                                                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `primitive type` | a compiler-known scalar value                                                                                                                       |
| `type`           | a transparent value aggregate; may carry an `invariant` clause and methods; value semantics                                                         |
| `class`          | an object with optional `needs:` handles, encapsulated `storage:`, optional invariants, constructors, and methods; may declare `implements <interfaces>` (R7) |
| `enum`           | a tagged union; may be given a backing integer type                                                                                                 |
| `bitflags`       | named bits over a backing integer type; implicitly has `none` (the empty set)                                                                       |
| `registers`      | a volatile field layout (field name, type, width, access, optional fixed-size index) for MMIO and shared DMA control memory (R8)                    |
| `wire`           | an on-wire byte layout used only by `parse`                                                                                                         |
| `interface`      | a compile-time contract implementing classes must satisfy; monomorphized and erased (R7)                                                            |
| `executor interface` | an interface whose callable surface is visible only to the generated executor (R12)                                                           |

plus the config DSLs: `image`, `target`, `phase`, `layer`.
`()` and finite tuples are compiler-known structural value type constructors,
not declaration forms; tuple elements follow ordinary move/drop/linearity rules.
`Self` is a lexical alias for the enclosing declaration, and `type X = Y` is a
transparent alias rather than a new declaration kind.
`constructor fn name(...)` declares an infallible class constructor (R5). If a
class declares no constructor, `T(...)` is its default named-field constructor.
Fallible setup stays an ordinary static factory returning `Result[Self, E]`.
`async` is a function modifier (R10), not a declaration form. Tasks are
scheduled inside an `executor fn` (R11), not at top level.

Compiler-provided declarations (`Storage`, `Ref`, `View`, `Slice`, `Token`, `Wait`, the
capability classes, and the image/runtime hooks) live in a sealed intrinsic
prelude. They look like ordinary declarations when used, but their identity,
constructors, hidden fields, drop glue, and privileged lowering are
compiler-owned. User code may not shadow, implement, construct, or counterfeit
them.
Specification listings use `abi class` and `abi fn` to show declarations
generated by a sealed ABI package. Those spellings are not accepted in user
modules and do not add user declaration forms.

Declarations live in modules; module exports are the visibility mechanism
(`Storage` is unexported by the stdlib and sealed by the intrinsic prelude).
An exported transparent value may keep individual representation fields
`private`; such fields participate in layout/invariants but cannot be named,
projected, or structurally constructed outside the defining module.
Modules are namespacing and visibility only; they do not grant authority by
themselves. Module-level mutable storage is not a declaration form in V1.
Every mutable object that can persist across calls must be reachable from the
image's returned runtime object graph or from a compiler-generated frame. `const`
items are compile-time values, not hidden mutable roots.

Byte order is explicit by default: `wire` fields are big-endian (network
order); `registers` layouts — MMIO and shared DMA alike — are little-endian
(bus order); either can be annotated per field. Materialized scalars are
host-order; the boundary forms do the swapping.

Parsing a `wire` value produces a loan-bearing projection by default. Fixed
scalar fields materialize as values, but variable-length byte fields are
`WireView` projections into the source `View[U8]`; they cannot be stored, held
across awaits, or used after the source frame/buffer loan ends. If code wants an
owned `Bytes[..N]`, it must copy explicitly into one. This keeps `parse` total
and non-allocating: no hidden bounded copy is smuggled into field access.

`registers` fields may be scalar or fixed-size indexed fields. MMIO layouts
use explicit offsets unless they name a target-provided ABI layout; shared DMA
layouts use explicit offsets or a checked ABI layout with target alignment and
atomicity guarantees. Register field types must be **register-safe**: primitive
integers, bitflags with declared reserved-bit behavior, open enums that can
carry `unknown(raw)`, or raw aggregates made only of those. Reads of a closed
protocol type are checked conversions that return `Result`; plain `read`
cannot manufacture a trusted closed enum or invariant-bearing aggregate from
device bytes. Indexed fields are accessed through the same typed volatile
accessors (`.desc[i]`), with `i` bounds-checked under R16; there is no pointer
arithmetic escape for register tables.

An open enum is declared `open enum E: U16 ... unknown(raw)`; unknown bit
patterns construct only that explicit variant. A closed enum never materializes
from foreign storage without checked conversion. Bitflags declare reserved bits
as `reject`, `read_masked`, or `read_preserve`; writing a preserved unknown bit
back requires a sealed read-modify-write helper, so generic code cannot echo
device-controlled reserved bits. Integer narrowing and signedness changes are
checked conversions returning `Result`; only same-width explicitly named bit
reinterpretation on `wire_plain` scalars is permitted.

Every registers field also has a CPU access class. `read`, `write`, and
`read_write` are available through the ordinary typed accessors. Only a named
sealed helper from the field's ABI package may perform the write side of
`sealed_write`, `read_sealed_write`, or `sealed_read_write`. Any field that
contains a bus address, descriptor address,
IOMMU key, queue publication index, or other device-reachability authority MUST
use a sealed access class or a sealed provenance-bearing field type; an ordinary
integer-typed `write` accessor is forbidden. Device/CPU direction is recorded
separately from CPU access, so a device-written field is always foreign-derived
even when its machine representation is an integer.

A type used directly in `wire`, DMA, or register storage must satisfy a sealed
structural predicate:

- `wire_plain`: fixed-size, padding-free data made only from explicitly sized
  integers, fixed arrays, and other `wire_plain` values;
- `register_safe`: the register-safe set above, with every padding byte and
  multi-access snapshot rule fixed by the ABI;
- `dma_plain`: padding-free `wire_plain`/register-safe data containing no class,
  capability, loan, linear value, compiler-private address, enum with invalid
  bit patterns, or user destructor.

These predicates are compiler-derived and cannot be implemented by user code.
Device-writable DMA may contain only `dma_plain` values and remains
foreign-derived after completion until guards discharge the facts actually
checked. Copying, moving, storing, wrapping in an aggregate, or passing through
a helper propagates foreign provenance; none of those operations launders it.

`wire` layout is packed by explicit offsets or declared sequential packed
order, has no implicit padding, and must
state whether trailing bytes are consumed, rejected, or projected by a final
bounded `WireView`. Fixed byte arrays materialize by a visible bounded copy;
variable fields remain projections. Nested fields must be `wire_plain` or
another `wire` layout. Parsing never invokes user constructors or methods.

`emit X(value) into slice guard: ...` is the write-side dual. It accepts only
owned/loaned protocol-safe fields satisfying the wire layout's verified guard,
writes each byte exactly once in declared order, and returns
`Result[USize, EmitError]` without partial publication outside the Slice. A
too-small destination or failed refinement returns before modifying the Slice;
checksums/length fields declared by the wire ABI are generated from the emitted
payload rather than trusted caller scalars.

An `abi` annotation names a target-provided layout contract: it fixes offsets,
strides, and ordering, and it GENERATES the sealed helpers and guards that ABI
declares (virtqueue install, descriptor install, guarded drain). Explicit
offsets written alongside an `abi` are checked against it — redundancy as
verification, not conflict.

ABI packages are sealed, versioned compiler inputs, not user-extensible magic.
Each generated helper has a machine-checkable contract from the proof-obligation
list below, and the target certificate binds the package hash, field layout,
access widths, fence sequence, and final lowering. An ABI helper may not create
an effect absent from that contract.

### Proof Obligations

The compiler's safety result is carried by explicit summaries, not by comments.
Every function, method, generated hook, and sealed helper receives a
compiler-visible proof summary containing at least:

- whether it can `await`, trap, panic, or enter target fatal;
- bounded-work cost for loops, repeated descriptor work, bulk copies, and
  deinitialization;
- loan-bearing returns and the source each returned projection depends on;
- linear values consumed, produced, parked, completed, quarantined, or moved to
  recovery;
- provenance edges created, adopted, or destroyed;
- MMIO, shared-DMA, and DMA-publication effects, including volatile ordering and
  fence requirements;
- token/Wait source effects: mint, arm, complete, abandon, reset, and deadline
  predicates;
- the canonical runtime object/source identity touched through every direct
  path, static handle, wrapper, and interface binding;
- the complete declared interface effect contract and proof that an
  implementation's effects are no stronger than it.

A sealed helper is not an exemption from the source rules. Its declaration must
state preconditions, consumed resources, memory effects, publication point,
failure behavior before and after publication, ordering/fence requirements,
whether it can trap or target-fatal, whether it can mint/adopt provenance, and
what cleanup obligation exists if the target fatal path fires. Lowering passes
must preserve these summaries: after each Wrela-specific lowering, a verifier
checks linearity, provenance, loan/projection scopes, token registry balance,
DMA-publication barriers, volatile access ordering, and the async frame
no-loan-across-await invariant.

The compiler rejects an obligation it cannot prove. Solver timeout, unknown
layout, missing target evidence, or an effect absent from an interface contract
is a compile error, never an assumed fact.

**R2. Passing and ownership.** There are exactly two parameter modes — you
either LEND a value or you GIVE it:

- `x: T` — **lend** (default). A non-escaping loan for the duration of the
  call. What the callee may do through the loan depends on what T is:
  _values_ are read-only; _objects_ grant full use — the callee may call any
  method, including mutating ones. (An interface-typed parameter is a
  bounded generic, R7: the concrete object bound to it is lent like any
  object.) Read-only access to object contents is expressed by lending a
  `Ref` or `View`; read-write access to a sub-range is a `Slice` (R3).
- `consume x: T` — **give**. Ownership transfers to the callee. Only
  consumed values (including `consume self`) may be moved into storage,
  returned, or released.

Values may OWN objects: a `type` field or enum payload may hold a class
(BootCaps holds capabilities; RecvStatus payloads are PacketBuffers). Owning
is orthogonal to lending: a lent value lends its object fields READ-ONLY,
like a Ref — activating an object field requires owning the aggregate, or
moving the field out under R4's partial-move rules.

Instance methods spell `self` explicitly as their first parameter; static
helpers omit it. A method call is simply the receiver being lent: it
ACTIVATES `self` — an exclusive object lend — for the duration of the call.

Executor-wired `needs:` fields use a third concept that is not a parameter mode:
a STATIC HANDLE. A handle is a compiler-known reference to an image-static
object. It may live in an async task object across awaits because it is not a
loan. Calling a method through a handle creates a normal short activation loan
for that synchronous call only. Handles are introduced only by the executor's
`schedule` construction of task objects and by monomorphized helper calls that
receive those wired objects; user code cannot store arbitrary handles in data
structures. In V1 a handle may appear only in a `needs:` field of an
executor-constructed task object, as a parameter of a helper immediately called
from such a task, or as a compiler-generated async-frame field. It may not be
returned, stored in `storage:`, captured by a value, abstracted over by a
generic predicate, or converted into an address-like value. "Handle-ness" is a
compiler kind, not an ability user code can implement.

A `needs:` field names an authority edge, not owned memory. It must be typed as
an interface or runtime-safe sealed capability, is immutable after construction,
is not moved or dropped, and is not part of the class's owned storage invariant.
Multiple task objects may have `needs:` handles to the same runtime object. This
does not create a CPU data race: each call through a handle creates one
synchronous activation of the target object, activations cannot cross awaits,
and the generated executor never overlaps task resumes.

Handle aliases are canonicalized to the concrete runtime-object identity before
R3 is checked. Thus two differently named `needs:` fields wired to the same
object are aliases for call-site disjointness, and cannot be activated as
siblings. Once executor wiring creates a handle or an awaitable source identity,
that source object and every ownership-tree ancestor that determines its address
are image-static: they may be mutated but never moved, replaced, or consumed.

**In-place returns.** A returned value is constructed directly in the
caller's storage; this is a language guarantee, not an optimization (easy to
guarantee because nothing aliases). "Fill this buffer for me" is spelled as
an ordinary return; there is no out-parameter mode.

**R3. The loan law.** Every lend — default parameters, `self` activation,
`Ref` (a single-value read loan), `View` (a sequence read loan), and `Slice` (the reified EXCLUSIVE
read-write loan) — is a LOAN, and one law covers them all:

- A loan never escapes: it may not be stored in a field, returned past the
  value it was projected from, moved, or held across an await point (R10)
  or a device boundary (R8).
- An object lend is EXCLUSIVE: while X is lent, no other loan of X may exist
  and the lender cannot touch X.
- While a read loan of X is live, X is FROZEN: no code on the stack may
  mutate X.
- A Slice reifies an EXCLUSIVE lend: projecting one requires exclusive
  access to the source, and while it lives the source is exclusively loaned
  — no sibling loans at all, where a Ref/View merely freezes. Read loans may
  coexist; a Slice is singular per source unless produced by consuming
  `split`. Ref/View are look; Slice is edit.
- A holder may RE-LEND what it holds: loans nest through the current holder
  (a callee that was lent an object may lend it onward). Exclusivity
  forbids SIBLING loans, never nested ones.
- CALL-SITE DISJOINTNESS: the paths lent or consumed at one call must be
  pairwise disjoint — `f(x, x)`, `f(x, x.view())`, and lending both `self`
  and a field of `self` to the same callee are compile errors. The
  destination of an assignment joins the same check, because returns
  construct in place (R2): `x = f(x.view())` would write under a live
  freeze, and is rejected.
- LOAN-BEARING AGGREGATES are loans: a `Result[Ref[T], E]`, a `Result[View[T], E]`, a
  `Result[Slice[U8], E]`, or the pair returned by a consuming split obeys
  the same law as the loan it carries — match it and use it within the
  source's scope; it cannot be stored in storage, returned past the source,
  or held across an await. (This is what makes view-returning accessors
  like `List.get` legal.)

A method may return a Ref or View into `self`; the result is a projection valid only
for the caller's loan of the receiver. This is the whole borrow story: Wrela
does not have user-written lifetime variables, but it does have a finite
synchronous loan checker that tracks projection provenance, path disjointness,
freezes, and non-escape within one call tree. It is checkable per call tree
because nothing else — no thread, no interrupt, no suspended task (R10/R11) —
can observe an object while an activation loan is live.

**R4. Copies, cleanup, and linearity.** Ownership character is mostly
derived, not declared:

- **Nothing copies; everything moves.** No value or object is ever copied
  implicitly — assignment and `consume` move. Two carve-outs, both narrow:
  - **Scalars materialize.** Observing a machine scalar through a read loan
    (`let a = b`, `x + 1`, `id.vendor`) produces a fresh value. Machine
    scalars are the primitives, `bitflags`, and fieldless enums. `const`
    items materialize at every use — they are compile-time values, not
    owned storage, so `VirtioPci.ready` can be written to four registers
    without being "moved." This is observation, not assignment-copying, and
    it applies only to machine scalars, ever.
  - **Aggregate duplication is a call.** Plain-data types may provide
    `copy()` (auto-derivable when every field is a scalar or itself
    copy-providing); buffers provide `copyFrom`. Every copy in a Wrela
    image is therefore at an explicit call site — memory traffic is
    greppable. This is why a PollBudget cannot be silently doubled, a
    Claimed cannot be silently forked, and a 2 KiB buffer cannot be
    duplicated by an innocent-looking assignment. (Honesty note: a MOVE of
    a large inline value still costs a memcpy — with no heap there is no
    pointer to swap. Move is about ownership, not about being free; what
    the rule buys is that duplication, the cost that keeps recurring, is
    never hidden.)
- **Drop glue is structural.** A class may declare `deinit`
  (compiler-provided capabilities have one), but cleanup is not limited to
  classes that write one by hand. Every aggregate has compiler-synthesized
  field cleanup for owned fields that need it; values have no user-defined
  destructors, but values containing cleanup-bearing fields still get
  structural drop glue. On scope exit — including an early `?` return — every
  owned-but-not-consumed value is cleaned up in reverse acquisition order,
  leaving hardware in a defined safe state. A `deinit` is synchronous,
  non-failing, non-async, bounded, and may not expose `self` or mint new
  long-lived capability provenance. If cleanup traps, the target fatal path is
  responsible for reaching a DMA-safe halt/reset state.

  Construction evaluates named arguments left-to-right. On partial failure,
  initialized temporaries are cleaned up in reverse evaluation order. On a
  fully constructed aggregate, sealed provenance sources first run any declared
  pre-drop barrier while every dependent is still intact (a running
  `DeviceClaim` quiesces here). User `deinit` then runs while every field is
  initialized, followed by field glue in the compiler's provenance topological
  order (dependents before sources), using reverse declaration order only where
  the DAG leaves a choice. `deinit` may not move fields out. A provenance cycle
  or two cleanup requirements that demand contradictory order is a compile
  error. The source's final release occurs after its dependents. A running DMA
  device is never ordinarily droppable without that pre-drop barrier: its sealed
  claim must first reach a target-proven quiescent state, or cleanup enters the
  DMA-safe target-fatal path without reclaiming reachable memory.
- **`linear` is the one written ownership word.** A linear class must be
  consumed explicitly: dropping it is a compile-time error, because no
  default cleanup can be correct for it (an in-flight DMA token cannot be
  reclaimed while the device owns the memory — R8/R9). For the same reason,
  `?` is illegal while a linear value is live in the enclosing function
  (R6): an early return would strand it. Discharge or park linear values
  before propagating errors. Linearity is infectious through EVERY
  aggregate: a class field, a `type` field, or an ENUM PAYLOAD holding a
  linear value makes the whole aggregate linear — `Result[Token[T, E], E2]`
  is linear, so `discard disk.submitFlush()` is a compile error, not a
  leaked token. (Infectious enums are also what let compiler-generated
  frame enums park tokens, R10.)
  Containers of linear elements are themselves linear. Methods such as
  `clear` exist only when their element type is droppable; linear containers
  need consuming drain/discharge APIs instead of silent element drops.
- **Moved-from variables are uninitialized.** A move leaves the source
  unusable until it is assigned again. Definite-assignment is checked across
  branches and loop backedges, so patterns like the journal task's
  `sector = await BlockIo.commit(...)` are legal only because every path
  reinitializes `sector` before the next use.
  PARTIAL MOVES: moving one field out of an owned aggregate
  (`let firmware = caps.firmware`) leaves it partially moved — the moved
  field is uninitialized (tracked per field), the others stay usable, and
  the whole cannot be lent, moved, matched, or copied while any field is
  out. Drop glue runs only on still-initialized fields. An aggregate with
  an `invariant` cannot be partially moved: the invariant covers the whole.

- **Replacement assignment is two-phase.** When assigning into an initialized
  owned slot, the right-hand side is evaluated into a temporary/spare location
  first. Only after the new value exists does the old value deinitialize, and
  only then does the new value move into place. The compiler may use an
  old-first optimization only when it proves the RHS cannot observe, fail
  after, or trap after the old value is destroyed. The assignment destination
  also participates in R3 call-site disjointness.

**Fallible consume law:** if a fallible function consumes a value and has not
committed to owning or discharging it, every error path must return that value
or move it into an explicit recovery state. This is why enqueue-style APIs are
usually split into `tryReserve` followed by an infallible commit, or return a
resource-bearing error. A value must never vanish merely because a bounded queue
was full. INFALLIBLE-CONSUME ESCAPE: an API may consume without a failure path
only when a DECLARED class invariant makes the failure case unrepresentable
(the net driver's buffer-conservation invariant; the block driver's
descriptor/inflight bijection). The invariant is part of the class (R5), and
the compiler holds the API to it. English comments do not discharge this escape:
the consumed value must be accounted for by a compiler-visible invariant
predicate over storage, ghost counters, or ghost finite sets.

**Derived capabilities and provenance:** a value derived from a capability
object (`Mmio[T]` from a PCI claim via `mapBar`; DMA memory from a DMA arena
via its allocators) must not outlive its source. The compiler tracks a
provenance DAG: a source cannot be moved, released, reassigned, or deinitialized
while derived nodes exist, and derived nodes are cleaned up before their
sources. The containment rule is OWNERSHIP-TREE, not same-field: source and
derivative must be owned within one ownership tree whose cleanup order destroys
derivatives first — a derivative may live in a child object (a VirtQueue holds
DmaShared rings while the parent driver holds the arena). SEAL ADOPTION: an API
may be declared provenance-adopting — it consumes a source node and returns a
replacement that adopts all derived nodes (`sealRuntime` on claims and DMA
builders); the DAG edge moves and the derived values remain valid. Capability
APIs declare whether they mint unique, shared-readonly, or aliased views. This
is why every driver keeps its device claim and DMA provenance in storage —
dropping them at the end of a successful bind would release the very device
just configured.

**R5. Construction.** Classes have two field sections with different semantics:
`needs:` for static handles and `storage:` for owned state. Field names are
unique across both sections. `needs:` fields may name only interfaces or
runtime-safe sealed capabilities; `storage:` fields hold the object-owned values
that move, drop, and participate in invariants. `needs:` and `storage:` are both
initialized by constructors, but only `storage:` is owned memory.

Class construction is named-argument only. Positional class construction does
not exist. A class may declare one or more infallible constructors:

```
constructor fn new(net: Network, console: Console):
    return Self(
        net = net,
        console = console,
        buffer = PacketBuffer(),
    )
```

A constructor has no `self`; it is a class method that returns `Self`. It may
initialize both `needs:` and `storage:` fields through `Self(...)`, and every
field with no default must be initialized exactly once. Constructor calls use the
class-qualified name, also with named arguments only: `PacketPump.new(net =
objects.net0, console = objects.console0)`.

If a class declares no constructor, the compiler provides the structural
named-field constructor `T(...)`. `T()` is available only when every `needs:` and
`storage:` field is defaultable or absent. Fallible setup is not a constructor
protocol in V1; it is an ordinary static factory such as `bind(...) ->
Result[Self, E]`, usually used by drivers during boot.

Outside the class, named construction is available for transparent `type` values;
class storage remains encapsulated except through constructors and factory
methods.

Default construction and `zeroed` are structural predicates, even though V1
does not expose a general abilities system. A field whose type has no default
is mandatory. `zeroed` is legal only for types whose all-zero bit pattern is a
valid value. Capability objects, tokens, many enums, and invariant-bearing
classes usually have no default and are not zeroable.

An invariant must hold after successful construction, at public method entry and
exit, before lending `self` or a field outside the object, before returning a
`Ref` or `View`, before any await boundary, and before any operation that can trap, panic,
or enter the target fatal path. Private helpers may temporarily open an
invariant only inside one synchronous call tree and must close it before any of
those boundaries. While an invariant is open, every operation in the open region
must have a compiler-visible `no_trap` summary or a local proof that its bounds,
arithmetic, register conversion, and guard predicates cannot fail.

A no-return target-fatal transition is the sole exception to the requirement to
re-close an already violated invariant. It is legal only with a compiler-visible
proof that the target-fatal path does not resume Wrela or reclaim memory still
reachable by a device. Ordinary panic, error return, or cleanup is not such an
exception.

V1 invariants are a small decidable DSL, not arbitrary logic. They may quantify
only over statically bounded containers, descriptor-state tables, token registry
slots, initialized storage ranges, and finite ghost sets/counters owned by the
class. They may state equality, membership, disjointness, cardinality, bounded
integer relations, and ownership conservation. They may not call user functions,
perform unbounded quantification, or depend on target state. Guard functions use
the same refinement language for their postconditions.
The fixed builtin vocabulary includes `initialized`, `length`, `keys`,
`cardinality`, `disjoint`, `owns`, `owners`, bounded/circular ranges, and
`isPowerOfTwo`; target/ABI packages may add only certificate-defined sealed
summary projections such as queue/registry key sets.

An invariant may mention only the class's own fields, ghost state, and sealed
summary projections exported by owned child objects. It may not mention a
sibling, a parameter, another object's private field, or mutable target state.
Relationships that must change atomically across a queue, inflight table, and
registry must be owned by one transaction object or represented by a linear
reservation token. Public calls never temporarily open invariants in two
independent objects. Ghost updates occur in the same transaction as their
concrete state change and are erased only after verification.

### Errors

**R6. Error discharge.** `expr?` requires the enclosing function to return a
compatible `Result`. On `err`, `?` widens the inner error into the outer
error type through the outer enum's `widen` variant for that payload type
(declared inline on the variant; two `widen` variants with the same payload
type are a compile-time error):

```
enum BindError:
    badQueueSize
    widen pci(PciError)      # `?` lifts PciError into BindError via .pci
    widen dma(DmaError)
```

`expr?` is itself a compile-time error at any point where a linear value
(R4) is live: an early return cannot strand an in-flight operation.
Using `?` on a linear `Result` is still legal when the `Result` itself is the
value being consumed and no other linear obligation is live: the `Result` is
matched first, the error path contains no success payload, and the success
payload is immediately bound, returned, or otherwise discharged.

A function returning `Never` cannot use `?`; it discharges each `Result`
explicitly with `.orPanic(panic, msg)` (fatal) or `.orLog(console)`
(best-effort), or by matching. `discard expr` is the explicit spelling for
intentionally ignoring a value, used only when failure is known to be
non-actionable; it never applies to a linear value or to any aggregate
containing one (R4). Every task entry returns `Never` (R11), so all top-level
code lives under this discipline: no error is dropped silently, ever.

### Interfaces and the reduction

**R7. Interfaces: contracts, monomorphized and erased.** An `interface` is
a compile-time contract, not a runtime value. Conformance is nominal: a
class lists the interfaces it implements (`class VirtioNet implements
Network, Pollable`), and conformance is checked wherever a concrete object
is bound to an interface-constrained parameter. An interface type may
appear only as a generic bound (`where T is Network`) or as a parameter
type, which is sugar for an anonymous bounded generic: `fn f(net: Network)`
means `fn f[N is Network](net: N)`. Interface types cannot be stored,
returned, or constructed — nothing interface-typed exists at runtime.

Kernel code is therefore written against contracts and MONOMORPHIZED at the
reduction point, when the image's `executor fn` constructs task objects from
concrete image-static runtime objects. A task object's `needs:` field is a
static handle (R2): it may live across awaits, but every method call through it
creates a short synchronous activation. Because the binding is known at compile
time, it erases to a direct static address. Schedulable task `needs:` may name
only layer-approved interfaces or runtime-safe sealed capabilities. Wiring a
concrete lower-layer driver class directly into a higher-layer task's `needs:`
is a compile-time error unless the task is explicitly marked as trusted
same-layer runtime code; the normal kernel/service surface is the interface, not
the driver object.
There is no dynamic dispatch anywhere in a Wrela image — not merely "no vtable
the source can name," but no vtables at all. Shared bindings cannot violate R3:
interface methods are synchronous, an activation begins and ends inside one
resume (R10/R11), so two activations of one object can never overlap. One
consequence, accepted deliberately: user code cannot build heterogeneous
interface-typed collections; the generated executor iterates the runtime
objects by unrolling over the record's known fields — compiler output, not
language surface.

Generic bodies are fully checked at monomorphization. Because an image is a
closed world with no separate compilation, monomorphization-time errors ARE
ordinary compile errors — so conditional methods like `Ref.copy` (R4) cost
no extra machinery, and there is no C++-style "surprise in someone else's
build."

The type-level language is deliberately finite. Recursive type definitions,
type-level loops, unbounded const evaluation, and cyclic associated-const
dependencies are compile errors. The compiler emits a deterministic diagnostic
if specialization exceeds the target's instantiation limit. Associated consts
participate in type equality only when they come from the same concrete binding
or from an explicit equality proof in the generic constraints; otherwise
`Bytes[d1.blockSize]` and `Bytes[d2.blockSize]` are different types even if both
happen to be 512 after specialization.

### Devices

**R8. Device memory.** A device is a concurrent actor; the only memory it
may reach is DMA memory, and DMA memory comes in exactly two kinds:

- **transferable** — payload buffers (`DmaBuffer`). Ordinary owned memory
  while held: lend it, view it, fill it. The ONLY way the device sees one is
  consuming it into a submit, and the only way back is a completion. CPU
  access to in-flight memory is unrepresentable: you do not hold the value.
- **shared** — control structures the device watches forever (`DmaShared`:
  virtqueue rings and their cousins). Never CPU-owned memory: no lends, no
  Views, no plain loads. Access is typed, volatile, and field-wise through a
  `registers`-declared layout, exactly like `Mmio` — the same discipline for
  the same reason: a concurrent reader/writer on the other side. Reads
  through shared layouts are ordered according to the target's DMA coherence
  contract: acquire/release fences on coherent targets, and cache
  clean/invalidate or bounce-buffer operations where required. Volatility
  prevents elision; target-checked alignment and atomicity prevent torn reads.

Loans never cross the device boundary: loaned or CPU-owned data passed to a
device API is copied into DMA memory, and the copy is the documented, visible
cost. Wrela never lets a device observe memory the type system still considers
CPU-owned. The preferred driver APIs build descriptors from live DMA objects
without exposing raw bus addresses; if a target exposes a `DmaAddress`-like
value, it is sealed, provenance-bearing, non-arithmetic, and scoped to the
source DMA object/domain.

This is enforced at the final write site, not by convention. A register or
shared-DMA field capable of changing device reachability is `sealed_write`, and
its helper accepts only live `DmaBuffer`, `DmaShared`, or sealed `DmaAddress`
provenance. It cannot accept `U64`, cast a scalar into an address, or publish a
range beyond the source object. Ordinary `DmaShared.write` cannot name address
or publication fields. A driver bug may choose the wrong live buffer, but it
cannot program an arbitrary bus address through the safe language surface.

DMA element types satisfy `dma_plain`. Device-writable completions remain
foreign-derived, including after being copied into owned CPU storage. Padding is
forbidden, every byte exposed to a device is initialized, and conversion into a
closed enum, invariant-bearing value, length, index, or ownership decision goes
through a total guard. Direction is part of every descriptor proof: a device
cannot receive write permission to a driver-readable-only object.

THE PUBLICATION CONTRACT: a sealed descriptor lowering is atomic within its
synchronous call — (1) payload bytes any device-read operation needs are
copied into device-owned staging BEFORE the descriptor becomes device-visible;
(2) the ring-index advance is the publication point, and everything the
descriptor references must be device-owned by then; (3) caller loans end
inside the call, before publication, so no loan ever crosses. A disk READ
takes no payload loan at all — it has no source bytes; its data copies out at
completion.

Device-written memory is **register-safe, not protocol-safe**. A volatile read
from MMIO or shared DMA proves only width, alignment, ordering, and reserved-bit
handling. It does not prove a descriptor index is in range, a length is
reasonable, an enum is known, or an aggregate invariant holds. Driver code must
convert raw device-written fields into protocol-safe types through explicit,
total guards before those values can index, select ownership state, redeem a
token, or influence a trapping operation.

**Driver/device trust boundary:** certified sealed fields prevent source driver
code from programming an address outside the live provenance it possesses, so
a source bug cannot simply cast another driver's memory into a descriptor.
Driver protocol logic is still trusted for functional correctness. Independent
containment of hardware that ignores descriptors, a compromised target/ABI
package, or a physically malicious bus master requires an IOMMU/vIOMMU domain;
source provenance is not a substitute for hardware isolation.

**R9. Completion tokens.** Every runtime device operation is split-transaction:
`submit*` hands the request (and any buffer, by consume) to the driver and
returns a `Token[T, E]` — a linear (R4) receipt that will yield an
operation-specific result when redeemed. Progress happens in the driver's
`poll`; redemption is `token.tryComplete()`, which consumes the token and
either returns `done(result)` or hands the still-live token back as
`pending(token)`. Redemption routes internally to the issuing driver, so
redeeming against the wrong device is unrepresentable. Because tokens are
linear, an in-flight operation can be neither forgotten nor redeemed twice, and
a buffer given to the device provably cannot be touched until it is handed back
or explicitly moved into quarantine/reset recovery.

Token identity is not just a user-visible integer. Internally it includes the
issuing driver, queue/source, slot, generation, operation kind, and reset epoch.
Minting a token registers it in an executor-visible driver table; redemption,
abandonment, and reset transition that table. Mint/complete hooks are generated
for ANY class that implements a token-minting contract, on any target — a
RAM-backed mock BlockDevice mints real tokens. Sealing guards the mechanism
(no forgery, registry bookkeeping), never the privilege.

Generation and reset-epoch values are sealed, source-branded, and increment
without wrapping. Exhaustion enters target fatal before a value is reused. These
values prevent accidental ABA only when the transport returns or otherwise
authenticates them. If hardware returns only a slot number, a late duplicate
after slot reuse is indistinguishable from the current completion; the target's
protocol-compliance certificate is therefore an explicit premise for that
transport, not a fact the guard pretends to prove.

A token-minting submit is one checked transaction, even if the source spelling is
several method calls: reserve queue capacity, reserve inflight ownership, create
a pending-unpublished registry entry, publish the descriptor, notify the device,
and return the token. Failure before publication rolls back and returns every
consumed resource; failure after publication must leave a registered obligation
that completion, abandon, reset, or target fatal can discharge. A descriptor may
not become device-visible before the registry has a canonical owner for every
resource the device can later complete.

Awaitables come in exactly two kinds:

- `Token[T, E]` — linear; must be awaited, tryCompleted, abandoned, or
  parked.
- `Wait` — droppable; a sealed awaitable carrying source identity plus a
  readiness predicate or deadline. Dropping a Wait abandons nothing and either
  unregisters bounded executor state or drops a value whose registration is
  derived from the parked frame. Wait completion is LEVEL-TRIGGERED: the
  predicate is evaluated when the Wait is armed and re-evaluated on every
  executor pass, so a Wait whose predicate already holds completes immediately
  — a task awaiting an already-ready source is runnable, not asleep, and the
  executor will not sleep past it. Deadline Waits complete by the target
  clock's wrap-safe deadline predicate, not by open-coded integer comparison.
  Waiter bookkeeping is bounded by the sum of simultaneously armed Wait slots
  over every reachable async/select frame variant, not merely by task count.

**Hung devices.** A token whose device never completes is recovered at the
device level, never per-request: hardware has no reliable per-request abort,
and reclaiming a buffer the device might still write would break R8. The two
primitives are ABANDON (`token.tryAbandon(recovery)` — gated by the sealed
`Recovery` capability; the issuing driver moves the buffer into a bounded
quarantine budget) and RESET (a target-proven reset reaches a declared
quiescence condition, advances the reset epoch, fails every in-flight token, and
reclaims every buffer). Operation types declare late-side-effect semantics:
side-effect-free, idempotent, may-still-happen, or
requires-reset-before-continuing. Fatal escalation is always a target-defined
DMA-safe reset or halt,
not merely falling off the source cleanup path.

ABANDON consumes one bounded quarantine slot. The general
`token.tryAbandon(recovery)` returns either `abandoned` or `full(token)`,
preserving the still-live token. An infallible `abandonProven` surface exists
only when the compiler proves a bound on the TOTAL unreclaimed quarantine
population across all loop iterations and tasks, not merely the number of
user-visible tokens live at once. Reset returns all quarantine slots only after
target-proven quiescence. If neither a dynamic slot nor a total proof exists,
abandonment is unavailable and the image must use device reset/watchdog
escalation or target fatal. Late-side-effect semantics are part of the public result shape:
an operation whose write or flush may still happen after an error must expose
that uncertainty in its token alias or error payload, not hide it in driver
comments.

### Concurrency

**R10. Suspension.** An `async fn` compiles to a compiler-private frame with
enum-like variants for suspension points and fields for locals alive at each
one. It is ordinary for layout and budget accounting, but user code cannot
construct, match, or forge frame states. `await` does not wait; it compiles to a
RETURN — store the live locals into the frame, mark the variant, and return
`pending` to the caller. Resumption re-enters at the marked variant.
Consequences, each load-bearing:

- No loan may be live across an await point. Everything crossing a suspension
  is owned or is an image-static handle and is stored in the frame. (This is
  what makes frames plain movable values — no self-reference, no pinning.)
- Frame sizes are computed at compile time and charged to the image's static
  demand. (Recursion is banned image-wide by R17; for async fns it would
  additionally make frames unbounded.)
- `await` grounds out in exactly two primitives: awaiting a Token (park; on
  resume, `token.tryComplete()`, which routes to the issuing driver) and
  awaiting a Wait. Awaiting a nested async fn embeds the callee's frame in
  the caller's and propagates `pending` outward as ordinary returns.
- `async` is permitted only in kernel- and service-layer code. Shared runtime
  object activations are synchronous and may not cross an await. A scheduled task
  object is different: `schedule` consumes a freshly constructed kernel object
  into the compiler-generated task frame, so its `storage:` and `needs:` live
  with that one task. Private async methods on the same task class are lowered as
  nested task-frame states over that owned task object, not as shared object
  activations. Driver `poll` and all driver methods are synchronous: drivers are
  the ground truth that advances hardware, and they complete within one bounded
  call.

V1 has no first-class futures in source. Async frames exist only as
compiler-generated task frames and immediately awaited nested async frames
embedded in their callers. User code cannot store, return, construct, match, or
traffic in an async frame value.

**R11. Tasks.** The image's `executor fn execute(objects: RuntimeObjects)`
declares a fixed set of tasks by calling `schedule` on constructed task objects;
there is no dynamic spawn. A task entry is an `async fn ... -> Never` method on a
`kernel class`, usually `run(consume self)`, where `consume self` moves the task
object into its statically sized frame. Every task is an infinite loop, so "run
to completion" means "run forever" and R6 governs all of its error handling. A
task's persistent state is its `storage:` plus locals live at suspension points.
Tasks share image-static runtime objects only through `needs:` static handles
typed by interfaces or runtime-safe sealed capabilities (R7).

**The interleaving theorem:** tasks interleave only at await points; no loan
spans an await (R10); therefore no loan — including an activation — held by
one task can be observed by another, and the single-call-tree aliasing story
of R3 holds for the whole system.

**R12. The executor and waiting.** The generated executor owns the one true
loop: resume runnable tasks, poll driver/event sources under compiler-checked
bounded-work rules, and when everything is parked and the rings are dry, sleep
(R13). It polls exactly the fields of the image's runtime object record —
boot's return — that implement executor source interfaces such as `Pollable` or
`DoorbellSource`. An `executor interface` is a normal erased interface for
conformance checking, but with generated-executor-only call visibility: driver
classes may implement it, while user code may not name it as a parameter,
storage field, or callable surface. A runtime object that mints a `Token` or
readiness `Wait` must expose the corresponding executor source; the set is
derived, never listed, so a driver cannot be forgotten.

The `executor fn` is a wiring function, not the event loop and not a runtime
capability. It may construct task objects with named arguments and call
`schedule task.run()`, but it may not await, branch on runtime device state, loop
over runtime data, or be called by user code. The compiler evaluates its fixed
schedule graph when building the generated executor. User code cannot run the
loop: there is no block_on and no executor capability. The only way to wait is
`await`, which unwinds the stack to the executor (R10), so "block the loop from
inside the loop" has no spelling.
(A user-callable loop entry would resume other tasks while the caller's
loans are live and its frames occupy the single runtime stack — breaking
R11's interleaving theorem and the stack budget. That is why none exists.)
R18 is the companion liveness rule: a task resume must eventually return to
this generated loop, either by reaching an await or by finishing a
statically bounded amount of synchronous work before an await.

Executor-source effects carry the canonical issuing object through forwarding
wrappers. A top-level runtime field that exposes a nested token or Wait source
must either implement a sealed delegating executor-source contract or expose the
actual fixed child source to generated wiring. Merely forwarding a token does
not hide its poll/reset/doorbell dependency, so nesting cannot recreate the
forget-to-poll bug.

`select` is LINEAR SELECT: all arms are evaluated into the select frame, the
frame owns the armed awaitables while parked, the first completion wins and is
the only thing consumed, losing Waits drop, and losing tokens move back into
visible locals before the winning arm or post-select continuation runs. A
timeout never cancels I/O; it only observes slowness. There is no way to cancel
a task and no silent cancellation at await points; the entire
cancelled-mid-operation bug class does not exist.

**R13. Doorbells and target entries.** Wrela has no user interrupt handlers.
While Wrela code runs, device interrupts are masked. When the executor finds no
work, it executes the generated target idle sequence:

1. arm per-queue wakeup thresholds (virtio EVENT_IDX) and the timer,
2. RE-CHECK the used rings (the lost-wakeup guard),
3. `sti; hlt` (atomic on x86: a pending doorbell ends the hlt).

The interrupt "handler" is generated target code whose only source-visible
effect is that the CPU is awake and Wrela resumes with interrupts masked again.
No Wrela object is ever entered from interrupt context, so R2/R3/R10 are
unaffected by the existence of interrupts. Because the image's hardware
contract is static, the doorbell wiring (for example MSI-X vectors per queue)
is computed at image build time; there is no runtime interrupt registration of
any kind. The target contract must also either disable, exclude, or fatalize
NMIs, SMIs, machine checks, debug traps, unexpected interrupts, extra devices,
SMP application processors, unbounded MMIO, and any other asynchronous CPU
entry outside the generated doorbell/fault paths.

### Lexicon

**R14. Iteration and matching.** `for x in c:` lends value elements read-only.
Generic value containers do not implicitly activate owned object elements;
object-owning containers expose explicit `activate`, `take`, or `replace`
methods whose disjointness and container-invariant obligations are checked.
`for consume x in ownedContainer:` is the consuming-drain form: it owns the
container, moves each element exactly once, and structurally cleans up any
unvisited droppable elements on an early exit; it is unavailable when that
cleanup would strand a linear element.
The container itself is loaned for the duration of the loop, so
`await` inside a `for` body is already illegal by R10; no extra rule needed.
`match` on a LOANED enum lends: payload bindings are read loans of the
payloads, valid for the arm body, with the whole enum frozen (R3). Moving a
payload out requires matching an OWNED enum — which is why `orPanic` takes
`consume self`. `for i in a..b:` iterates a scalar range; a range is a value,
and the loop is R18-bounded whenever its bounds are.

**R15. Conveniences.**

The V1 language package includes a versioned EBNF grammar and a deterministic
name-resolution/type-inference specification; the examples in these documents
are explanatory renderings of that grammar. Expressions and arguments evaluate
left-to-right, `and`/`or` short-circuit, `match` is exhaustive, and integer
literals are contextual only while their exact value fits the selected type.
There are no implicit narrowing, signedness, enum/integer, or float/integer
conversions. Ambiguous overload or generic inference is a compile error.

- Within a class body, unqualified names resolve to self's `needs:`, `storage:`,
  and methods.
- Methods are public by default. `private fn` and `private async fn` are visible
  only inside the declaring class; they are not callable through interfaces,
  image wiring, or generated executor surfaces.
- **Phase and layer defaults:** the layer is declared once, on the class
  (`driver class VirtioNet`, `kernel class BlockIo`); methods inherit it.
  Runtime-layer free functions are not part of V1. A schedulable task entry is
  an async method on a `kernel class`, scheduled by the image's `executor fn`;
  helper logic is an ordinary method on a layer-marked class, usually private.
  Stateless helpers use static methods (the VirtioPci and BlockIo idiom); shared
  task state uses instance methods over owned task objects. Capability classes
  and interfaces carry no layer. Layer names remain dependency/review
  structure, but capability EFFECTS are enforced transitively: an interface
  exposed to kernel or service code may not hide MMIO, DMA-address, reset,
  recovery, or other effects forbidden to that layer. Wrapper methods inherit
  the effects of everything they call, and implementations must fit the
  interface's declared effect ceiling. The phase defaults to `runtime`,
  which is therefore NEVER WRITTEN: only `boot` and `fault` code is marked, and
  interfaces are runtime by definition (R7). Most declarations carry at most one
  annotation. Sealed capability classes may be NAMED in
  a layer's signatures and storage only per that layer's vocabulary rows
  (image-runtime.md) — kernel code can name Clock and PanicSink but never
  Mmio or DmaShared. Naming is cheap to check; possession still flows only
  by wiring.
- `ok x` and `err e` are construction sugar for `.ok(x)` / `.err(e)` on an
  inferred Result type — sugar, not magic; Result stays an ordinary stdlib
  enum.
- Unit literals like `4.MiB`, `512.KiB`, `1.ms`, `1.s` are calls to const
  helper methods on integer literals.
- Generics are bounded by interfaces and nothing else. Structural predicates
  such as linear, needs-drop, defaultable, zeroable, droppable, foreign-derived,
  wire_plain, register_safe, dma_plain, unsigned_scalar,
  certified_mmio_layout, and provenance-bearing are
  compiler-computed facts: they may be REQUIRED in
  `where` clauses (`where T is droppable`) but cannot be user-defined,
  implemented, or extended in V1.

**R16. Arithmetic and bounds.** Integer arithmetic TRAPS on overflow, and a
trap is a panic (R6's fault philosophy: with no demand paging and no heap, an
arithmetic surprise is a bug). Explicit wrapping (`+%`, `-%`, `*%`) and
saturating (`+|`, `-|`) operators exist for intentional cases. Division by zero
and shifts past the width trap.

Indexing and slicing are CHECKED. Container accessors return `Result`.
`view[..n]` traps only when `n` is statically trusted or already proven in
bounds; slicing with foreign-derived or otherwise unproven bounds returns
`Result[View[T], BoundsError]`. The same bounds regime governs Slice
projection, re-projection, and split. `parse ... guard` is total and
non-trapping over a `View[U8]`; guards over foreign data are total and bounded,
and values derived from foreign bytes cannot feed trapping arithmetic or
slicing until guarded.

A guard is not an arbitrary boolean helper. A total guard declaration attaches
refinements to the values it checks: bounds (`len <= 1514`), enum membership,
checksum validity, descriptor state, token identity, initialized ranges, and
similar facts from the invariant DSL. A plain `Bool` result never clears
foreign-derived taint unless its function signature declares the refinement and
the compiler verifies the function body against it.

`orTargetFatal(msg)` on Result/Option is the explicit trap spelling for
corruption with no continuation (a stale device completion, a broken paired
invariant): it yields the success value or enters the target fatal path. It
belongs to this trap family and is available only to driver, boot, fault, and
generated-executor code. Kernel and service code require an explicitly wired
`PanicSink`; there is no ambient fatal spelling in those layers. The
compiler tracks `target_fatal` as an effect so fatal paths are visible in the
proof and review artifacts.

Foreign provenance is flow-sensitive and transitive. Arithmetic, copying,
container insertion, return, and aggregate construction preserve it. A guard
clears only the named refinements in its verified postcondition; unrelated
fields remain foreign-derived. Control dependence does not launder a value, and
a helper lacking a declared verified refinement can never clear provenance.

**R17. The call graph is acyclic.** Recursion — direct or mutual, sync or
async — is a compile-time error. Wrela has no function pointers and no dynamic
dispatch (R7), so the whole-image call graph is static; generated token
redemption edges, deinit edges, executor hooks, doorbell hooks, panic paths,
and fault paths are included. With cycles banned, the compiler computes the
true worst-case stack depth of boot and of every task resume. Bounded
containers make bounded iteration the replacement idiom. Memory demand includes
the lowered evaluation order's peak temporaries: in-place return slots,
replacement-assignment spares, nested async callee frames, select frames, deinit
temporaries, parse projections/copies, sealed-helper staging, and every
compiler-generated registry object. Object and frame sizes alone are not enough.

V1 source has no FFI, inline assembly, foreign object linkage, function-address
imports, post-link patching, user compiler intrinsics, or unverified linker
scripts. Target startup/fault code and ABI helpers are sealed, hash-bound target
package inputs. Adding any foreign-code surface requires extending the theorem
and final-code verifier first.

**R18. Runtime liveness.** Every control-flow cycle reachable during a runtime
entry — task resume, driver `poll`, driver interface method, executor-only hook,
or `deinit` — must be either await-yielding where awaits are legal or
statically bounded:

- **Await-yielding:** every path around the cycle crosses an `await`, so the
  task returns to the generated executor before continuing.
- **Statically bounded:** the compiler proves a finite upper bound from a
  const range, bounded container capacity, or a decreasing variant over a
  bounded integer. The bounded work is charged to the task's resume budget.

Finite is not sufficient: the computed worst-case cost of every poll slice,
task resume, deinit, watchdog scan, and reset step must fit a target-certified
numeric budget. A `U64`-decreasing loop with an astronomical bound is rejected.
Watchdog/fatal work has a reserved budget that ordinary polling cannot consume.

Unbounded non-yielding cycles are compile errors: `loop: pass`, an unbounded
packet-drain loop, or a synchronous helper that can spin forever cannot appear
on a runtime path. The common idiom is to drain a bounded batch, then await
readiness. Await-yielding loops still obey executor fairness: a task that yields
is not resumed again in the same pass unless the generated executor's bounded
fairness rules allow it. Zero-duration waits are either rejected or rounded to a
yield-to-next-pass wait by the target clock.

## Core primitive types

Integer widths are exact; `USize`/`ISize` equal the certified target address
width but are never addresses. `Bool` has only `false` and `true` and is not
`wire_plain`/`register_safe` without an ABI encoding. Enum discriminant size is
explicit or compiler-private and therefore never inferred at a foreign boundary.
ASCII byte literals such as `b'\n'` have type `U8`; character/string encoding is
otherwise outside V1.

```
primitive type Bool
primitive type U8      primitive type I8
primitive type U16     primitive type I16
primitive type U32     primitive type I32
primitive type U64     primitive type I64
primitive type USize   primitive type ISize

# Floating point is off by default in V1 targets. A target may opt in only by
# declaring FP/SIMD save-restore across awaits, deterministic exception modes,
# and disabled-FPU fault behavior; otherwise F32/F64 are rejected in runtime
# code.
primitive type F32
primitive type F64

primitive type Never
primitive type Duration      # non-negative and <= target's unambiguous clock
                             # window; const construction outside it is rejected
primitive type Instant       # opaque monotonic clock tick; deadline comparison
                             # is target-provided and wrap-safe
primitive type StaticString

type Byte = U8

# String literals and StaticString storage live in immutable image-static
# memory. StaticString.bytes() returns a View whose source is that static
# region; it may be passed down the current call tree like any other View, but
# it is still not storable unless a distinct StaticBytesView-like type says so.
```

## The standard library

Option and Result are ordinary stdlib enums. The compiler may optimize their
layout, but their behavior is not a hidden runtime service.

```
enum Option[T]:
    none
    some(value: T)

    fn orTargetFatal(consume self, message: StaticString) -> T   # R16 trap


enum Result[T, E]:
    ok(value: T)
    err(error: E)

    # How Never-returning functions discharge a Result (R6). Ordinary
    # methods, not compiler magic.
    fn orPanic(consume self, panic: PanicSink, message: StaticString) -> T:
        match self:
            .ok(value):
                return value
            .err(_):
                panic.panic(message)

    fn orLog(consume self, console: Console) -> Option[T] where E is droppable:
        match self:
            .ok(value):
                return .some(value)
            .err(_):
                discard console.writeLine("operation failed")
                return .none

    # The explicit trap for corruption with no continuation (R16): success
    # value or target fatal path. A trap, not a panic capability.
    fn orTargetFatal(consume self, message: StaticString) -> T


enum CapacityError:
    full

enum BoundsError:
    outOfBounds

enum EmitError:
    destinationTooSmall
    refinementFailed

enum PushError[T]:
    full(value: T)

enum SetError[T]:
    outOfBounds(value: T)

enum SplitError[T]:
    outOfBounds(slice: Slice[T])
```

Capacity errors come in two flavors on purpose: `PushError[T]` returns the
rejected value (the fallible-consume law, R4) for APIs that consume, while
`CapacityError` serves copy-in APIs like `VarBytes.append`, where nothing was
consumed and nothing needs returning.

`Storage[T, N]` is the one sharp primitive under the bounded containers: it
reserves memory for up to N values of T without constructing them. The stdlib
owns the invariant for each container (List: slots `0..len-1` initialized;
Ring: occupied slots initialized; Array: every slot initialized). Normal user
code cannot reach Storage at all: it is sealed in the intrinsic prelude and not
exported from the stdlib module.

```
class Storage[T, const N: USize]:
    # Intentionally sharp; containers check bounds and initialization
    # invariants before calling these.
    fn writeUninit(self, index: USize, consume value: T)
    fn replaceInit(self, index: USize, consume value: T) -> T
    fn readMoveInit(self, index: USize) -> T
    fn refInit(self, index: USize) -> Ref[T]
    fn dropInit(self, index: USize)


# Exactly N initialized elements, with transparent value semantics. Usually
# inferred from literals:
#   [1, 2, 3]      Array[I32, 3]
#   [0_u8; 4096]   Array[U8, 4096]
#   [0..100]       Array[I32, 100]      (half-open)
#   [0..=100]      Array[I32, 101]      (inclusive)
type Array[T, const N: USize]:
    private items: Storage[T, N]

    invariant: initialized(items) == 0..N

    const length: USize = N

    fn get(self, index: USize) -> Result[Ref[T], BoundsError]

    # Array is the value/read-only aggregate. Lending it is read-only because it
    # is a value (R2). Mutation happens through owning containers, Slice
    # projections, or stdlib internals that own the backing Storage. If T is an
    # object, get still returns a read loan of the element; it does not activate
    # the object. Object-owning indexed collections use specialized containers
    # that expose explicit element activation or move-out/replacement APIs with
    # R3 disjointness checks.


# Up to N initialized elements: the bounded "list" shape without a heap.
# Constructed as List[T, N](): len zero-defaults (R5). [] desugars to this
# when the expected type is a List.
class List[T, const N: USize]:
    storage:
        len: USize
        items: Storage[T, N]

    invariant:
        len <= N
        initialized(items) == 0..len

    fn length(self) -> USize
    fn capacity(self) -> USize

    fn push(self, consume value: T) -> Result[(), PushError[T]]:
        if len == N:
            return err .full(value)
        items.writeUninit(len, value)
        len += 1
        return ok ()

    fn pop(self) -> Option[T]:
        if len == 0:
            return .none
        len -= 1
        return .some(items.readMoveInit(len))

    # Owning an element is get(i)?.copy() -- the copy said out loud (R4) --
    # or pop() to move it out.
    fn get(self, index: USize) -> Result[Ref[T], BoundsError]:
        if index >= len:
            return err .outOfBounds
        return ok items.refInit(index)

    fn clear(self) where T is droppable:
        while len > 0:
            len -= 1
            items.dropInit(len)


# Bounded circular queue. Drivers use this heavily.
class Ring[T, const N: USize]:
    storage:
        head: USize
        len: USize
        items: Storage[T, N]

    invariant:
        N > 0
        head < N
        len <= N
        initialized(items) == circularRange(head, len, N)

    fn length(self) -> USize
    fn capacity(self) -> USize

    # Const-proven convenience for scalar rings. Construction is available
    # only when 0 <= end-start <= N and every element converts to T.
    fn fromRange(start: USize, end: USize) -> Self where T is unsigned_scalar

    fn push(self, consume value: T) -> Result[(), PushError[T]]:
        if len == N:
            return err .full(value)
        items.writeUninit((head +% len) % N, value)
        len += 1
        return ok ()

    fn pop(self) -> Option[T]:
        if len == 0:
            return .none
        let value = items.readMoveInit(head)
        head = (head + 1) % N
        len -= 1
        return .some(value)

    fn clear(self) where T is droppable:
        while len > 0:
            len -= 1
            items.dropInit((head +% len) % N)
        head = 0


# Exactly N bytes.
class Bytes[const N: USize]:
    storage:
        data: Array[U8, N]

    const length: USize = N

    fn fill(self, value: U8)
    fn copyFrom(self, source: View[U8]) -> Result[(), BoundsError]
    fn view(self) -> View[U8]         # the look loan (R3)
    fn slice(self) -> Slice[U8]       # the edit loan (R3); sub-ranges via [a..b]


# Variable-length bytes with a compile-time maximum; spellable as Bytes[..N].
class VarBytes[const N: USize]:
    storage:
        bytes: List[U8, N]

    fn length(self) -> USize
    fn capacity(self) -> USize
    fn append(self, source: View[U8]) -> Result[(), CapacityError]
    fn clear(self)


type Bytes[..N] = VarBytes[N]


# A single-value read loan projected from a container slot. Ref and View obey
# the same non-escape/freeze rule, but their shapes are not conflated.
class Ref[T]:
    fn copy(self) -> T        # exists iff T provides explicit copy


# A sequence read loan projected from a buffer (`buffer[..n]`). Passable down
# the synchronous call tree; never stored or held across await/device boundaries.
class View[T]:
    fn length(self) -> USize
    fn get(self, index: USize) -> Result[Ref[T], BoundsError]
    # Slicing sugar: view[..n], view[a..b]. Projections of projections are
    # still projections of the original source.


# A parse-produced byte projection with a static maximum. It behaves like a
# View[U8] for lending and slicing, but carries a refinement that length <= N
# and that the source bytes are foreign-derived until guards discharge them.
class WireView[const N: USize]:
    fn view(self) -> View[U8]
    fn length(self) -> USize


# The exclusive read-write reified loan (R3): View's dual — View is look,
# Slice is edit. Projected from an exclusively held object
# (`buffer.slice()`, `packet.build(n)`); same law as every loan: never
# stored, never returned past its source, never across an await or the
# device boundary. While a Slice lives, its source is exclusively loaned;
# projecting a View FROM a Slice freezes the Slice for the View's lifetime.
class Slice[T]:
    fn length(self) -> USize
    fn fill(self, value: T) where T is scalar
    # Copies source into destination prefix [0..source.length], leaving the
    # remainder unchanged; errors before modification when source is too long.
    fn copyFrom(self, source: View[T]) -> Result[(), BoundsError]
    fn set(self, index: USize, consume value: T) -> Result[T, SetError[T]]
    fn view(self) -> View[T]          # freezes this Slice while live

    # Consuming split: the parent ceases to exist, so the two children are
    # disjoint by construction — no aliasing check, no blessed primitive,
    # just move semantics (R4). This is split_at_mut for free.
    fn split(consume self, mid: USize) -> Result[(Slice[T], Slice[T]), SplitError[T]]
    # Re-projection sugar: slice[a..b] (exclusive, nested via R3).


# Bounded formatting — the whole V1 text story: StaticString for literals,
# Slice[U8] for composition. No string type, no allocation; digits and labels
# go straight into an edit loan, the return is bytes written, and a too-small
# destination is an error, never a silent truncation. Static methods of a
# class: classes are the namespacing idiom, and free helper functions are
# not a thing (R15). Signed and other-width overloads are ordinary methods,
# elided.
class Fmt:
    fn decimal(value: U64, out: Slice[U8]) -> Result[USize, BoundsError]
    fn hex(value: U64, out: Slice[U8]) -> Result[USize, BoundsError]
    fn labeled(label: StaticString, value: U64, out: Slice[U8]) -> Result[USize, BoundsError]
```

## Awaitables

```
# A linear receipt for one submitted device operation (R9). No public
# constructor: tokens are minted by driver queues and record their issuing
# driver/source/slot/generation/operation/reset epoch internally -- source code
# never names the linkage.
linear class Token[T, E]:
    # Consumes the token and either yields the operation result or hands the
    # token back still-live. Routed to the issuing driver; redeeming against
    # the wrong device is unrepresentable. `await token` desugars to this (R10).
    fn tryComplete(consume self) -> Completion[T, E]

    # Hung-device recovery (R9), gated by the Recovery capability: the
    # issuing driver moves owned resources into a bounded quarantine/reset
    # state. The general form can report a full quarantine without losing the
    # token. abandonProven is generated only from a total-population proof.
    fn tryAbandon(consume self, recovery: Recovery) -> Abandonment[T, E]
    fn abandonProven(consume self, recovery: Recovery)

    fn id(self) -> U64
    # id is diagnostic only, may be reused after the obligation is gone, and is
    # never consulted for redemption, equality, or authority.


# A droppable awaitable carrying no result and owning no caller memory: timer
# expiry, rx readiness. It carries sealed source identity plus a deadline or
# readiness predicate. Dropping a Wait abandons nothing (R9).
class Wait


# What tryComplete returns: either the operation result, or your token back.
# The linear token makes "is it done?" an exchange, never a peek -- you always
# hold exactly one of {token, result}.
enum Completion[T, E]:
    pending(token: Token[T, E])
    done(result: Result[T, E])

enum Abandonment[T, E]:
    abandoned
    full(token: Token[T, E])
```

**Linear select (R12).** A `select` block awaits several awaitables at once
and runs the arm of whichever completes first. The full semantics, in nine
rules:

1. A `select` has two or more arms of the form `pattern = await expr: body`.
2. Every arm's `expr` is evaluated, and its awaitable armed, before the
   select parks — top to bottom, exactly once. There is no lazy arming: you
   cannot race what is not armed. An arming expression may only move a named
   Token or create a sealed Wait; it may not submit I/O, mutate unrelated
   state, panic, trap, or target-fatal. Wait construction is infallible. If a
   compiler-generated arming hook cannot finish, already armed Waits are
   unregistered and named Tokens are restored before target escalation.
3. The select parks until an armed awaitable completes. The first completion
   wins; on simultaneous completions, the top-most arm wins.
4. Only the winner is consumed. Its result binds to the arm's pattern and
   that arm's body runs. No other body runs.
5. A losing `Wait` is dropped — Waits are droppable (R9) and abandon
   nothing.
6. A losing `Token` is moved back into its named local before the selected arm
   or post-select continuation runs. To guarantee it stays reachable, a linear
   awaitable may enter a select only as a NAMED LOCAL, never as an inline
   temporary; ordinary linearity checking (R4) forces the winning arm — or the
   code after the select — to discharge it.
7. No loan may be live across a `select` — it contains awaits, so R10
   already forbids it.
8. `select` never cancels anything: losing awaitables are unaffected by
   losing. A timeout observes slowness; it does not stop I/O.
9. An awaitable may appear in at most one arm of one select instance. A losing
   token that remains live may be armed again by a later select after the
   previous select has completed. Note the loop corollary: a `select` inside a
   loop creates fresh waits each iteration, so a timeout that should span
   retries must be created outside the loop.

```
select:
    result = await flushToken:
        # The flush won. The timer was armed up front (rule 2) and lost;
        # a Wait drops freely (rule 5).
        result.orPanic(panic, "flush failed")
    _ = await clock.after(100.ms):
        # Timed out. flushToken is STILL LIVE (rule 6) and must be awaited
        # or parked before this arm ends; it cannot be dropped.
        discard console.writeLine("flush is slow")
        (await flushToken).orPanic(panic, "flush failed")
```

## Illegal source, for calibration

```
fn examples() -> Result[(), PushError[I16]]:
    let fixed: Array[I16, 4] = [1, 2, 3, 4]
    var bytes: Bytes[512] = zeroed
    var list = List[I16, 100]()
    list.push(42)?                          # legal: compatible Result return
    return ok ()

    # Illegal Wrela source:
    # let ptr: *I16 = addressOf(fixed)      # no address-of
    # class BadCache:
    #     savedView: View[U8]               # no stored loan (R3)
    # fn mutateData(x: PciAddress):
    #     x.bus = 0                         # lent VALUES are read-only (R2)
    # async fn bad(buffer: Bytes[512]):
    #     let v = buffer[..16]
    #     await someToken                   # no loan across await (R10)
    #     use(v)
    # fn strand(disk: BlockDevice) -> Result[(), BlockError]:
    #     let token = disk.submitFlush()?
    #     otherCall()?                      # `?` while a linear value is
    #                                       # live (R4/R6): would strand it
```

## Safety summary

Wrela avoids a Rust-style borrow checker not by magic but by removing the
source patterns that force one, and replacing them with the rules above.

Source never exposes: user-visible pointers, address-of, pointer arithmetic,
null references; an ambient heap; stored loans or loans that outlive their
call tree, cross an await, or cross a device boundary; interrupt handlers,
preemption, or asynchronous entry into any object; blocking primitives, task
cancellation, or dynamic task creation.

**V1 theorem.** Given a correct compiler plus successful final-code certificate
verification, the sealed intrinsic/ABI packages, trusted driver protocol logic, a
protocol-compliant device completion assumption wherever the transport cannot
authenticate generations, descriptor-obedient device DMA or a certified IOMMU
domain, a single-CPU non-reentrant certified target,
target-specified DMA coherence, reset
quiescence, MMIO boundedness, panic/fault boundedness, extra-device handling,
and concrete memory placement at boot, Wrela kernel and service code cannot
forge compiler-provided capabilities, cannot access freed or uninitialized CPU
memory, cannot touch in-flight DMA payloads, cannot overlap object activations
across awaits, and has statically bounded object, temporary, stack, frame, and
DMA memory. CPU faults and panic paths are not source-level recovery; they must
enter a target-provided DMA-safe reset, IOMMU revoke, power-cycle, or halt
state. The theorem is not a multi-tenant confidentiality or denial-of-service
claim: a task intentionally constructed with both `Network` and `Console` needs
can leak data, and trusted Wrela code can intentionally fatal the appliance.

The model rests on:

- the load-bearing fact: single-threaded, cooperative, non-reentrant;
- two parameter modes (R2): lend or give — lent values read-only, lent
  objects usable, `consume` transfers ownership, returns construct in place;
- one loan law (R3) covering activation, lends, Ref (single look), View
  (sequence look), and Slice
  (edit): non-escaping, freezing or exclusive, confined to one synchronous
  call tree;
- nothing copies (R4): everything moves, machine scalars materialize when
  observed, and aggregate duplication is always an explicit call. Scalar
  materialization and memcpy-shaped moves are still recorded in compiler cost
  summaries even though they are not duplication call sites; `deinit` gives
  deterministic pre-drop barriers and provenance-ordered cleanup,
  and `linear` — the one written ownership word — must be consumed (dropping,
  or `?`-ing past, is a compile error), so in-flight I/O can be neither
  forgotten nor duplicated, and timeouts return live obligations instead of
  cancelling them (R12);
- the device as quarantined concurrency (R8): transferable buffers move by
  ownership, shared control memory is Mmio-style volatile access, loans stop
  at the boundary, copies are said out loud, sealed fields confine source-level
  address programming, and an IOMMU is required to contain disobedient hardware;
- completion tokens (R9) as the single runtime I/O idiom, self-redeeming and
  device-safe, with async/await (R10) as compiled sugar over them: await is
  a return, frames are plain statically sized values, no loan survives a
  suspension;
- the interleaving theorem (R11): tasks interleave only at awaits and loans
  never span awaits; task-owned `storage:` lives in one task frame, and shared
  image-static objects are reached only through `needs:` handles whose method
  calls create short synchronous activations, so sharing dependencies across
  tasks cannot produce overlapping activations;
- the loop belongs to generated code (R12): there is no user-callable
  executor entry; waiting has exactly one spelling, `await`, which unwinds
  the stack;
- arithmetic traps and bounds are checked (R16), and the call graph is
  acyclic (R17): recursion is a compile error, worst-case stack depth is
  computed, and the last unproven number in the compiler's memory demand is
  gone;
- async task liveness is statically checked (R18): a task resume cannot
  spin forever without reaching an await or exceeding a target-certified
  numeric work slice;
- doorbells, not interrupts (R13): a device interrupt can end a halt and do
  nothing else, so the concurrency model is unchanged by its existence;
- boot-only authority cannot cross into runtime; driver-owned provenance stays
  visible even when a trusted driver intentionally wraps it behind a kernel
  interface; drivers keep their claims and arenas in storage so derived MMIO
  and DMA state never outlives its source (R4);
- foreign input stays bounded and tainted until explicit verified guards clear
  named refinements; wire variable payloads are loan-bearing projections, and
  copying into owned storage preserves foreign provenance;
- List, Ring, Bytes, Option, Result are stdlib Wrela code; Storage[T, N] is
  the single compiler-provided primitive for uninitialized slots, unexported
  outside the stdlib.

The compiler still lowers objects, containers, interfaces, views, tokens,
and task frames to concrete machine layouts and CPU addresses internally.
Wrela source simply does not expose CPU object addresses as programmable
values. DMA bus addresses stay inside sealed descriptor/register builders under
R8, and every object's size and placement demand — including every suspended
task's — is known at compile time.
