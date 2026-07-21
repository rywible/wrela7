# Foundations

## 1. Purpose

wrela is for fixed-function appliance images: storage targets, network
functions, routers, kiosks, embedded guests, and similarly sealed systems. The
language is designed around information a general-purpose, separately compiled
language cannot assume:

- the complete code graph is known at build time;
- the actor and task set is finite and bounded;
- hardware bindings and resource budgets are part of the build input;
- no code enters the image after it is sealed; and
- revision 0.1 executes application code on one core.

The compilation unit is therefore not a library or process. It is the machine
image.

## 2. The closed world

An image contains exactly the runtime code reachable from:

1. its single `@image` entry;
2. the selected target package and target ABI;
3. actor constructors, message handlers, tasks, ISRs, and teardown paths wired
   by the image; and
4. compiler-generated runtime support for that graph.

The compiler MUST reject a build if reachability is not closed. Revision 0.1
has no dynamic loader, JIT, runtime code generation, runtime method lookup, or
unbounded task creation. There is no `dyn` type and no vtable-based interface
dispatch.

Closed-world knowledge permits, but does not by itself prove, static boundedness.
The language also restricts program shapes: task slots, mailboxes, pools,
recursion, and request concurrency must all have finite build-time bounds.

## 3. The runtime world

A revision 0.1 image has:

- one address space;
- one application core;
- one cooperative event loop;
- a bounded, generated set of actor and task frames;
- target-defined interrupt entry and ISR stacks; and
- no userspace/kernel mode transition within the image.

Firmware may execute before the image takes ownership of the machine. After the
target boot transition, runtime code cannot call firmware boot services.

The one-core rule eliminates simultaneous execution of ordinary actor code. It
does **not** eliminate asynchronous interleaving, compiler reordering, DMA
concurrency, or interrupt preemption. Those remain explicit parts of the model.

## 4. The image graph

The result of `@image build()` is a typed graph, not an imperative boot script.
Its nodes include:

- device declarations and driver bindings;
- actor instances marked `@driver`, `@service`, or `@app`;
- typed mailboxes and bounded task slots;
- static, DMA, request, and transferable pools;
- interrupt-vector bindings and poll tasks;
- the supervision tree; and
- target configuration and baked read-only data.

Ordinary ownership inside an actor is a tree. Actor-to-actor edges are typed
message channels, not object references. Device edges are capabilities minted
by image binding. A graph-shaped data structure inside an actor uses stable
value handles such as `SlotMap.Key`, never stored projections.

The three actor roles have distinct graph meanings. An `@app` is a top-level
workload leaf: it may depend on services and drivers' safe APIs, but its handle
cannot be installed into another actor. A `@service` is a reusable non-hardware
actor that may be an image-wired dependency of apps or other services. A
`@driver` is the only actor role that may receive hardware authority. These
roles share the same ownership and non-reentrancy semantics; the distinctions
constrain image wiring and capability flow rather than scheduling behavior.

```text
Image
├── Target and boot contract
├── Driver actor ── owns MMIO, IRQ, DMA pools, queues
├── Storage actor ─ owns filesystem and cache
├── App actor ───── owns application state
├── Static mailboxes and task frames
└── Supervisor tree

App ── typed message / iso move ──> Storage
Storage ── typed message / DMA move ──> Driver
IRQ vector ── exclusive ISR entry ──> Driver
```

## 5. Load-bearing invariants

Every conforming implementation MUST enforce these invariants.

### 5.1 Values and access

1. Fields contain owned values or branded `iso` handles; they never contain a
   `view` or a second-class view carrier.
2. A `mut` access is exclusive for its lexical duration.
3. A `take` access leaves its source uninitialized until explicitly replaced.
4. Only a projection may yield a view. Provenance is implicit and conservative:
   every receiver and parameter reachable by the projection is treated as a
   possible backing source, and callers retain that access until the view
   ends. A view is lexical and second-class: it cannot be stored, sent,
   captured by an escaping closure, submitted to hardware, or kept across
   `await`. An `Option`/`Result` carrier wrapping one view leaf exists only
   while immediately binding, destructuring, propagating, or matching the
   projection.
5. Non-scalar duplication is explicit with `copy`; assignment otherwise moves.
6. Cross-actor messages contain scalar or explicitly copied values, immutable image-static values,
   transferred `iso` values, or sealed linear runtime handles such as device
   receipts. They contain neither loans nor shared mutable state.

### 5.2 Regions and resources

1. Every allocation belongs to exactly one region.
2. Every region has a compile-time capacity bound and a deterministic teardown
   point.
3. Values live across `await` in a generated task frame or an owned nested
   region, never in an ephemeral call region.
4. Nontrivial resources are linear. A reclaimable linear value has a generated,
   deterministic consume action; a strict linear protocol value must be
   consumed explicitly or protected by a scope.
5. Scope abort/exit and strict resources form an acyclic cleanup dependency
   graph. Ready nodes run in deterministic reverse source order on normal exit,
   early return, cancellation, and abandonment; a dependency may delay an exit
   while sealed recovery keeps its region quarantined.

### 5.3 Actors and scheduling

1. Mutable state is owned by one actor.
2. An actor processes at most one external message turn at a time.
3. Awaiting a dependency does not admit another external turn into that actor.
4. The unified wait-for graph over actor turns, tasks, replies, receipts,
   admission slots, permits, pools, and cleanup/recovery nodes is acyclic.
5. Every task activation, mailbox, and in-flight request has a finite build-time
   bound.
6. Every async loop back edge is a semantic checkpoint unless source supplies a
   proven finite uninterrupted bound; every synchronous/ISR loop is itself
   finitely bounded and never suspends implicitly.
7. A successfully admitted `take` is irrevocable unless an explicit result or
   sealed receipt promises return before a typed commit point.

### 5.4 Devices and interrupts

1. Hardware authority is represented by unforgeable, manifest-minted
   capabilities.
2. Each interrupt vector has one ISR entry. A driver may own several vectors.
3. An ISR can touch only its bound device state and ISR-safe driver state, can
   acknowledge the source, and can wake work. It cannot allocate, await, block,
   use floating point, or call application code.
4. CPU code cannot access DMA payload memory while the device owns it.
5. Device-shared control memory is never accessed as an ordinary value.
6. Device protocol/control values used as lengths, indices, or bounds remain
   untrusted until checked. Device-written payload bytes are ordinary
   application data and require their format's own validation.
7. DMA memory is not reclaimed after cancellation until the queue or device is
   proven quiescent.

### 5.5 Build and failure

1. All interface calls resolve to concrete code or a closed enum branch.
2. Compile-time evaluation is deterministic, target-emulated, I/O-free, and
   step-bounded.
3. Recoverable failures are values. Bugs abandon an actor and are not catchable
   as ordinary errors.
4. Restart cannot skip resource teardown.

## 6. Safety claim and threat boundary

wrela aims to prevent, in conforming source code:

- use-after-free and double ownership;
- mutable aliasing through language values;
- stored or suspended projections;
- cross-actor shared mutable state;
- unbounded runtime allocation and recursion;
- app-level MMIO, DMA, or IRQ authority fabrication;
- CPU access to device-owned DMA payloads;
- ISR calls outside the ISR effect set; and
- reclaim of in-flight DMA on an unquiesced device.

This is language-level isolation in one address space. It is not process-style
fault containment. A compiler bug, target-runtime bug, firmware bug, malicious
device, incorrect target ABI, or future unsafe/FFI escape can compromise the
entire image. Typed MMIO, DMA confinement, and an IOMMU reduce that trusted
computing base; they do not erase it.

The standard safe language has no arbitrary pointer arithmetic and no general
`unsafe` block. Any future FFI or unsafe facility MUST be a separately auditable
target capability and is outside revision 0.1.

## 7. What “static” means

wrela promises **static bounds**, not that all values exist forever or that the
compiler can predict every runtime branch.

- Image-root objects, mailboxes, task frames, fixed pools, and baked data have
  fixed layouts.
- Bounded arenas may hold a runtime-varying number of values up to a known cap.
- Request and frame arenas reset at runtime at deterministic points.
- Region inference may promote an allocation to image lifetime; the compiler
  must report that promotion and its cause.

This distinction permits workloads such as a compositor scene with a dynamic
number of objects per frame while retaining a build-time memory ceiling.

## 8. Revision boundary

Revision 0.1 deliberately excludes:

- multi-core execution;
- shared-memory concurrency and app-visible atomics;
- dynamic application installation or loading;
- tracing garbage collection;
- runtime reflection and dynamic dispatch;
- legacy PCI INTx sharing;
- arbitrary top-half or “privileged ISR” escape hatches; and
- install-time verified bytecode.

The actor/message semantics, `iso` transfer, and per-vector IRQ ownership are
chosen to make it plausible that a future per-core actor scheduler would not
change application APIs. This is an explicitly tracked bet, not a guarantee:
its falsifier is the absence of a 2-core semantic sketch that validates
non-reentrancy and deterministic replay under these same actor/message/`iso`
rules. That future scheduler, and this bet about it, are not part of the
current safety or determinism claim.
