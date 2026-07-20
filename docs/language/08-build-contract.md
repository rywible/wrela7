# Build contract

## 1. Purpose

The closed world matters only if the compiler turns it into visible proofs and
bounds. This chapter defines what a successful build must establish and what it
must report.

A compiler cannot defer a required revision 0.1 check to “programmer discipline”
or silently insert an unbounded allocator, dynamic dispatcher, or cancellation
leak.

## 2. Required successful-build properties

Before emitting an artifact, the compiler MUST establish all of the following.

### 2.1 Source and type closure

- The package/module graph is complete, every source path is portable and
  canonical, and every constant/layout/initialization semantic cycle is rejected.
- There is one reachable `@image` constructor.
- Every name, generic argument, `impl`, interface call, and attribute resolves;
  package orphan rules and non-overlap hold before whole-image coherence.
- Every match over a closed sum is exhaustive.
- Every local and field is definitely initialized before use.
- Every explicit aggregate copy is legal, scalar duplication is legal, and every
  move has one owner.
- Every `?` error conversion resolves to one explicit `From` implementation.
- Every fallible initializer covers partially initialized strict and
  reclaimable fields.

### 2.2 Access and region safety

- Exclusive accesses do not overlap.
- Every view is yielded only by a projection, is backed by its declared
  provenance set, remains unstored, and is dead before suspension.
- Every view carrier is consumed immediately, and every suspended whole-value
  access is rooted in the current actor turn rather than an external argument.
- Every allocation has a region and finite capacity contribution.
- Every task frame, call stack, request region, branded `iso` pool, and image allocation
  has a finite bound.
- Every promotion is reported; forbidden promotion fails.
- Every reclaimable resource has one generated reclaim destination; every
  strict-linear resource has an explicit consume/return path; every acquisition
  prefix and cleanup dependency graph is complete and acyclic.

### 2.3 Actor and async safety

- Every actor message has a fixed layout and legal payload.
- Every actor handle is image-wired and absent from runtime messages/replies.
- Every successfully admitted actor `take` is treated as irrevocable, and every
  API that promises return/recovery has an explicit all-outcomes result or sealed
  receipt with a typed commit boundary.
- Every `@receipt_handoff` atomically installs the caller endpoint before its
  moved payload becomes actor-owned; its declared input and receipt payload
  match exactly, and every handler/failure path resolves the one generated
  producer exactly once.
- Every mailbox, turn frame, child task set, and async activation is bounded.
- Every elided actor enqueue, reply hop, continuation, or handler boundary is
  proved equivalent under the actor as-if rule.
- The unified actor/task/resource/cleanup wait-for graph is acyclic.
- Every actor reply has explicit peer, cancellation, and deadline outcomes;
  every task error has a declared supervisor action.
- Every request-associated admission atomically owns a child registration before
  enqueue and every stale/closed admission returns all moved payloads.
- No unbounded detached work exists.
- Every ordinary async loop back edge is a legal semantic checkpoint or has a
  declared finite uninterrupted bound; every synchronous/ISR loop has a proven
  finite uninterrupted bound and never gains a hidden suspension.
- Every semantic checkpoint is legal with respect to live views/accesses/scopes,
  and logical selection is equivalent to the reference FIFO/deadline policy.
- Priority/deadline inheritance is sufficient for hard paths.

### 2.4 Hardware safety

- Every hardware operation has matching capability provenance and role.
- Device and vector ownership is exclusive under the target topology.
- MMIO partitions are non-overlapping, including sealed protocol mappings.
- Every ISR's transitive effects fit the ISR whitelist.
- Every `iso[P] T` ownership transition where `T` is `@dma`, and every
  `DmaShared[P, L]` operation, is
  valid.
- Every `@wire`, `@dma`, and `@mmio` layout has exact endian/offset/padding
  semantics, and ordinary structs cannot cross those representation boundaries.
- Queue capacity accounts for complete descriptor chains.
- Every untrusted device control value used as a bound is checked. The compiler
  does not claim to prove arbitrary application-format semantics: an API that
  consumes structured external data must either use explicit checked field
  operations or require `Validated[F]` produced by the format's declared parser.
- Every cancellation path either completes, proves quiescence, quarantines under
  an explicit bounded policy, or goes target-fatal before reclaiming DMA.

### 2.5 Specialization and layout

- Every ordinary type/const generic is concrete, every proof-only region brand is
  well-scoped and erased, and every interface dispatch is resolved.
- No runtime-polymorphic dispatch or unreachable comptime branch remains.
- Required WIR layout transformations preserve actor ordering, cancellation,
  supervision, work budgets, and deterministic record/replay events.
- Static sections, zero-fill reservations, stacks, frames, mailboxes, and pools
  fit the target address and image constraints.
- Target page tables, IOMMU tables, retained firmware allocations, PE/COFF
  alignment slack, relocation data, and boot scratch are included or explicitly
  identified as target-variable reservations.
- Post-layout assertions pass without mutating the graph.
- Emitted section sizes match the analyzed report.

## 3. Required image report

Every successful build emits a machine-readable report and a readable summary.
The report contains at least:

- compiler, language revision, target, profile, and input hashes;
- reachable module/declaration counts;
- every monomorphized instantiation and resolved interface call summary;
- static and peak memory by owner, region, and allocation site;
- every region promotion and its why-chain;
- actor/mailbox capacities and payload maxima;
- logical actor edges and their physical lowering: queued, direct-dispatch,
  continuation-forwarded, or fused;
- task-frame slot counts, frame sizes, overlaid live ranges, and tail-frame reuse;
- logical mailbox capacity and physical bytes by message kind;
- executor, ISR, and fault stack bounds;
- nursery/request/pool capacities;
- queue request shapes, descriptor usage, and maximum in-flight operations;
- scheduling budgets, semantic checkpoint sites/elisions, priority/deadline inheritance;
- maximum interrupt-masked interval and ISR work bounds;
- device/reset features assumed by each recovery path;
- pool brands, reclaim actions, strict-resource paths, restart provisions, and
  quarantined recovery capacity;
- every receipt handoff edge, its admission commit site, producer owner,
  supervisor recovery node, and terminal transitions;
- peer-failure reply edges and task-failure supervisor actions;
- baked artifact sizes and content hashes;
- record/replay buffer policy when enabled;
- target tables, boot scratch, alignment slack, and any target-variable memory
  excluded from the exact peak;
- declared profile-guidance hashes and optimization decisions that are required
  to satisfy a hard layout assertion; and
- code and data size by owner after whole-image dead-code elimination.

An illustrative summary might read:

```text
wrela build wrela.toml appliance --target aarch64-qemu-virt-uefi
  language revision ................. 0.1-design
  closed runtime declarations ....... 418
  generic instantiations ............ 67
  interface calls resolved .......... 344 / 344 (100%)

  actor lowering
    logical cross-actor edges ........ 23
    ordinary queued paths ............ 8
    legal-next direct dispatches ..... 7
    tail continuations forwarded ..... 6
    proved handler fusions ........... 2
    logical mailbox slots ............ 18
    physical mailbox storage ......... 24.00 KiB

  async layout
    task and turn frame slots ........ 31
    values sharing state storage ..... 46
    tail-frame reuses ................ 6

  image/static reservation .......... 4.18 MiB
    Storage.cache (4096 lines) ....... 2.13 MiB
    block DMA pool ................... 256.00 KiB
    actor mailboxes .................. 24.00 KiB
    task and turn frames ............. 71.50 KiB
    executor + ISR + fault stacks .... 40.00 KiB
    seed filesystem .................. 1.37 MiB
    other runtime/image data ......... 327.50 KiB
  peak bounded memory ............... 4.43 MiB

  virtio-blk queue
    depth ............................ 128 descriptors
    direct request shape ............. 3 descriptors
    maximum direct requests .......... 42 (2 descriptors spare)
    cancellation recovery ............ per-queue reset, full-reset fallback

  scheduling
    BlkDriver.drain_used ............. <= 200 us between checkpoints
    Notes.run ........................ <= 5 ms between checkpoints
    max interrupt-masked interval .... 1.8 us

  region promotions ................. 0
  post-layout assertions ............ 3 passed
  output ............................. wrela-storage.efi
```

Numbers in this example are illustrative, not measurements or promises about an
implementation.

## 4. Diagnostics

A diagnostic has:

- a stable category such as `view`, `access`, `wait-cycle`, `region`, `dma`,
  `isr`, `comptime-budget`, `capability`, or `performance`;
- a primary source span;
- the inferred fact that caused rejection;
- a path/why-chain when whole-image analysis is involved; and
- at least one source-level repair when a local repair exists.

Diagnostics must use source concepts rather than only generated frame fields or
backend IR names.

### 4.1 View across await

```text
error[view]: `line` remains live across this await
  storage/cache.wr:72:18  line = self.peek(index)
  storage/cache.wr:75:12  await disk.submit(...)
  storage/cache.wr:78:9   line.valid = true
  note: views cannot be stored in an async frame
  help: copy or take the required value before await, then project again after it
```

### 4.2 Invisible move prevention

```text
error[access]: argument `pool` requires ownership transfer
  driver = BlkDriver(cap, pool)
                          ^^^^
  help: write `pool=take pool`; `pool` will be uninitialized after the call
```

### 4.3 Actor boundary

```text
error[actor-message]: `mut Bytes` cannot cross from Notes to Storage
  note: actor messages cannot contain mutable loans
  help: allocate it from a durable branded pool as `iso[Packets] Bytes`, pass it with `take`, and return ownership
```

### 4.4 Wait-for cycle

```text
error[wait-cycle]: blocking resource cycle
  A.turn -> child[0] -> B.turn -> A.turn
  note: A retains its non-reentrant turn while joining child[0]
  help: make one edge one-way, return a receipt, or move the child out of A's turn
```

### 4.5 Queue capacity

```text
error[queue-bound]: request path may reserve 43 three-descriptor chains
  queue depth: 128; required descriptors: 129
  help: reduce request concurrency to 42, increase queue depth, or negotiate indirect descriptors
```

### 4.6 ISR effect

```text
error[isr]: allocation is not permitted in interrupt context
  note: no call or request region is active in `isr fn`
  effect path: on_irq -> format_status -> Bytes.with_capacity
  help: store a level signal and wake the driver's bottom half
```

### 4.7 DMA state

```text
error[dma]: payload is device-owned after queue publication
  published here: drivers/virtio/block.wr:188
  attempted read: drivers/virtio/block.wr:191
  ownership returns only through receipt completion or reset teardown
```

### 4.8 Region promotion

```text
error[region]: `@no_promote` allocation would require image lifetime
  allocated in `Parser.run` at parser.wr:31
  escapes through `self.pending` at parser.wr:44
  `self` is image-owned actor `Parser`
```

### 4.9 Actor chatter

```text
warning[performance]: loop may perform 4096 cross-actor turns per request
  call edge: Router.route -> Firewall.classify
  note: a direct-dispatch fast path is not guaranteed under competing ready work
  help: batch classifications, compose the components inside one actor, or
        move a bounded packet group through `iso`
```

## 5. Tooling-visible inferred effects

Even when a private receiver omits `read self` or `mut self`, compiler metadata
and language-server hover must display the inferred signature. Expanded views
also show:

- region assignment and promotion reason;
- inferred/displayed `iso` pool brand and reclaim destination;
- strict versus reclaimable linear classification and restart provision;
- copy versus move at every binding;
- logical actor edge versus internal call, plus its queued, direct, forwarded,
  or fused lowering;
- message payload layout, copy/move behavior, and mailbox contribution;
- suspension points and frame fields;
- frame storage overlays, recomputed values, and tail-continuation forwarding;
- semantic checkpoints and any proved elisions;
- capability/effect provenance; and
- DMA state before and after protocol calls.

Whole-image inference must reduce annotations, not hide causality.

The compiler SHOULD diagnose performance shapes whose cost is surprising at the
source level, including bounded actor chatter in a hot loop, a large copied
message, largest-variant mailbox padding, a value that unnecessarily inflates
many async frames, specialization-driven code growth, and a preventable region
promotion. These are advisory unless a profile budget makes them errors.

## 6. Reproducibility

Given identical declared inputs, compiler revision, target package, build
profile, quotas, and signing configuration, the emitted unsigned image and
machine-readable report must be byte-for-byte reproducible.

Timestamps, random build IDs, absolute host paths, nondeterministic archive
ordering, and undeclared environment data cannot enter the artifact. Packaging
signatures may be non-reproducible but are external to the unsigned language
artifact and report their inputs separately.

## 7. Build profiles

A profile declares at least:

- target and ABI versions;
- always-checked arithmetic/bounds semantics and optional non-safety diagnostics;
- comptime step/memory quotas;
- memory and latency ceilings;
- DMA coherency/IOMMU assumptions;
- device reset time bounds and quarantine policy;
- record/replay mode and log capacity;
- development diagnostics/watchdogs;
- optimization level and declared profile-guidance inputs. The exact CPU,
  register reservations, and backend features belong to the selected target
  package and cannot be overridden by a profile.

A “release” profile cannot disable the language's ownership, view, actor,
checked-arithmetic, bounds, capability, ISR, or DMA rules. It may change logging,
debug assertions explicitly classified as non-safety checks, or performance
instrumentation.

## 8. Conformance tests

A conforming toolchain test suite includes, at minimum:

1. parser/type acceptance of every complete normative `wrela` block (fragments
   containing `...` are explicitly excluded) and rejection snapshots for
   every grammar production, trailing-comma site, indentation error, malformed
   literal/escape, and contextual type/const argument error;
2. left-to-right receiver/argument/constructor/interpolation evaluation,
   short-circuiting, assignment/compound-assignment order, access activation, and
   reverse full-expression temporary teardown using observable test effects;
3. checked arithmetic in every profile, signed `MIN / -1`, remainder signs,
   invalid shifts, checked/wrapping conversion, canonical NaN, and float-to-int
   edge cases;
4. explicit aggregate copy versus move and rejection of copying every linear
   struct;
5. every legal and illegal access/view example, including projection-only
   returns, conservative implicit provenance, branch-dependent sources, and
   disjoint mutable-projection paths;
6. rejection of a view/external access across `await`, plus legal turn-rooted
   access to nested actor-owned state;
7. every second-class carrier shape and rejection of storing, returning,
   capturing, sending, or suspending it;
8. fresh pool/request brands, fresh map instance IDs, duplicate source-brand
   rejection, cross-pool and foreign-map rejection, request-brand escape, and
   concurrent request activations from one source site;
9. generation/epoch/instance-ID retirement at maximum with no wrap for slot,
   queue, actor, request, task, and map identifiers;
10. reclaimable `iso` cleanup on `?`, strict-linear rejection, acquisition
    `abort`, cleanup-DAG dependency ordering, blocked exit nodes, and double-fault
    escalation;
11. actor payload (including explicit `Static[T]` versus rejected bare runtime
    shapes), image-wired handle, non-reentrancy, FIFO-head scheduling, and
    explicit actor-call cancellation/deadline outcomes;
12. reservation-before-argument actor admission, unevaluated rejected `try send`
    with arm-refined initialization, irrevocable committed `take`, explicit
    receipt/result recovery before commit, and `OutcomeUnknown` after commit;
    plus `@receipt_handoff` failure immediately after admission, while queued,
    during handler abandonment, and during restart, with exactly one caller
    receipt and eventual owned-payload recovery in every case;
13. unified wait-for rejection for actor cycles, parent-child-actor cycles,
    mailbox/permit cycles, and a driver receipt whose producer requires the same
    turn; plus accepted external timer/device producers;
14. request admission registered before enqueue, queued child cancellation,
    stale/canceled/deadline admission without payload loss, and one-way child
    registration;
15. mailbox, nursery, frame, recursion, queue, cleanup-node, and quarantine
    capacity limits;
16. wake-before-park, wake-during-park, duplicate-wake, and static task identity;
17. async semantic loop checkpoints/cancellation, illegal live views/scopes,
    proved `@uninterrupted` elision, and rejection of unbounded synchronous/ISR
    loops without hidden suspension;
18. IRQ and poll builds from the same const-generic driver source;
19. MSI-X multi-vector/virtio-MMIO demultiplexing, interrupt nesting bounds, and
    same-vector non-reentry;
20. ISR transitive-effect rejection and interrupt-atomic `InterruptCell` RMW;
21. Virtio undefined interrupt bits never written to `InterruptACK`;
22. out-of-order DMA completion, stale software generation/reset epoch, duplicate
    descriptor head, malicious device length, and no head reuse before quiescence;
23. cancellation before submission, after publication, during deferred reset,
    and as a losing sealed `race` alternative;
24. per-queue/full-device reset with sibling invalidation and quarantined-region
    non-reuse;
25. rejection of ordinary/`@dma` structs by wire decoders, exact `@wire`
    endian/offset/version fixtures, and persisted schema migration checks;
26. comptime I/O rejection, per-instantiation branch evaluation, phase-cycle
    diagnostics, quota exhaustion, cache reproducibility, and explicit/implicit
    `Secret` leakage rejection;
27. supervision cleanup of live branded handles, restart provisions, fallible
    initializer rollback, and epoch exhaustion;
28. UEFI map-key invalidation/retry with no boot-service call between the final
    `GetMemoryMap` and successful `ExitBootServices`;
29. record/replay of DMA bytes and interrupt injection points plus deliberate
    input, extent, output, and checkpoint divergence;
30. actor direct dispatch, tail forwarding, and fusion equivalence against the
    reference semantics;
31. Unicode version/NFC/default-ignorable/confusable/path-collision fixtures on
    case-sensitive and case-insensitive hosts;
32. state-sensitive frame overlay with cancellation/abandonment at every state;
33. logical versus physical mailbox accounting and actor-chatter diagnostics;
    and
34. emitted section sizes and target-runtime reservations matching the report;
35. compiler-evaluated `@test fn` quota/cache/failure reporting,
    generated integration-test image isolation and bounds, declared image-test
    scenarios, framed-event corruption/sequence/terminal rejection, boot/crash/
    timeout/protocol failure classification, and evidence that no runtime test
    executes through a hosted target or ambient QEMU/firmware; and
36. AArch64 PE/COFF machine/entry/subsystem inspection plus boot under the
    digest-pinned versioned QEMU `virt`/UEFI runner profile.

The corrected virtio appliance in
[`examples/virtio-storage.wr`](examples/virtio-storage.wr) is a required
integration-shape test once the corresponding standard-library APIs exist; the
worked source alone is not boot or device-I/O evidence. Current status is
tracked in the [conformance inventory](conformance-inventory.md).

## 9. Performance claims

The design enables direct calls, no mode switches inside the image, bounded
arena reset, static frames, and compile-time footprint accounting. These are
structural properties.

They do not constitute benchmark results. Documentation must not claim a
specific footprint, throughput, latency, or advantage over another operating
system until a wrela implementation measures it on a named target and workload.

The permitted transformations and their semantic limits are specified in
[Optimization model](09-optimization-model.md). Optimization may improve an
accepted image's physical footprint and latency; it cannot erase a logical
capacity use, weaken a safety check without proof, or change observable actor
behavior.

## 10. Conformance statement

A revision 0.1 compiler conforms only if it implements all normative semantics
in chapters 01 through 10 for its advertised target profile. A target may omit
an optional profile such as deterministic recording. It may not advertise a
feature while weakening its invariants.
