# Design decisions and reconciliation

This file is non-normative. It records how the design discussions were merged
when an early proposal and a later review disagreed.

| Topic | Settled revision 0.1 decision |
|---|---|
| Compilation unit | A sealed bootable image, not a separately linked program. |
| Product scope | Fixed-function appliance substrate. “General macOS replacement” and dynamic app installation are not revision 0.1 claims. |
| Surface references | The early `&`/`&mut` spelling is removed. Access is expressed by `read`, `mut`, `take`, `view T`, and `mut view T`. |
| Call-site visibility | Non-receiver `mut` and `take` effects appear in both the parameter declaration and call argument. Read access is bare. |
| Receiver effects | Private receiver access may be inferred. Public, interface, driver-entry, and actor-message methods spell `read self`, `mut self`, or `take self`. |
| View lifetime | A view is bound to a lexical scope. It cannot be stored and cannot remain live across `await`. This replaces the contradictory “expression only” wording without forcing closure-style access for every read. |
| Mutable projections | `mut view T` accessors may yield an exclusive interior projection. The source is inaccessible until the projection ends, enabling zero-copy read/modify/write. |
| Runtime roles | `@app` is a top-level workload leaf, `@service` is a reusable non-hardware actor, and `@driver` is the only role that may own hardware authority. All three are actors; the distinct declarations are semantically enforced. |
| Actor granularity | Views stay inside an actor; actor boundaries move values or provenance-branded `iso[P]`. Components that need zero-copy views may be composed inside one actor. |
| Reentrancy | Actors are non-reentrant across dependency awaits. One unified wait-for graph covers actor turns, children, receipts, permits, and cleanup; cycles are rejected. |
| Actor lowering | Admission, ordering, non-reentrancy, cancellation, and supervision are semantic. A physical ring, payload copy, reply hop, and scheduler round trip are not; the compiler may remove them under the actor as-if rule. |
| Async storage | Values live across `await` in generated task frames. The former ambiguous “task arena” is the frame arena, not a separate magical heap. |
| Performance model | The language exposes strong closed-world facts and permits proved whole-image optimization, but makes no unmeasured throughput, latency, or footprint claim. |
| Region inference | A footprint optimization with enforceable bounds, not a promise of trivial inference. Promotion is diagnosed and can be forbidden with `@no_promote` or a hard budget. |
| Queue capacity | Requests reserve a complete descriptor chain before submission. Three-descriptor virtio-blk requests permit `floor(QDEPTH / 3)` concurrent direct chains, not `QDEPTH`. |
| Cancellation | A request region owns cancellation, deadline, DMA, queue permit, and teardown. Submitted virtio buffers enter a quarantined recovery completion and are reclaimed only after queue reset or device reset proves quiescence. The scheduler may run unrelated work while the owning driver performs recovery. |
| Drop/RAII | `with` is the universal scoped-effect form. Abort/exit actions are deterministic, synchronous, and nodes in a cleanup dependency DAG. A sealed device obligation may block a dependent node while a compiler-generated driver recovery turn runs; the scope completes only when the DAG is empty. |
| Linear values | Reclaimable linear resources have one sealed recovery transition; strict-linear resources such as published I/O receipts and partially initialized devices require an explicit proof-bearing terminal transition and cannot be silently forgotten. |
| Ring ordering | Freestanding fences are not the public API. Typed standard-library ring operations define publication, acquire, and doorbell ordering. |
| Wakeups | Parking is a compiler/runtime primitive with mask–arm–recheck semantics. A plain check followed by park is not legal synchronization. |
| Interrupt ownership | One vector maps to one ISR entry; one driver may own N MSI-X vectors. Virtio-MMIO may demultiplex its one dedicated line. Legacy shared INTx is unsupported. |
| Comptime termination | The compiler enforces a finite evaluation step quota; it does not claim to decide termination. |
| Footprint assertions | Image construction precedes analysis/layout. Layout-dependent assertions run in a second, read-only comptime pass. |
| Fault model | `Result` for recoverable operation faults, typed peer/task failure at concurrency boundaries, uncatchable abandonment for bugs, build errors for invalid images, and target-fatal failure when safe recovery is impossible. |
| Supervision | The manifest is a zero-allocation supervision tree. Restart quiesces resources, resolves old-epoch replies, applies explicit linear constructor-argument provisions, then resets and reinitializes the frame—never raw `memset` over live resources. An admitted `take` is not magically restored; recovery is an explicit result/receipt contract. |
| Security claim | Capabilities provide language-level authority control, not hardware process isolation. Target/runtime/compiler code remains trusted. |
| Comptime phase | `comptime fn` removed; ordinary `fn` is phase-neutral and checked for comptime legality at the call boundary. Twin `_comptime` APIs are thereby impossible. |
| Variant patterns | Leading-dot variant syntax; bare pattern identifiers always bind; `bind` and expected-type disambiguation removed. |
| Aggregates | `class` merged into `struct` (+ optional init, `linear` modifier). One nominal product form. |
| Projections | One view leaf per projection, implicit conservative provenance; multi-leaf, tuple carriers, `from` clauses, repair tokens deferred beyond 0.1. |
| Wrapping shift | `<<%` removed; wrapping +%/-%/*% remain. |
| Outcome types | ActorCallError composes AsyncExit instead of duplicating its variants. |
| Module list | Manifest [[module]] table removed; module set derived from source_root with verified module-declaration bijection. |
| Integer widths | u128/i128 considered for removal, retained (implemented, low surface cost). |

## Why actors are in revision 0.1

The original single-core model allowed two tasks to call the same mutable
service and interleave at `await`. That removes data races but not logical
corruption: the second call can invalidate the first call's assumptions. Making
services non-reentrant actors solves that problem and makes the intended future
multi-core transition semantic rather than source-breaking.

Static mailboxes have a cost. The image report therefore itemizes them. If a
representative appliance shows unacceptable mailbox bloat, actor granularity
can be coarsened without weakening the boundary rule: zero-copy components live
inside one actor, and isolation boundaries remain move-only.

The actor boundary is semantic rather than representational. Requiring every
edge to execute through a homogeneous ring would turn a reasoning tool into a
mandatory performance tax. The optimizer may direct-dispatch an idle actor,
forward a tail continuation, specialize message storage, or fuse machine code
when the result remains equivalent to logical admission. Programs must remain
correct without those transformations, and tooling must continue to display the
actor edge after it is optimized.

Actors remain deliberately coarse. They are ownership, fault, and future
placement units—not a replacement for ordinary structs and calls. Receipts,
batching, and explicit sharding address concurrency; accidental reentrancy is
not reintroduced as an optimization.

## Why request regions are in revision 0.1

Virtio has no general “unsubmit this one descriptor” operation. Dropping an
async frame cannot safely free a buffer that hardware may still own. A request
scope gives the compiler and driver one owner for:

- the queue permit and descriptor chain;
- the DMA payload and status memory;
- the completion token;
- the deadline and cancellation state; and
- the reset-or-complete teardown path.

This is not an optional convenience layer. It is the mechanism that makes
structured cancellation and DMA ownership agree.

## Deferred research, not hidden promises

- Multi-core scheduling retains actor and branded `iso[P]` semantics but
  requires a new replay and timing story.
- Verified install-time bytecode could support dynamic application install in a
  different product tier; full-image rebuild is the revision 0.1 rule.
- Session-typed device initialization and design-by-contract are promising
  compiler layers. Revision 0.1 requires typed protocol states and checked
  standard-library APIs but does not specify a general session-type language.
- A per-region collector could help irregular, long-lived object graphs in a
  future revision. Revision 0.1 uses bounded pools and generational handles.
- A privileged ISR escape would weaken the clean ISR theorem and is not reserved
  syntactically.

## Concept budget

The census counted roughly 225 user-facing concepts across the chapters. The
standing cap is 100. A change introducing a new named concept must name the
concept it retires or subsumes.
