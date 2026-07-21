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
| Integer widths | u128/i128 first retained, then removed from 0.1 (decision reversed after two independent reviews: the bounded-appliance domain does not need 128-bit arithmetic, and every width multiplies checked-arithmetic/format/wire obligations; GUID-shaped data is `Bytes[16]`). |
| Test tiers | `@test(runtime)` forces the runtime tier explicitly; routing-by-legality alone bred the tier-guard `while` incantation in examples. Intent is declared, not smuggled through an illegal construct. |
| Argument labels | Declaration-owned (Swift lesson): parameters are label-required by default; `_` declares positional-only. A function whose only non-receiver parameter defaults to positional-only instead. Exactly one legal spelling per call site; replaces "positional until first named". |
| Comptime contract | Public comptime-callability is a declared, compiler-verified `@comptime` marker on pub functions (cross-package); in-package stays inferred. Mirrors the receiver-effect rule: inferred privately, spelled publicly. |
| POD duplication | `copy struct` opt-in: scalar-recursive pointer-free types duplicate implicitly; explicit `copy` remains for everything else. The C++ lesson is about non-POD implicit copies, not 8-byte values. `SlotMap.Key`/`RequestMetadata` re-specified through the marker instead of by fiat. |
| Expression forms | `if` and `match` are expressions (inline `if c: a else: b`; block-form match-as-value with divergence-or-value arms). Statement-only forms taxed every binding with rebinding ceremony, measured in our own stdlib and worked example. |
| Request lineage | Ambient by default: async fns implicitly carry the lexically enclosing request lineage; explicit `request=` override and `@detached` cover the exceptions; tooling displays the inference. Optional explicit threading is the C#/Go propagation-gap failure mode. `[region R]`/`RequestContext` leave ordinary signatures. |
| Ephemeral types | The five second-class carriers (projection carrier, AdmissionResult, actor-call outcome, and peers) unify under one declared `ephemeral` concept with enumerated per-type deviations. |
| Receipts | `TransferReceipt`/`IoReceipt` merged into one `Receipt[P]` state machine with named states; all strict-linear and recovery rules preserved. |
| Evidence wrappers | `Untrusted[T]` and `Validated[F, T]` are two instantiations of one evidence-wrapper family (taint-in vs proof-out). |
| Work bounds | `@budget` and `@uninterrupted` merged into one `@budget` attribute covering function-level and loop-level bounds. |
| Prelude | A fixed, shadowable prelude: `Option`, `Some`, `None`, `Result`, `Ok`, `Err`, `panic`. Everything else is imported. |
| Iteration | Revision 0.1 iterates a closed builtin set (ranges, arrays, container operations); a general user-defined iteration protocol is deliberately excluded until driver evidence demands one. |
| Deriving | A sealed compiler-built-in `deriving(Eq, Format, From)` clause with a closed list; removes the error-conversion boilerplate farm without opening a macro system. |
| Naming and capacity | Variants are CamelCase constructors (lint-enforced); `..N` spells bounded runtime occupancy, plain `N`/`[T; N]` spells exact extent. |
| Doc comments | `##` documentation comments attach to the following declaration and feed tooling. |
| Lockfiles | Dropped from revision 0.1: with exactly one acquirable package (the toolchain `core` component), a lock pins no choice. Returns with real third-party acquisition. |
| Service concurrency | Non-reentrancy stays unconditional. Concurrent I/O uses the service slot idiom (bounded in-flight `SlotMap` + sealed `slot.resolve(take receipt)`); sharding remains available. Reentrancy is not a service-tier exception. |
| Multicore | Normative static placement: each actor assigned to one core by the image manifest; per-core cooperative schedulers; cross-core edges lower to generated bounded SPSC rings; IRQ/DMA affinity to the driver core; admission-order record/replay. Advertised 0.1 runtime remains single-core. |
| Unary labels | A function whose only non-receiver parameter defaults to positional-only (label opt-in); multi-parameter and bool-heavy APIs stay label-required. |

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

Actors remain deliberately coarse. They are ownership, fault, and physical
placement units—not a replacement for ordinary structs and calls. The service
slot idiom, receipts, batching, and explicit sharding address concurrency;
accidental reentrancy is not reintroduced as an optimization.

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

- A full multicore *runtime* (multi-core boot, GIC routing for N cores beyond
  a proof vertical) remains deferred; the normative static-placement model is
  already written in chapter 01 §8.1.
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

The census counts concept FAMILIES, not spellings: one ephemeral-type concept,
one evidence-wrapper family, one brand concept with three introduction sites,
one access lattice at two scopes, and attribute families rather than individual
attributes. After the recorded merges (ephemeral carriers −4, receipts −1,
outcome taxonomy −2, work bounds −1, evidence wrappers −1, ambient lineage −2,
brand consolidation −2, access lattice −1, u128/i128 −2) the honest estimate is
roughly 190 against the cap; the remaining gap closes only through further
retirements, never by re-counting. The service slot idiom and static core
placement add **zero** user-facing concepts (they reuse `SlotMap`, `Receipt`,
and sealed rings, with placement as manifest config); retiring the service
reentrancy open problem and the multicore API bet is a favorable net movement.

## Bets register

A bet is a design decision whose correctness we cannot yet check. Each entry
names its falsifier — the concrete evidence that would confirm or reverse it.
Wrong-but-tracked is recoverable; wrong-but-implicit fossilizes.

| Bet | Falsifier |
|---|---|
| Wait-for-graph acyclicity rejects few enough correct programs to keep | The reference virtio appliance: count restructurings of correct code required to satisfy the analyzer. The actor chapter does not freeze before this runs. |
| Slot idiom is ergonomic enough to be the only service-concurrency mechanism | The reference virtio appliance's Storage actor under 2+ client load: count contortions and queue-behind-latency incidents. |
| Static placement suffices without migration | The same appliance's image report: does any realistic profile need per-load rebalancing that a manifest edit cannot express? |
| Admission-order replay is complete for multicore | The 2-core vertical's record/replay run diverges only if an unlogged nondeterminism source exists; any divergence names a spec hole. |
| Cross-core ring cost is acceptable | Named measured benchmark on the 2-core vertical (chapter 08 §9: no unmeasured claims). |
| `view`/projections earn their concept-budget rent | The first real driver: if the appliance needs projections beyond closure accessors and `with`-scoped access, they stay; otherwise they are cut before freeze. |
| Verified `@comptime` markers prevent silent stdlib comptime breakage | The first stdlib upgrade that changes a marked function's closure: breakage must surface at the declaring package, not a consumer. |
| Ambient request lineage covers real programs with rare explicit overrides | Frequency of `request=` overrides and `@detached` in the appliance; if overrides dominate, ambient was the wrong default. |
| Dropping lockfiles from 0.1 loses nothing real | The arrival of third-party package acquisition; the lockfile returns designed against real requirements. |

## Prose follows evidence

Normative ergonomics prose in chapters 02–04 now follows implementation
evidence: the daily-use kernel (expression `if`/`match`, POD copy, read-param
loans, prelude, iteration, one end-to-end request-scoped I/O path) is
implemented and exercised before further normative surface is added. The spec
does not run ahead of what the worked example and the verticals have paid for.
