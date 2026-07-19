# Revision 0.1 conformance inventory

This is the authoritative implementation inventory for the normative prose in
chapters 01–10. It describes the advertised
`aarch64-qemu-virt-uefi` profile; it is not a conformance claim.

## Rules for maintaining this inventory

- A row covers every normative sentence and list item in the cited section(s).
  A section is split when its obligations have different implementation status.
- `verified` means the cited implementation is exercised through every applicable
  compiler/runtime layer and the cited evidence passes. `partial` means the row
  has real implementation and evidence but at least one named layer or behavior
  is absent. `gap` means there is no end-to-end implementation. `exclusion`
  means the normative specification itself explicitly places the feature outside
  revision 0.1; project scheduling is never an exclusion.
- Layer abbreviations are `S` source/package/parser/formatter, `A` semantic
  analysis and diagnostics, `SW` SemanticWir, `FW` FlowWir, `MW` MachineWir,
  `N` LLVM/ARM64 COFF/EFI, `R` target runtime/QEMU, and `P` image report/tooling.
  A dash in a layer list is an explicit missing layer, not “not applicable”.
- Evidence names checked-in files. A test name without a successful recorded run
  is implementation evidence, not proof of conformance. The focused gate for a
  row is `cargo xgate <owning-slice>`; milestone proof additionally requires the
  release gates and pinned QEMU profile.
- A new normative heading or obligation must add or split a row in the same
  change. Unsupported source must fail closed with a source diagnostic; accepting
  and silently weakening a row is forbidden.

Unless a row narrows applicability explicitly, source-only rules require
`S,A,P`; compile-time-only rules require `S,A,SW,FW,MW,N,P` when they materialize
runtime data/code and `S,A,P` otherwise; every runtime-observable rule requires
`S,A,SW,FW,MW,N,R,P`; and image/product rules require all eight layers. Thus a
`partial` or `gap` row names missing end-to-end coverage even when its evidence
cell mentions only the layers currently present. “Not implemented”, “absent”,
or “none” is explicit evidence that no qualifying positive test exists; a row
may become `verified` only after replacing that statement with concrete positive,
negative, exact-limit/cancellation (where applicable), native, report, and QEMU
evidence.

The compiler phase map is documented in [the crate contracts](../../crates/README.md),
and versioned boundary fixtures are described in
[the contract fixture index](../../tests/contracts/README.md).

## Chapter 01 — Foundations

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 1.1 | Sealed fixed-function image, finite actor/task/resource world, one application core. | Model exists across build/target crates; no complete appliance/QEMU proof. | partial — req-02,03,12 |
| 1.2 | Exact reachable closure from one image, target ABI, handlers/tasks/ISRs/teardown and generated runtime; reject dynamic/unbounded closure. | A/SW/FW/MW scaffolding; `crates/wrela-compiler/tests/build_planner.rs`. | partial — req-09 |
| 1.3 | One address space/core/cooperative loop, bounded frames, ISR stacks, and no boot-services calls after transition. | Target/runtime ABI and EFI linker exist; recurring runtime proof absent. | partial — req-03,15 |
| 1.4 | Typed image graph, actor roles/wiring, capabilities, pools, IRQs, supervision and stable value handles. | Image/build models exist; general graph execution absent. | partial — req-03,08,09 |
| 1.5.1 | Owned fields, exclusive `mut`, initialized `take`, projection-only lexical views, explicit aggregate copy, legal actor payloads. | Scalar/flat aggregate/move fragments only. | partial — req-05 |
| 1.5.2 | Exactly-one bounded region, frame-safe suspension, linear cleanup, deterministic acyclic cleanup dependencies. | Representational models only; no general cleanup runtime. | gap — req-05 |
| 1.5.3 | Actor ownership/non-reentrancy, acyclic unified wait graph, finite activations, checkpoints, irrevocable admitted takes. | One-way actor vertical exists: `actor_flow_vertical.rs`, `actor_one_way_send_vertical.rs`; recurring scheduler/wait graph absent. | partial — req-03,04,07 |
| 1.5.4 | Manifest capabilities, exclusive ISR, DMA/control-memory ownership, untrusted checks and quiescent cancellation. | Target types/tables are modeled; no complete virtio execution. | gap — req-08 |
| 1.5.5 | Closed dispatch, deterministic bounded comptime, value errors vs abandonment, restart after teardown. | Bounded comptime vertical exists; other clauses incomplete. | partial — req-09,10 |
| 1.6 | Enforce safety claim while accurately documenting compiler/runtime/firmware/device TCB; no general unsafe/FFI. | Architecture boundaries documented; full enforcement follows feature rows. | partial — req-18 |
| 1.7 | Static layouts and ceilings with bounded runtime occupancy and reported promotion. | Build/report models exist; general region accounting absent. | gap — req-05,09 |
| 1.8 | Only the explicitly listed later-revision features are excluded. | See exclusion ledger below. | verified — documentation |

## Chapter 02 — Source language

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 2.1 | UTF-8/Unicode 16 XID+NFC/security, comments, four-space blocks, continuations, literals/escapes/interpolation and bounded formatting. | Syntax and formatter crates plus `tests/contracts/syntax/v3`; Unicode/security and full literal corpus not complete. | partial — req-02,13 |
| 2.2 | Module declaration/path identity, absolute imports/re-exports, visibility, SCC imports and semantic-cycle diagnostics. | Package/source/HIR pipeline exists; complete cycle/visibility matrix unproven. | partial — req-02,09 |
| 2.2.1 | Exact schema-1 manifest/lock, explicit modules/dependencies/profiles/images/tests, canonical acquisition and sole target. | `wrela-package*`, `tests/contracts/package/v1`. | partial — req-09,16 |
| 2.3, 2.3.1 | All declarations and function colors; explicit async/task outcomes and prefix `await`. | Parser models much of the surface; general executable functions/async absent. | partial — req-02,04 |
| 2.3.2 | Struct construction/privacy/copy, generative brands and zero-sized values. | Flat nongeneric structs execute in bounded subsets: `runtime_flat_structure_vertical.rs`, `comptime_aggregate_vertical.rs`. | partial — req-02,05 |
| 2.3.3 | Unique classes, partial initialization, fallible rollback, actor roles and receiver-free associated functions. | Parsed/modelled; no general class runtime. | gap — req-05 |
| 2.3.4 | Closed enums, exhaustive guarded patterns, alternatives/bindings, `is`, payload access and fixed-array patterns. | Local 1–256 variant copy-scalar subset; `runtime_result_vertical.rs`. | partial — req-02,06 |
| 2.3.5 | Static interfaces, orphan/non-overlap/coherence, direct dispatch, operators and unique `From` propagation. | No general interface/From implementation. | gap — req-02,06,09 |
| 2.3.6 | Projection carriers/provenance/disjointness and scope enter/abort/exit/suspend-safe repair. | Surface/model only. | gap — req-05 |
| 2.4, 2.4.1 | Exact read/mut/take call markers, place operands, binding/evaluation order and explicit receiver effects. | Scalar/aggregate call fragments; general access analysis absent. | partial — req-02,05 |
| 2.5.1 | Primitive integer/float/unit/never semantics, checked/wrapping arithmetic/conversions, canonical NaN and target widths. | Integer verticals: `checked_shift_vertical.rs`, `compound_assignment_vertical.rs`; float completeness absent. | partial — req-02 |
| 2.5.2 | Tuples, fixed arrays, bounded collections/strings/bytes, Static/Option/Result/Actor/iso/view/capability legality. | Flat structures and restricted `Result[S,S]`; general types absent. | partial — req-02,06 |
| 2.5.3 | Type/const/brand generics, inference and monomorphization without runtime generics. | Restricted core Result authentication only. | partial — req-09 |
| 2.6 | Let/inferred bindings, move/copy, definite initialization, assignment and partial-field state on all CFG edges. | Locals/branches in selected verticals only. | partial — req-02,05 |
| 2.7 | If/match/for/while/loop, return/break/continue/pass, bounded sync loops and async checkpoints. | `elif_vertical.rs` and `bounded_while_vertical.rs` prove the canonical unsigned finite `while local < literal` slice with mutation, nested `if`, `continue`, `break`, cyclic SSA, and machine CFG; `for`, general `loop`, non-canonical bounds, cleanup edges, and async checkpoints remain absent. | partial — req-02,04 |
| 2.8 | Complete precedence/evaluation/place/call/assignment/temporary teardown/arithmetic contract. | Several scalar expression verticals; general expression and teardown execution absent. | partial — req-02,05 |
| 2.9 | Non-escaping/escaping closure capture modes, regions, bounds and async legality. | Surface only. | gap — req-02,05 |
| 2.10 | Complete attribute legality/phase/effects, including image/actor/task/hardware/layout/test/budget attributes. | Test and selected runtime attributes only. | partial — req-08,09,13 |
| 2.11 | Normative grammar accepts all legal forms and rejects all illegal productions with canonical formatting. | Syntax v3 fixtures exist; chapter-wide corpus incomplete. | partial — req-13,14 |

## Chapter 03 — Values, views, and regions

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 3.1–3.3 | Read/mut/take semantics, structural copy/linear classes and path-based exclusivity. | Restricted scalar/flat aggregate ownership only. | partial — req-05 |
| 3.4–3.4.4 | Lexical second-class views, projection provenance/carriers/disjointness, no escape/suspension and iterator access. | Parsed/modelled only. | gap — req-05 |
| 3.5 | Generative branded `iso`, durable/request brands, actor transfer and ownership-conditioned recovery. | No general iso/pool runtime. | gap — req-05,07 |
| 3.6–3.6.5 | Image/task/call/request/iso region classes and exact lifetime/slot/reset rules. | Frame/layout data structures exist; general inference/runtime absent. | gap — req-05 |
| 3.7–3.9 | Whole-image region inference, reported promotion/budgets and bounded allocation/capacity errors. | Report/build models only. | gap — req-05,09 |
| 3.10 | SlotMap graph model with fresh IDs, generation retirement, checked lexical access. | Not implemented end to end. | gap — req-06 |
| 3.11 | Universal `with`, abort/exit, restoration obligations, deterministic cleanup DAG and all normal/abnormal teardown paths. | Not implemented end to end. | gap — req-05,10 |

## Chapter 04 — Actors and async

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 4.1–4.2 | Actor roots/typed handles and legal fixed-layout payloads; handles remain image-wired. | Initial actor call/send source-to-native verticals. | partial — req-03 |
| 4.3, 4.3.1 | Non-reentrant turns and concrete unified wait graph including resources/producers; driver handlers never self-wait. | General recurring turns and wait graph absent. | gap — req-03,07 |
| 4.3.2 | One-way `send`/`try send`, reserve-before-evaluation, arm-sensitive ownership, restart capacity/FIFO. | `actor_one_way_send_vertical.rs` and diagnostics test cover a bounded first slice. | partial — req-03,07 |
| 4.3.3–4.3.4 | Observable admission/FIFO/turn/replay semantics and exactly-once typed replies/peer failures/take outcomes. | Initial actor flow model; no recurring failure/runtime proof. | partial — req-03,07,10 |
| 4.4 | Derived finite mailbox/turn bounds and logical-vs-physical reporting. | Build models only. | gap — req-03,09 |
| 4.5–4.5.1 | Ahead-of-time bounded async machines, static tasks, explicit exits, recursion/frame/stack bounds. | General async lowering absent. | gap — req-04 |
| 4.6–4.7 | Suspension legality, consuming awaitables, completions, idempotent wake and mask-arm-recheck park. | Runtime timeout slice is not general async: `runtime_timeout_vertical.rs`. | gap — req-04 |
| 4.8–4.10 | Normative deterministic scheduler, priorities/fairness proof, budgets/checkpoints and inherited deadlines. | No complete runtime scheduler. | gap — req-04 |
| 4.11 | Bounded nursery/structured task creation and teardown. | Not implemented. | gap — req-07 |
| 4.12–4.12.3 | Fresh request lineage, atomic child registration, cancellation cleanup, permit backpressure and sealed race/select. | Not implemented. | gap — req-07 |
| 4.13–4.14 | Device receipt throughput accounting and IRQ/poll idle behavior. | Not implemented end to end. | gap — req-07,08 |
| 4.15 | Single-core APIs remain future-multicore-compatible without providing multicore semantics. | Design constraint; multicore itself is excluded. | partial — req-18 |
| 4.16 | Narrow implemented actor-flow boundary is accurately documented and unsupported paths fail closed. | `actor_flow_vertical.rs`; native emission documented in section. | partial — req-03 (must expand) |

## Chapter 05 — Hardware safety

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 5.1–5.3 | Manifest-minted linear authority, role/effect checking and nonoverlapping typed MMIO with volatile ordering. | Target/runtime ABI models only. | gap — req-08 |
| 5.4–5.5 | Exact DMA/wire layout, transfer vs shared-control memory, pool provenance/coherency/confinement. | Layout structures exist; ownership protocol execution absent. | gap — req-08 |
| 5.6–5.8 | Complete queue reservation, nonwrapping IDs/epochs, protocol ordering and checked Untrusted control values. | Not implemented end to end. | gap — req-08 |
| 5.9–5.11 | Exclusive vector topology/GICv3 route, restricted ISR effects, InterruptCell ordering/masking and stack bounds. | Runtime ABI cross-contract test: `crates/wrela-runtime-abi/tests/cross_contract.rs`; source/effect/runtime completeness absent. | partial — req-08 |
| 5.12–5.14 | Bounded bottom halves, const-generic IRQ/poll/hybrid specialization and typed virtio protocol states. | Not implemented end to end. | gap — req-08 |
| 5.15 | Cancellation transfers receipts to bounded recovery, resets/quiesces, quarantines DMA and reports unknown outcomes. | Not implemented end to end. | gap — req-08,10 |
| 5.16 | Preserve and report residual compiler/target/firmware/hardware TCB. | Documentation present; distribution/report proof incomplete. | partial — req-08,16 |

## Chapter 06 — Comptime and images

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 6.1–6.5 | Typed target-emulated comptime, deterministic/no ambient I/O, finite quotas, safe phase crossing and nonobservable Secret taint. | Bounded scalar/flat-struct evaluator vertical; Secret/general value surface absent. `comptime_unit_vertical.rs`, `comptime_aggregate_vertical.rs`. | partial — req-09 |
| 6.6–6.7 | Complete specialization, direct closed dispatch, graph-changing const configuration and phased hygienic attributes. | Restricted specialization only. | partial — req-09 |
| 6.8–6.9 | Unique typed image construction, graph roles/order/brands/restart provisions and exclusive capability minting. | Image/build models exist; complete source construction/runtime boot absent. | partial — req-09 |
| 6.10 phases 1–3 | Parse/collect, resolve/type comptime, evaluate image root under quotas. | Implemented for bounded subsets. | partial — req-09 |
| 6.10 phases 4–6 | Fixed-point specialized checking, graph invariant closure and exact resource inference. | Models/subsets only. | gap — req-09 |
| 6.10 phases 7–9 | Seal SW, optimize verified FW, lower MW/layout/report, read-only assertions, emit/link/reconcile. | Pipeline exists for selected verticals; general semantic and report reconciliation absent. | partial — req-09,15 |
| 6.11 | Content-addressed comptime caching with identical diagnostics and no unstable host input. | Cache tests: `artifact_cache_reuse.rs`, `change_set_reuse.rs`, `incremental_session.rs`; general evaluator equivalence incomplete. | partial — req-09,17 |
| 6.12.1 | Genuine bounded source `@test comptime fn`, exact-limit/cancellation diagnostics and canonical CLI reports for the documented subset. | `comptime_unit_vertical.rs`, CLI/test-model infrastructure. | partial — section itself explicitly narrows delivery; req-13 expands it |
| 6.12.2 | Generated bounded runtime/image test harness, protocol and pinned target execution. | Test protocol/runner and QEMU smoke exist; general source tests absent. | partial — req-13,14 |
| 6.13 | Deterministic ARM64 PE32+ EFI, exact UEFI transition/runtime entry and artifact/report match. | Native/link/test runner slices exist; complete current-tuple proof absent. | partial — req-15 |
| 6.14 | Atomic compiler/target/library contract and exact target rejection. | Toolchain/target crates and contract fixtures. | partial — req-15,16 |

## Chapter 07 — Faults and reliability

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 7.1–7.4 | Exact failure taxonomy, Result/task/async values, uncatchable abandonment and build-time assertions. | Restricted Result and assertions only. | partial — req-06,10 |
| 7.5–7.7 | Complete supervision tree, bounded restart intensity, zero-allocation teardown/provisioning and partial-state recovery. | Build models only; runtime absent. | gap — req-10 |
| 7.8 | Reset outcome precision and sibling invalidation. | Not implemented. | gap — req-10 |
| 7.9–7.9.2 | Optional advertised record/replay logs every nondeterministic input/injection/output, bounded policy and divergence; time-travel is tooling over it. | No complete record/replay profile. | gap — req-10 |
| 7.10 | Sealed A/B deployment and versioned persistent migrations; no hot/runtime installation. | Distribution/update proof absent. | gap — req-10,16 |
| 7.11 | Required executable checks/proofs without claiming a general user proof language. | Individual validators exist; complete protocol proofs absent. | partial — req-08,09 |

## Chapter 08 — Build contract

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 8.1–8.2.1 | Fail-closed source/type/image closure and initialization/copy/move/error conversion proofs. | Implemented for bounded subsets only. | partial — req-02,06,09 |
| 8.2.2 | Complete access/view/region/bounds/linear cleanup proof. | Missing general implementation. | gap — req-05 |
| 8.2.3 | Complete actor/async capacity, ordering, wait, receipt, request, checkpoint and priority proof. | Initial actor send slice only. | gap — req-03,04,07 |
| 8.2.4 | Complete hardware provenance/layout/queue/untrusted/cancellation proof. | Missing general implementation. | gap — req-08 |
| 8.2.5 | Concrete specialization, verified WIR transformations, exact placement and emitted/report reconciliation. | Selected verticals only. | partial — req-09,15 |
| 8.3 | Machine/readable report contains every listed compiler/input/reachability/memory/actor/async/device/recovery/artifact fact. | `wrela-image-report` exists; required schema is incomplete. | gap — req-09,13 |
| 8.4–8.4.9 | Stable source diagnostics with facts/why paths/repairs for every illustrated category. | Diagnostics infrastructure and selected snapshots; full category coverage absent. | partial — req-13 |
| 8.5 | Tooling exposes all inferred effects and advisory performance shapes. | Partial reports; no complete expanded-effects surface. | gap — req-13 |
| 8.6–8.7 | Byte reproducibility and immutable safety rules across exact build profiles. | Determinism tests exist for slices; full artifacts/distribution unproven. | partial — req-17 |
| 8.8 items 1–8 | Grammar/evaluation/arithmetic/copy/view/carrier/brand conformance corpus. | Scattered subset tests; matrix incomplete. | gap — req-14 |
| 8.8 items 9–17 | Nonwrap cleanup/actors/receipts/wait/requests/capacities/wake/checkpoint corpus. | Initial send/timeout tests only. | gap — req-14 |
| 8.8 items 18–25 | IRQ/poll/vector/ISR/virtio/DMA/reset/wire corpus. | Runtime ABI contract only. | gap — req-14 |
| 8.8 items 26–33 | Comptime/secret/supervision/UEFI/replay/optimization/Unicode/frame/mailbox corpus. | Comptime/cache and some native tests only. | gap — req-14 |
| 8.8 items 34–36 | Report reconciliation, all test modes/protocol failures, ARM64 COFF inspection and pinned QEMU boot. | QEMU smoke/native lanes exist but complete feature corpus absent. | partial — req-14,15 |
| 8.9 | Performance claims require named measured compiler/target/workload and never substitute for semantic proof. | Documentation constraint. | verified — req-13 maintains |
| 8.10 | Conformance requires every applicable chapter 01–10 obligation, not modeled/parsed support. | This inventory records current nonconformance. | verified — documentation |

## Chapter 09 — Optimization model

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 9.1–9.2 | As-if optimization through distinct verified SW/FW/MW boundaries; UB-bearing backend facts trace to proofs. | Crate boundaries/validators exist for selected operations. | partial — req-15,18 |
| 9.3 | Closed-world monomorphization/dispatch/config/DCE and reproducible declared guidance without optimization-dependent safety. | Selected verticals only. | partial — req-09,15 |
| 9.4 | Actor fast paths preserve all nine listed logical admission/scheduling/cancellation/fault/replay properties. | No equivalence suite for general actors. | gap — req-03,17 |
| 9.5 | Generated static scheduler may specialize representation while preserving ISR/device boundaries. | Runtime incomplete. | gap — req-03,04 |
| 9.6 | State-sensitive async frame/continuation optimization preserves cleanup and reports source mapping. | General async absent. | gap — req-04 |
| 9.7 | Ownership-driven optimization and removed checks require FW proof; shifts and hardware effects lower without LLVM UB. | Checked shift vertical exercises a bounded subset. | partial — req-02,15 |
| 9.8 | Physical memory planning preserves logical capacity and proves all overlap across failure paths. | Models only. | gap — req-09 |
| 9.9 | Reports expose logical/physical decisions, proof-backed removed checks and performance diagnostics. | Incomplete report surface. | gap — req-13 |
| 9.10 | Numerical claims require named reproducible benchmark boundary. | Documentation constraint. | verified — req-13 maintains |

## Chapter 10 — Standard library contracts

| Spec | Contract inventory | Layers/evidence | Status / delivery owner |
|---|---|---|---|
| 10.1 | Alternative implementations preserve exact typed effects/bounds/events/diagnostics with no hidden behavior. | Architecture policy; complete library absent. | partial — req-11 |
| 10.2 | General Option/Result payload ownership, projection carriers, `?`, unique From and mut Option take. | Restricted `Result[S,S]` only; `runtime_result_vertical.rs`, `std/core/result.wr`. | partial — req-06 |
| 10.3 | Image-wired Actor/Static and exactly-once typed calls/admission/peer failure/ownership-conditioned outcomes. | Initial actor send/call vertical only. | partial — req-03,07,11 |
| 10.4 | Completion, transfer/IO receipts, receipt handoff and request lineage implement strict exactly-once recovery. | Not implemented end to end. | gap — req-07,11 |
| 10.5 | Complete Duration/Instant/now semantics including record/replay and checked APIs. | Function-based Duration subset: `stdlib_time_scalar.rs`, `stdlib_time_runtime_vertical.rs`, `std/core/time.wr`; section documents missing surfaces. | partial — req-11 |
| 10.6 | Static task identities, explicit AsyncExit, idempotent wake and supervised TaskFailed. | Not implemented generally. | gap — req-04,11 |
| 10.7 | Bounded nurseries/joins and capacity-proved race with complete loser teardown. | Not implemented. | gap — req-07,11 |
| 10.8 | Fixed arrays/List/SlotMap exact capacities, ownership iteration, fresh IDs/generations and exhaustion. | Not implemented generally. | gap — req-06,11 |
| 10.9–10.9.1 | Bounded formatting/Secret/panic plus validated external formats and exact wire decoding. | Not implemented generally. | gap — req-11 |
| 10.10 | InterruptCell/MMIO/DMA/VirtQueue sealed contracts preserve authority/order/ownership/recovery. | Runtime ABI fragments only. | gap — req-08,11 |
| 10.11 | Image/request/nursery/pool semantic intrinsics preserve exact graph/generativity/cleanup contracts. | Build models only. | gap — req-09,11 |

## Normative exclusion ledger

These are the only revision-boundary exclusions. A missing implementation from
the tables above remains a gap even if it is difficult or scheduled later.

| Exclusion | Normative citation |
|---|---|
| Multicore execution; shared-memory concurrency; app-visible atomics | 01 §8 (04 §15 only preserves future API compatibility) |
| Dynamic application installation/loading, JIT/runtime code generation, runtime reflection/dynamic dispatch/`dyn` | 01 §§2,8; 06 §6 |
| Tracing garbage collection and ambient/unbounded heap allocation | 01 §8; 03 §9 |
| General unsafe blocks and general FFI | 01 §6 |
| Shared legacy PCI INTx | 01 §8; 05 §9 |
| Arbitrary privileged/top-half ISR escape hatches and ISR nesting on the advertised profile | 01 §8; 05 §11 |
| Install-time verified bytecode and hot in-memory migration | 01 §8; 07 §10 |
| Hex floating literals; multiline/raw literals | 02 §1 |
| Rest/slice patterns | 02 §3.4 |
| Interface specialization, negative impls and overlapping blanket impls | 02 §3.5 |
| Variadics/runtime keyword-argument collections | 02 §4 |
| Runtime-indexed fixed-array `take`; loop `else`; labeled `break` | 02 §§6–7 |
| Arbitrary AST macros | 06 §7 |
| General session-type language | 05 §14 |
| General user-facing design-by-contract/proof language | 07 §11 |
| CST and LSP (product objective; syntax remains a lossless typed AST) | `crates/README.md` and project scope; neither is promised by chapters 01–10 |
| Targets other than `aarch64-qemu-virt-uefi` | 02 §2.1 fixes the only accepted full-image target for revision 0.1 |

## Known unsupported-path register

Every non-exclusion gap is visible in the chapter tables. The highest-risk
accepted-but-not-executed boundaries are tracked explicitly here so a parser or
model cannot be mistaken for language support:

1. General functions/CFG/ABI and aggregate memory execution are not complete
   beyond the named scalar, flat-structure, enum/Result and time verticals.
2. Actors do not yet provide the recurring bounded cross-actor runtime,
   non-reentrant scheduler, complete replies, requests or wait graph.
3. General async state machines, ownership/views/regions/cleanup, hardware
   protocols, recovery/supervision and record/replay are absent end to end.
4. `Option`, general `Result[T,E]`, bounded collections, formatting and most
   standard-library contracts remain incomplete.
5. Image closure/resource proofs/report reconciliation and the reference virtio
   storage appliance do not yet prove the complete target profile.
6. Existing native COFF/QEMU tests prove only their named narrow tuples; they do
   not establish chapter-wide runtime conformance or an installed offline
   distribution.

Until the corresponding row becomes `verified`, unsupported source must be
rejected by the owning phase with a stable source-aware diagnostic. Deleting a
rejection to make a fixture parse is not progress on that row.
