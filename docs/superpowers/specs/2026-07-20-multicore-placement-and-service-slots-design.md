# Multicore static placement and the service slot idiom

**Status:** design specification draft, targeting revision 0.1
**Date:** 2026-07-20
**Depends on:** docs/language/01-foundations.md, 04-actors-and-async.md,
05-hardware-safety.md, 07-faults-and-reliability.md, design-decisions.md

## 1. Problem statement

Revision 0.1 currently carries two related unresolved items:

1. **Service head-of-line (HOL) blocking is a documented open problem.**
   A non-reentrant `@service` that holds its turn across an I/O `await`
   serializes all clients (the Orleans lesson). The design-decisions ledger
   deliberately leaves interleaving mechanisms unspecified, requiring only
   head-of-line diagnostics. Shipping 0.1 with this as folklore means the
   first multi-client appliance invents ad-hoc patterns that become de facto
   language.

2. **Multicore compatibility is a tracked bet, not a design.**
   Chapter 01 §8 states that actor/message semantics, `iso` transfer, and
   per-vector IRQ ownership are *chosen to make it plausible* that a future
   per-core scheduler would not change application APIs, and names its
   falsifier: a written 2-core semantic sketch validating non-reentrancy and
   deterministic replay. That sketch does not exist.

This document resolves both with one design move, adding **zero new
user-facing concepts** against the standing concept budget.

## 2. Design thesis

Wrela's identity is: *the closed world turns runtime questions into
build-time facts.* Applied here:

> **The actor is simultaneously the unit of mutual exclusion, fault
> isolation, and physical placement.** Cores are a property of the image
> graph — assigned at build time like pools, mailboxes, and IRQ vectors —
> not a runtime scheduling concern.

Three consequences, each detailed below:

1. Non-reentrant turns remain unconditional (§3).
2. In-service concurrency comes from ending turns early via bounded slots
   and receipts — the canonical HOL answer (§4).
3. Multicore is static actor-to-core placement with compiler-generated
   bounded cross-core rings; no migration, no work stealing (§5).

## 3. Non-reentrancy is unconditional

Chapter 04's rule is unchanged and now explicitly load-bearing for
multicore: **while an actor turn is live, including across `await`, no new
external message is admitted into that actor.**

Rationale (non-normative): the actor-as-lock rule is the only mutual
exclusion mechanism that behaves identically on one core and N cores without
app-visible atomics, which chapter 01 §8 forbids. Softening it for services
would introduce a second synchronization vocabulary precisely when the model
must scale to parallel execution. Reentrancy is not reintroduced as an
optimization or a service-tier exception.

## 4. The service slot idiom (canonical HOL answer)

### 4.1 The rule

A `@service` that performs I/O on behalf of multiple clients SHOULD NOT hold
its turn across the I/O `await`. Instead it:

1. **Admits** the request in a short turn: validate arguments, reserve one
   slot in a bounded, actor-owned in-flight table (`SlotMap[State, ..N]` or
   equivalent), acquire buffers from its pool.
2. **Submits** to the downstream driver, receiving a sealed `Receipt[P]`
   (chapter 04 §13–14, unchanged).
3. **Ends the turn** by awaiting resolution *through the slot*, releasing
   `self` for the next client turn. Completion arrives as a later turn that
   resolves the slot and the caller's reply.

```wrela
@service
pub struct Storage:
    inflight: SlotMap[ReadState, ..16]
    pool: IsoPool[Payloads, ..16]
    disk: Actor[BlkDriver]

    pub async fn read(mut self, lba: u64) -> Result[Static[Bytes], IoError]:
        slot = self.inflight.reserve()?
        buffer = self.pool.get()?
        receipt = self.disk.submit_read(lba=lba, buffer=take buffer)
        return await slot.resolve(take receipt)
```

The client experience is unchanged: one `await`, a pure-value result (the
"option A" public API shape). Internally, up to `N` requests overlap. Each
turn on `self` remains atomic; the mutable structures (cache, in-flight
table, pool) are touched only in short non-awaiting sections.

### 4.2 What is new, and what is not

Nothing in §4.1 requires new language surface. `Receipt[P]`, bounded
`SlotMap`, `IsoPool`, and reply resolution already exist in chapters 03, 04,
and 10. This design:

- **Blesses** the pattern as the normative answer to the chapter 04
  open-problem subsection, replacing "deliberately unspecified" with "the
  slot idiom is the specified mechanism; sharding remains available for
  state partitioning."
- **Requires** stdlib support so the idiom is one line, not a protocol the
  user reinvents: `slot.resolve(take receipt)` is a sealed stdlib contract
  that (a) parks the caller's reply on the slot, (b) ends the service turn,
  and (c) wires the receipt's completion to a generated internal turn that
  fills the slot and resolves the reply. Its exact chapter 10 contract is an
  implementation-plan work item. This is the one point where a caller's
  reply outlives the originating service turn; it does not contradict §3
  because the turn *ends* rather than suspends — the same shape
  `@receipt_handoff` already gives drivers (return a receipt promptly,
  complete in a later turn).
- **Keeps** the head-of-line diagnostic requirement: the compiler/report
  still flags a service turn that awaits a dependency while its mailbox has
  queue-behind latency, and the diagnostic's suggested repair is this idiom.

### 4.3 Wait-for graph interaction

The slot idiom is compatible with the unified wait-for graph: the service
turn that admits and submits does not hold-and-wait (it ends); the slot is a
resource node whose producer edge is the driver's completion/recovery lane,
which is already how receipts participate in the graph. No new node or edge
kinds are introduced.

## 5. Multicore: static placement

### 5.1 Placement model

- Every actor receives exactly one core assignment at build time. Placement is
  an `@image` build fact, not a language concept, on the same footing as
  profiles and pool sizing. A manifest assignment fixes that actor's core;
  all other actors are placed by the deterministic inference in chapter 04
  §15.1.
- The inference uses the sealed report facts for maximum uninterrupted work
  and total reserved actor/mailbox/frame/pool bytes. After applying explicit
  assignments, it orders remaining actors by descending work, descending
  bytes, then canonical actor identity, and assigns each to the eligible core
  with the lexicographically smallest resulting `(work, bytes)` totals (lower
  core index breaks ties). Revision 0.1's single-core target consequently
  infers core 0 for every unassigned actor; a target package with cores > 1
  makes the bin pack meaningful.
- There is **no actor migration and no work stealing**. Load imbalance is a
  build-time report. The report records inferred-versus-explicit provenance,
  every actor's input totals, the final table, and per-core totals. An explicit
  assignment overrides one result without disabling inference for the other
  actors — the same philosophy as `@no_promote` and promotion reporting.

### 5.2 Execution model

- **Each core runs the existing single-core cooperative scheduler,
  unchanged.** All chapter 04 semantics (admission, ordering, turns,
  checkpoints, deadlines, cancellation) are per-core facts.
- A **same-core actor edge** keeps today's semantics and today's as-if fast
  paths (direct dispatch, elided rings).
- A **cross-core actor edge** is the same typed logical message channel,
  lowered by the compiler to a **generated bounded SPSC ring** between the
  two cores. Because the actor topology and both endpoints' cores are closed
  build-time facts, the compiler generates exactly the rings the image
  needs: no locks, no MPMC queues, no dynamic routing tables.
- Ring publication/acquire ordering is sealed inside the generated ring
  operations, exactly as virtio ring ordering is sealed inside typed
  standard-library operations (chapter 05). Freestanding fences remain
  absent from the public surface. **App-visible atomics remain excluded.**

### 5.3 Payload legality is unchanged

Cross-actor payload rules (chapter 04 §2) already forbid views, `mut`
loans, and shared mutable state; payloads are scalars, explicit copies,
`Static[T]`, moved `iso[P]` values, and sealed linear handles. Because
messages are the only way values cross actors, these are automatically the
only ways values cross cores. **No new user-facing transfer rules.** The
one new obligation is on the compiler: an `iso` move across a cross-core
ring must be published with the ring's release/acquire discipline, which is
internal to the sealed ring ops.

### 5.4 Hardware affinity

- A `@driver`'s interrupt vectors route to the core that hosts the driver
  actor. One vector, one ISR entry, one core.
- DMA pools, queue permits, receipt recovery lanes, and quarantine regions
  live on the driver's core. There is no cross-core hardware state, ever.
- ISR effect rules (chapter 05 §11) are unchanged; the ISR's "wake work"
  action targets its own core's scheduler.

### 5.5 Determinism and replay

The only new nondeterminism multicore introduces is **cross-core admission
interleaving at each mailbox**, because mailboxes are the only meeting
point between cores.

- **Record:** per-mailbox admission order (a bounded per-edge sequence log),
  plus the existing chapter 07 nondeterministic-input log.
- **Replay:** enforce the recorded admission order at each mailbox;
  everything between admissions is already deterministic per-core execution.

This is dramatically cheaper than general shared-memory replay and is the
written 2-core semantic sketch that the chapter 01 bets-register falsifier
demands: non-reentrancy, per-vector IRQ ownership, mailbox ordering, and
record/replay all survive because every rule above is stated per-core or
per-edge.

## 6. Revision 0.1 scope

Split spec from runtime honestly:

1. **Normative now (spec changes):**
   - Chapter 04: replace the open-problem subsection with the service slot
     idiom (§4) as the specified interleaving mechanism; keep the HOL
     diagnostic requirement and point its repair text at the idiom.
   - Chapter 01/04: replace the "tracked bet" hedge with the placement
     model (§5) as normative multicore semantics; the single-core target
     remains the only advertised profile.
   - Chapter 10: add the sealed slot-resolution contract stub with its
     exact-once and ownership-conditioned outcome obligations.
   - Design-decisions ledger: retire the "service reentrancy open problem"
     row and the "multicore will not change APIs" bet (falsifier
     satisfied by this sketch; the remaining falsifier is the vertical
     below).
2. **One implementation vertical (proof, not product):** a 2-core target
   variant running two `@app` actors on core 1 and one `@service` on
   core 0, exercising exactly one cross-core `send`, one cross-core awaited
   call with an `iso` move, and admission-order record/replay verification.
   Small, honest, falsifiable — the analogue of the existing
   `actor_cross_send_vertical`.
3. **Everything else stays single-core** until the reference virtio
   appliance exists. The full multicore runtime (multi-core boot, GIC
   routing for N cores, per-core ISR stacks beyond the vertical's needs) is
   explicitly not a 0.1 runtime claim.

## 7. What this design refuses

| Refused | Why |
|---|---|
| Reentrant services (full or opt-in) | Reintroduces await-time logical corruption; requires a second synchronization vocabulary before parallelism |
| Work stealing / actor migration | Load-balancing tools for open worlds; the closed world makes placement a build-time report + config change |
| App-visible atomics | Chapter 01 §8 exclusion stands; the actor stays the only mutual-exclusion concept |
| MPMC / dynamic routing between cores | The closed edge set makes generated SPSC rings sufficient and provable |
| A `core`/`place` language keyword | Placement is manifest configuration; no concept-budget spend |

## 8. Concept budget accounting

New user-facing concepts introduced: **zero.** Placement is manifest
config; slots/receipts/`SlotMap`/`IsoPool` exist; rings are sealed stdlib.
Retired: one open problem (service interleaving) and one standing bet
(multicore API compatibility). Net budget movement: favorable.

## 9. Falsifiers and open questions

| Item | Falsifier / decision evidence |
|---|---|
| Slot idiom is ergonomic enough to be the only mechanism | The reference virtio appliance's Storage actor under 2+ client load: count contortions and queue-behind-latency incidents |
| Static placement suffices without migration | The same appliance's image report: does any realistic profile need per-load rebalancing that a manifest edit cannot express? |
| Admission-order replay is complete | The 2-core vertical's record/replay run diverges only if an unlogged nondeterminism source exists; any divergence names a spec hole |
| Cross-core ring cost is acceptable | Named measured benchmark on the 2-core vertical (per chapter 08 §9 rules: no unmeasured claims) |
| Slot-resolution stdlib contract shape | Written during implementation planning against chapter 10's exactly-once and ownership-conditioned outcome rules |

## 10. Testing

- **Spec-level:** conformance-inventory rows added for §4 (slot idiom
  contract) and §5 (placement/ring/replay semantics), initially `gap`,
  with the 2-core vertical as their first evidence target.
- **Vertical:** the §6.2 two-core vertical proves cross-core send, iso
  move, admission-order record/replay, and IRQ-affinity wiring for a timer
  or synthetic completion source.
- **Diagnostics:** HOL diagnostic fires on a deliberately turn-holding
  service fixture and its repair text names the slot idiom.
- **Negative:** a manifest placing one actor on two cores, a cross-core
  view/`mut` payload, and an ISR bound to a non-owner core are all build
  errors with stable diagnostics.
