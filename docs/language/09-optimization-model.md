# Optimization model

## 1. Purpose

wrela exposes more closed-world information than a separately compiled systems
language: the runtime graph, actor set, task bounds, message layouts, target
features, device topology, regions, and all reachable code are known before the
image is emitted. A conforming compiler SHOULD exploit that information.

Optimization is governed by an as-if rule. The emitted image may use any
representation that preserves the normative source semantics, build-time
proofs, observable scheduling contracts, and required diagnostics. Performance
is not itself a license to weaken ownership, cancellation, DMA, ISR, fault, or
capacity rules.

## 2. Verified whole-image representations

The compiler uses three named whole-image representations. They are not
interchangeable and a successful value at one boundary cannot be substituted
for another.

`SemanticWir` is the first representation after successful semantic analysis.
It is fully specialized and syntax-free, but retains structured language
operations, types, effects, linearity, image topology, regions/scopes, actors,
async/tasks, hardware transitions, tests, and proof records.

`FlowWir` lowers SemanticWir into target-layout-independent typed SSA. It is the
only serialized frontend/backend IR and retains:

- concrete actor identities and logical message admissions;
- ownership, access, region, and DMA states;
- suspension, wake, cancellation, cleanup-DAG, and unified wait-for edges;
- mailbox, task, request, and pool capacity uses;
- priorities, deadlines, semantic checkpoints, and uninterrupted-work bounds;
- abandonment attribution and supervisor actions; and
- target effects, typed MMIO operations, fences, and interrupt transitions.

Safety and capacity validation operates on SemanticWir and FlowWir, not on
patterns guessed from backend IR. Each transformation that changes control
flow, ownership placement, frame storage, actor dispatch, or check placement
MUST leave enough proof information for the FlowWir verifier to re-establish
the affected invariants. Ordinary optimization remains in FlowWir; an
intermediate representation is not renamed for each optimization pass.

`MachineWir` is created only after FlowWir optimization. It fixes the AArch64
ABI, data layout, sections, symbols, stack/frame slots, runtime intrinsic calls,
memory semantics, and every undefined-behavior-bearing backend fact. LLVM may
translate MachineWir and perform backend peepholes, but it is not another
language-semantic lowering phase.

The backend may receive additional proven facts such as alignment, non-aliasing,
value ranges, and unreachable branches. It MUST NOT invent LLVM `noalias`,
`inbounds`, non-null, alignment, overflow, or similar undefined-behavior-bearing
claims from naming conventions or optimistic inference. Every such fact traces
through a MachineWir proof to a FlowWir/semantic proof.

## 3. Closed-world specialization

Before target code generation, the compiler SHOULD perform:

- monomorphization of reachable generic instantiations;
- concrete resolution of every interface call;
- constant propagation from image and target configuration;
- removal of unreachable comptime branches and unused target paths;
- whole-image inlining and dead code/data elimination;
- specialization for exact target-owned CPU features and declared device modes;
- scalar replacement, loop simplification, and proved bounds-check elimination;
  and
- hot/cold code and data placement when declared profile guidance supports it.

The target package's exact CPU/features and every profile-guidance input are
part of the image build contract. They are hashed, reported, and reproducible.
Runtime device probing may select only among variants that were declared and
bounded in the sealed image; it cannot change the compiler's CPU ABI or
register-reservation contract.

Optimization cannot be required to discover a safety bound that the semantic
analysis lacks. For example, optional tail-call elimination does not make
unbounded recursion legal. A deterministic state-sensitive frame or mailbox
layout performed before the image report may, however, determine the artifact's
physical footprint and is then a required, verified part of that build.

## 4. Actor as-if rule

An actor call through a different actor handle always creates a logical actor
edge. Its admission is reserved before ordinary argument evaluation; rejection
evaluates no argument. Its message is admitted under the receiver's capacity and ordering rules,
the receiver owns one non-reentrant turn, and its reply or fault follows the
same cancellation and supervision path regardless of physical lowering.

Subject to those rules, the compiler MAY use:

- direct placement into a statically known receiver slot;
- a small actor or method ID and a specialized jump table;
- direct dispatch when the receiver is the scheduler's legal next actor;
- a direct reply write into the waiting caller frame;
- tail-continuation forwarding when a caller only returns an awaited result;
- code fusion across actor handlers whose intervening admission is
  unobservable; and
- a specialized mailbox representation rather than one homogeneous ring.

Direct dispatch is not ordinary reentrant calling. The logical receiver turn
must still be admitted in order, the sender cannot retain access to moved
values, and no other external turn may enter the receiver until that turn ends.

Handler fusion or continuation forwarding MUST preserve:

1. logical mailbox admission and backpressure;
2. reservation-before-argument evaluation and atomic move/commit;
3. message selection order;
4. actor non-reentrancy;
5. priority, deadline inheritance, and the scheduler's legal next-work choice;
6. checkpoint and uninterrupted-work bounds;
7. cancellation observation and loser teardown;
8. abandonment attribution and supervisor behavior; and
9. deterministic record/replay events.

If any condition is unproved, the compiler uses the ordinary bounded enqueue
and scheduler path. Source correctness cannot rely on fusion occurring.

## 5. Generated scheduler

The sealed image does not require a general-purpose executor. The compiler and
standard runtime MAY synthesize:

- dense static task and actor IDs;
- ready bitsets and precomputed priority masks;
- direct wake targets into known frame slots;
- separate small queues for priority bands;
- specialized IRQ, poll, or hybrid paths after comptime selection;
- batched device completion draining; and
- level-triggered wake coalescing where the source operation explicitly has
  level rather than event semantics.

Ordinary actor work on the single application core does not require atomic
read-modify-write instructions. State shared with an ISR, device, or firmware
boundary retains the target-defined volatile, interrupt, cache, and fence
semantics. The optimizer cannot move ordinary memory access across those
boundaries without a target proof.

## 6. Async frames and continuations

The compiler computes liveness separately at every suspension state. It SHOULD:

- omit values dead before suspension;
- color non-overlapping values into shared frame storage;
- use a tagged union rather than the sum of all state-local storage;
- scalar-replace aggregates and erase proof-only zero-sized values;
- recompute cheap pure expressions when storing them costs more;
- reuse a caller frame for a legal tail await;
- forward a continuation past an actor that only returns a dependency result;
  and
- compile statically known cleanup into compact state-specific actions.

Recomputation cannot duplicate effects, traps, volatile access, secret access,
or work that violates a declared budget. Storage overlay cannot join values
that may be live simultaneously, including during cancellation, abandonment,
or supervisor teardown. Debug information and the image report map physical
storage back to source values and suspension states.

## 7. Ownership and check optimization

The ownership model can prove facts useful to native code generation:

- `mut` and `mut view` establish lexical exclusivity;
- an `iso[P]` region has one owner, retains pool provenance, and moves without
  copying its payload;
- actor state is accessible only to its current turn and checked ISR paths;
- region and pool allocation provide known bounds and alignment; and
- device-owned DMA payloads are inaccessible to CPU code until completion or
  reset returns ownership.

The compiler SHOULD use these facts for scalar replacement, vectorization,
load/store forwarding, check hoisting, and alias analysis. It may eliminate a
bounds, generation, capacity, or arithmetic check only when FlowWir proves the
failure case unreachable under the selected profile. Device-derived values are
validated at their trust boundary; a validated range may then flow through FlowWir
without redundant checks.

Typed MMIO, device-shared memory, `InterruptCell` publication, and DMA ownership
transitions constrain optimization. A safe-language alias proof does not permit
the backend to erase a required hardware observation or barrier.

## 8. Static memory planning

Logical capacity and physical storage are distinct. The compiler MAY:

- use an ordering ring with exact-size per-method payload banks;
- allocate dedicated lanes for senders with statically disjoint bounds;
- overlay task, request, or scratch storage with proved non-overlapping
  lifetimes;
- place hot actor fields separately from cold supervision metadata;
- keep large transferred payloads in branded `iso` pools while messages carry
  handles;
  and
- remove backing for target branches eliminated by comptime.

It MUST NOT overlay storage merely because tasks usually do not overlap; mutual
exclusion must be proved for completion, cancellation, abandonment, restart,
and interrupt paths. Alignment padding, page tables, IOMMU tables, relocation
data, boot scratch, and retained target allocations remain part of footprint
accounting rather than disappearing as linker or target overhead.

## 9. Tooling and performance diagnostics

Optimization must not make the source model opaque. Expanded source, language
server metadata, and the image report identify:

- every logical actor edge and whether it was queued, direct-dispatched,
  continuation-forwarded, or fused;
- logical mailbox capacities and physical bytes by message kind;
- copied payload bytes and moved `iso` handles;
- frame fields by suspension state and physical storage overlay;
- removed checks and the proof that discharged them;
- semantic checkpoints and any proved as-if elisions;
- specialization-driven code growth and eliminated target paths; and
- target/runtime memory outside ordinary language regions.

The compiler SHOULD warn about a cross-actor call repeated in a hot bounded
loop, a large copied message, a value that inflates many frame slots, excessive
largest-variant mailbox padding, or specialization whose code growth exceeds a
profile threshold. The diagnostic suggests batching, moving an `iso` value,
coarsening an actor boundary, sharding a bottleneck, or narrowing a live range.

These diagnostics preserve the ergonomic actor surface while making its cost
visible. An optimization report is explanatory; programmers do not need to
rewrite source into physical message structs or executor operations.

## 10. Measurement boundary

The structural design permits direct calls, allocation-free state machines,
static scheduling, arena reset, zero-copy ownership transfer, and aggressive
whole-image specialization. It does not establish a numerical performance
claim.

Throughput, latency, code size, boot time, and memory comparisons require a
named compiler revision, target CPU and firmware, build profile, device mode,
workload, and measurement method. Profile-guided optimization results name and
hash their training workload. A compiler may advertise structural facts from
the image report without presenting them as benchmark results.
