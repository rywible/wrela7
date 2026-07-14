# Standard library contracts

## 1. Purpose and authority

This chapter defines the minimum semantic contracts of standard types whose
behavior is load-bearing for the language invariants. Their implementation may
be ordinary specialized wrela, compiler-generated code, or sealed target code.
Alternative libraries MAY change names and representations only when they
implement the same typed effects, ownership transitions, bounds, scheduling
events, and diagnostics.

The semantic signatures below are exact. A concrete target library may add
compile-time capacity, brand, or target parameters only where this chapter names
them, and tooling MUST display the fully substituted signature. It may not add a
hidden failure, copy, allocation, authority, suspension, or ownership transition.
Proof-only generated parameters have no source value and do not create ambient
allocation or authority.

## 2. `Option`, `Result`, and conversions

`Option[T]` is the closed sum `Some(T) | None`. `Result[T, E]` is
`Ok(T) | Err(E)`. Ownership of a payload follows ordinary enum rules. When a
type argument contains a view leaf, the complete tuple/`Option`/`Result` shape
is the second-class projection carrier defined in
[Values, views, and regions](03-values-views-regions.md): it has no storable
layout and must be consumed immediately.

Postfix `?` on `Result[T, E]` either yields `T` or returns from the enclosing
`Result` function. Errors convert only through a unique whole-image
implementation equivalent to:

```wrela
iface From[Source]:
    fn from(take value: Source) -> Self
```

The implementation is declared with the source-language
`impl From[Source] for Destination` form. The compiler does not search
conversion chains. The conversion is an ordinary specialized call with its
ownership and effects visible. `?` on `Option[T]`
propagates `None` only from an `Option`-returning function. `ok_or(error)` is an
explicit `Option`-to-`Result` conversion and consumes its error argument only on
the `None` path.

For `mut Option[T]`, `take()` returns the prior owned `Option[T]` and writes
`None` before returning. This is a legal runtime-indexed container operation:
the element remains initialized as `None`, so it does not create a dynamic
partially moved place. It is the standard way to move a non-`Copy` payload out
of a runtime-selected slot before later restoring that slot.

## 3. Actor handles and replies

`Actor[T]` identifies one concrete image actor instance and exposes only `T`'s
public actor methods. It is minted by image construction, installed only as an
image-wired field/constructor dependency, and is neither serializable nor legal
inside a message, reply, runtime collection, or mutable input. Numeric actor
IDs and pointer identity are not source-visible.

`Static[T]` is a scalar, copyable, read-only image handle minted only by image
construction or immutable literals. It may appear in messages/replies and lends
`read T` for a call, but cannot expose an address, produce `mut T`, or refer to
runtime-mutable or secret storage.

Every actor request creates a sealed strict single-resolution `ActorCall[T, E]`
awaitable. Calling a public method through `Actor[T]` returns this awaitable
regardless of whether the handler body is synchronous or async. Await consumes
it. The effective results are:

```text
declared R             → Result[R, ActorCallError[Never]]
declared Result[T, E]  → Result[T, ActorCallError[E]]

ActorCallError[E] =
    operation(E)
  | peer_failed(PeerFailed)
  | not_admitted(AdmissionError)
  | cancelled(Cancelled)
  | deadline_exceeded(DeadlineExceeded)
```

`PeerFailed` contains a static actor identity, non-wrapping supervision epoch,
and bounded
failure category. It contains no failed-frame reference, secret payload, or
unbounded formatted text. Abandonment/restart resolves all outstanding replies
from the failed epoch exactly once before reclaiming their slots.

Admission reservation occurs before actor-call argument evaluation. A rejected
reservation therefore moves no argument. Successful commit irrevocably consumes
every `take` argument. No implicit
restoration bundle exists. An API promising return of an input places it in every
success/failure result that preserves it or returns a sealed
`TransferReceipt[P]`.

When a call has a `take` argument, its effective result is a second-class
ownership-conditioned carrier until immediate `?`/`match` consumption:
`not_admitted` leaves every source initialized and every other variant means
they were moved. Match arms must converge linear initialization before joining.
With no `take` argument the result is an ordinary storable `Result`.

Nonblocking one-way admission is sealed expression syntax:

```text
try send actor.method(arguments...) -> AdmissionResult
AdmissionResult = admitted | rejected(AdmissionError)
AdmissionError =
    full | restarting | stale_request | cancelled | deadline_rejected
```

All variants remain in the source type; whole-image optimization may erase
unreachable representations/branches. Reservation failure evaluates no
argument. The success transition evaluates
arguments and consumes their explicit moves atomically with enqueue.
`AdmissionResult` is second-class and must be immediately matched/tested so
definite initialization can refine moved sources in each arm; it cannot be
stored, returned, captured, sent, awaited, or propagated with `?`.

## 4. `Completion`, receipts, and request lineage

`Completion[T]` is a sealed strict-linear, single-resolution awaitable. Awaiting
it consumes it. The producer resolves it once with ownership of `T`; duplicate
resolution is abandonment. Its wake is level-triggered and idempotent.

`TransferReceipt[P]` is a sealed strict-linear state machine. Before its typed
`commit`, rejection/cancellation returns `P`; commit consumes that state and
produces the protocol-specific committed receipt. `IoReceipt[P]` is such a
committed strict completion whose state owns a published device operation,
non-wrapping queue/reset epoch, cleanup dependency, and eventual payload `P`.
Awaiting it consumes it and yields `IoCompletion[P]` with owned `payload: P`
before `status: Result[unit, IoError]` is propagated. Cancellation transfers it
only to the generated driver recovery node; ordinary drop is illegal.

A public synchronous `@driver` method annotated
`@receipt_handoff(input=p)` has a special, compiler-sealed calling convention.
It must take exactly one parameter `take p: P` and declare return type
`IoReceipt[P]`. Admission commit atomically creates a paired receipt state:
the caller owns the `IoReceipt[P]`, while the admitted message owns `P` and its
single-resolution producer. The actor call completes with the caller endpoint
at admission commit, before the handler runs. Within the handler, an expression
of apparent type `IoReceipt[P]` is a second-class producer transition, not a
second caller endpoint: `return queue.publish(...)` commits the existing pair,
and `return queue.reject(payload=take p, ...)` resolves the same pair with
owned payload plus error. The value cannot be stored, copied, sent, or returned
by a nested function. Every normal handler path must perform exactly one such
transition. Abandonment, cancellation, actor failure, or restart before that
transition transfers the producer and payload to the generated supervisor
recovery node, which resolves the caller endpoint. No execution can create a
second receipt, strand `P`, or expose an error before returning ownership.
The annotation is forbidden on non-drivers, async handlers, multiple moved
inputs, mismatched brands/types, and methods whose bodies can finish without a
terminal producer transition.

`RequestContext[R]` is a sealed second-class admission descriptor with
proof-only region brand `R`, request identity/epoch, ancestry, deadline, and
priority. It has no ordinary storable layout and cannot be returned, captured,
formatted, or placed in a message except through an admission operation that
atomically creates a strict child registration before enqueue. Stale, canceled,
and expired admission returns a typed error without consuming other payloads.
`RequestContext[R]` must be supplied as a bare binding so admission may inspect
it before ordinary argument evaluation.
`RequestMetadata` is the separate explicitly copyable bounded diagnostic value;
it carries no admission authority or region brand.

## 5. Time

`Duration` is a nonnegative checked span represented by a target-independent
integer number of nanoseconds in the language model. `ns`, `us`, `ms`,
`seconds`, and larger unit constructors are available at runtime and comptime
when their input is comptime. Construction, addition, and multiplication fail
at comptime on overflow and abandon at runtime unless their checked forms are
used.

`Instant` is an opaque point on the target's monotonic clock. It has total
ordering, supports checked `Instant + Duration`, and subtracts two ordered
instants to `Duration`. It cannot be serialized as a wall-clock timestamp.
Targets must provide a monotonic horizon longer than every declared deadline
and restart-intensity window; wraparound is normalized by the target or the
profile is rejected.

`now() -> Instant` has the sealed monotonic-clock effect. It is available only
to runtime code whose image graph includes that target effect; the compiler
infers and displays the requirement. It is forbidden in comptime and ISR code.
Record mode records every observed value, and replay supplies the recorded
sequence. Wall time is a separate optional capability and is not used for
scheduling, deadlines, or restart intensity.

## 6. Tasks, wake, and task failure

Every local or nursery-installed async activation resolves once with:

```text
declared R             -> Result[R, AsyncExit[Never]]
declared Result[T, E]  -> Result[T, AsyncExit[E]]
AsyncExit[E] =
    operation(E) | cancelled(Cancelled)
  | deadline_rejected(DeadlineRejected)
  | deadline_exceeded(DeadlineExceeded)
```

Awaiting consumes the activation's completion. Actor transport maps these causes
to the corresponding `ActorCallError` variants rather than nesting two error
sums.

Each `@task` method has one or more statically reserved task slots determined by
its declared activation bound. It does not produce a first-class bound method or
storable `TaskHandle`. The expression `Type.task_method` is legal only where a
sealed scheduling operation requires a statically bound task identity.

`wake(Type.task_method)` marks that concrete generated slot ready. In ISR code
the target must be bound to the same driver instance and be in the transitive
ISR wake set. Wake is idempotent and uses the mask–arm–recheck protocol when it
interacts with parking.

An image-installed task returns `unit` or `Result[unit, E]`. `Err(E)` becomes a
bounded owned `TaskFailed[E]` supervisor event after lexical teardown. The image
declares `stop`, `restart_actor`, or `escalate` for that event. Absence of a
policy is a build error; `Err` is never discarded.

## 7. Nurseries, joins, and races

`Nursery[N]` owns at most `N` child activations. `start` consumes or copies its
arguments according to the child signature. Exiting the nursery waits for or
cancels and tears down every child.

For a statically heterogeneous set of children, `join_all` returns a fixed tuple
in start order. Tuple element ownership follows the language tuple rules. A
homogeneous dynamic count returns `List[T, N]` with an explicit maximum.

`race(a, b, ...)` is sealed syntax that build-proves/reserves all child slots
before evaluating or starting any alternative; it is not an ordinary eager
function call. The build rejects a race whose setup capacity is not proved. It
returns a generated closed sum
`RaceN[A, B, ...]` identifying
which alternative won; it cannot return a tuple because only one result exists.
Before returning the winner it cancels every loser, waits for all sealed
recovery completions, and proves that no loser retains a restoration obligation
or quarantined mutable region. Winner selection among simultaneously ready
alternatives uses argument order after the scheduler's recorded readiness set.

## 8. Bounded arrays and collections

`[T; N]` supports constant-index element moves. Runtime-indexed `take` is
forbidden. `for take element in take array` consumes the array as a whole and
visits every element in index order. `map_take` is the sealed whole-array
builder:

```text
[T; N].map_take(fn(take T) -> U) -> [U; N]
[T; N].try_map_take(fn(take T) -> Result[U, E])
    -> Result[[U; N], E]  where T and U are reclaimable
```

`map_take` consumes each input exactly once and is infallible apart from
abandonment in its closure. `try_map_take` tears down constructed outputs in
reverse order and reclaims every remaining input on `Err`; it is therefore
available only when both element classes have compiler-known reclaim actions.
Strict-linear elements require an explicit consuming loop whose error paths name
their protocol-specific cleanup.

`List[T, N]` and `SlotMap[T, N]` never exceed `N`. Construction mints a fresh
non-wrapping map instance ID. `SlotMap.Key` is the explicitly copyable
`(map_id, index, generation)` value. `get` and `get_mut` validate all parts
and return second-class
`Option[view T]`/`Option[mut view T]`. `remove` increments before reuse and
permanently retires a slot rather than wrapping; insertion may return
`GenerationExhausted`. Image-resident instances receive compile-time IDs;
runtime construction draws from a bounded ID pool and may return
`MapIdExhausted` rather than wrapping. Iteration holds the corresponding
lexical access.

## 9. Bounded formatting

Types implementing the static `Format` contract provide a compile-time
`max_formatted_len(spec)` and a writer operation that cannot exceed it. Core
integers, booleans, chars, bounded strings, and closed enums have standard
implementations. User implementations are checked against the declared bound;
exceeding it is abandonment because it violates a proven contract.

`f"...{expression:spec}..."` sums literal bytes and maximum expression lengths
to produce `String[..N]`. A caller may instead write into a supplied bounded
formatter. A dynamically sized shape needs an explicit precision/truncation
bound. `Secret` has no formatting implementation. ISR formatting is forbidden.

`panic` writes through a target-reserved allocation-free formatter with a fixed
profile maximum. A panic expression whose maximum does not fit is a build error,
not an invitation to allocate.

### 9.1 External formats and wire values

`Validated[F, T]` is a sealed owned wrapper minted only by the declared
`FormatValidator[F, T]` operation:

```text
validate(data: Bytes) -> Result[Validated[F, T], F.Error]
Validated[F, T].into_value(take self) -> T
```

The compiler enforces use of the wrapper when an API declares that precondition;
it proves memory/bounds/ownership safety of the validator but does not claim a
theorem that arbitrary user validation matches an external prose format.
Standard validators have independent fixture/conformance obligations.

`Bytes.read_wire[W](offset)` exists only for `@wire W`; it checks the complete
encoded extent and decodes the declared endian/version/layout into an owned
`Result[W, WireError]`. There is no `read_struct` operation for ordinary or
`@dma` structs.

## 10. `InterruptCell`, MMIO, and virtqueues

`InterruptCell[T]` is only for ordinary/ISR-visible state and exposes the operation
set in [Hardware safety](05-hardware-safety.md). RMW methods are
interrupt-atomic and contribute to the masked-interval report when implemented
by masking.

`Mmio[L]`, `iso[P] T` for `@dma T`, `DmaShared[P, L]`, `VirtQueue`, queue permits, prepared
operations, and receipts are sealed protocol types. Their public contracts must
encode the authority partitions, ordering, ownership transitions, complete
descriptor reservation, epochs, untrusted control validation, and deferred
recovery rules of chapter 05. A replacement implementation cannot expose a raw
address, ordinary view of shared control memory, droppable receipt, or
unpartitioned register mapping.

## 11. Construction and scope intrinsics

`Image`, `request`, `nursery`, actor admission, and pool construction are
compiler-recognized semantic intrinsics even when a standard package supplies
their surface declarations.

- `Image(name, target)` is comptime-only and produces one linear
  `ImageBuilder`. Its mutation is deterministic graph construction, not runtime
  allocation.
- `device[D]` produces a proof-only `DeviceDecl[D]`; `driver[A]`,
  `service[A]`, and `app[A]` each produce one proof-only `ActorDecl[A]`.
  Their constructor arguments must exactly match `A.__init__` after generated
  capabilities/handles are substituted.
- `ActorDecl[A].handle()` is legal only as a constructor field/dependency in the
  same image and only when chapter 01's role graph permits that edge. In
  particular an app handle is never installed as another actor's dependency. It
  installs the runtime `Actor[A]` identity and is not a comptime escape into
  baked bytes.
- `iso_pool[T](brand=P, slots=N, max_payload=B)` and
  `dma_payloads[T](brand=P, device=D, count=N)` bind previously unbound source
  brand `P` exactly once, reserve exact backing, and create the declared initial
  handles. The DMA form additionally requires `@dma T` and device reachability.
- `supervise` assigns each actor/task exactly one parent and bounded policy;
  `check_layout` registers a read-only post-layout assertion.
- `seal(take builder)` succeeds only after every declaration is fully bound and
  returns the sole `Image`; any incomplete, duplicate, cyclic construction, or
  unused strict declaration is a build error.
- `request(...)` is a suspend-safe scope that mints `RequestContext[R]` and a
  bounded request region for fresh `R`; `nursery(capacity=N)` is a suspend-safe
  scope owning exactly `N` child slots. Their cleanup contracts are chapters 03
  and 04, not replaceable destructor conventions.

An alternative standard library may rename wrappers around these intrinsics but
cannot alter their graph nodes, generativity, phase, access effects, failure
points, or cleanup/wait-for edges.
