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

## 2. Prelude

Revision 0.1 fixes one always-in-scope prelude: `Option`, `Some`, `None`,
`Result`, `Ok`, `Err`, and `panic`. These names resolve without an import in
every module. An explicit declaration or `from`/`import` in the same module
MAY shadow a prelude name for that module; shadowing is ordinary name
resolution, not a language exception. Every other standard name — including
every type named later in this chapter — MUST be imported explicitly. A
standard library MAY grow, but it cannot enlarge this fixed set without a
language revision.

## 3. `Option`, `Result`, and conversions

`Option[T]` is the closed sum `Some(T) | None`. `Result[T, E]` is
`Ok(T) | Err(E)`. Ownership of a payload follows ordinary enum rules. When the
type argument is a view leaf, the `Option`/`Result` shape is the second-class
projection carrier defined in
[Values, views, and regions](03-values-views-regions.md): it has no storable
layout and must be consumed immediately.

Postfix `?` on `Result[T, E]` either yields `T` or returns from the enclosing
`Result` function. Errors convert only through a unique whole-image
implementation equivalent to:

```wrela
interface From[Source]:
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

## 4. Actor handles and replies

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
declared R             → Result[R, ActorCallError[never]]
declared Result[T, E]  → Result[T, ActorCallError[E]]

ActorCallError[E] =
    Exit(AsyncExit[E])
  | PeerFailed(PeerFailed)
  | NotAdmitted(AdmissionError)
```

`ActorCallError` composes the task/async exit sum defined in §7 rather than
duplicating its `Operation`/`Cancelled`/`DeadlineRejected`/`DeadlineExceeded`
variants.

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
`Receipt[P]`.

When a call has a `take` argument, its effective result is a second-class
ownership-conditioned carrier until immediate `?`/`match` consumption:
`NotAdmitted` leaves every source initialized and every other variant means
they were moved. Match arms must converge linear initialization before joining.
With no `take` argument the result is an ordinary storable `Result`.

Nonblocking one-way admission is sealed expression syntax:

```text
try send actor.method(arguments...) -> AdmissionResult
AdmissionResult = Admitted | Rejected(AdmissionError)
AdmissionError =
    Full | Restarting | StaleRequest | Cancelled | DeadlineRejected
```

All variants remain in the source type; whole-image optimization may erase
unreachable representations/branches. Reservation failure evaluates no
argument. The success transition evaluates
arguments and consumes their explicit moves atomically with enqueue.
`AdmissionResult` is second-class and must be immediately matched/tested so
definite initialization can refine moved sources in each arm; it cannot be
stored, returned, captured, sent, awaited, or propagated with `?`.

A source brand's public spelling may use the actor-associated alias form
`iso[Owner.Brand]` — for example `iso[Storage.Payloads]` — where `Owner` is the
actor whose image wiring declared the brand and `Brand` is the brand name
itself. The alias denotes the identical proof-only brand as the bare
identifier (§12); it exists so a signature reads which actor's pool a handle
belongs to, not to create a second identity or an implicit coercion.

## 5. `Completion`, receipts, and request lineage

`Completion[T]` is a sealed strict-linear, single-resolution awaitable. Awaiting
it consumes it. The producer resolves it once with ownership of `T`; duplicate
resolution is abandonment. Its wake is level-triggered and idempotent.

`Receipt[P]` is the single sealed strict-linear receipt state machine for
protocols requiring recovery after publication; it replaces the former
separate `TransferReceipt[P]`/`IoReceipt[P]` split with one state machine:

```text
Receipt[P] =
    Submitted
  | Committed
  | Resolved(payload: P)
  | Recovery
```

Before the typed `commit` boundary, rejection or cancellation resolves
`Submitted` directly to `Resolved(payload: P)`, returning ownership of `P`. A
successful `commit` instead advances `Submitted` to `Committed`, the
protocol-specific state that owns a published device operation, non-wrapping
queue/reset epoch, cleanup dependency, and the eventual payload `P`. Awaiting a
`Committed` receipt consumes it and yields `IoCompletion[P]` with owned
`payload: P` before `status: Result[unit, IoError]` is propagated.
Cancellation of a `Committed` receipt transfers it only to the generated
driver recovery node, reaching `Recovery`; ordinary drop is illegal in every
state. `Recovery` resolves the caller's original endpoint exactly once with
recovered ownership of `P`. The compiler verifies the receipt implementation,
not an implicit whole-program value-tracing promise.

A public synchronous `@driver` method annotated
`@receipt_handoff(input=p)` has a special, compiler-sealed calling convention.
It must take exactly one parameter `take p: P` and declare return type
`Receipt[P]`. Admission commit atomically creates a paired receipt state:
the caller owns the `Receipt[P]`, while the admitted message owns `P` and its
single-resolution producer. The actor call completes with the caller endpoint
at admission commit, before the handler runs. Within the handler, an expression
of apparent type `Receipt[P]` is a second-class producer transition, not a
second caller endpoint: `return queue.publish(...)` commits the existing pair
(`Submitted -> Committed`), and `return queue.reject(payload=take p, ...)`
resolves the same pair with owned payload plus error
(`Submitted -> Resolved`). The value cannot be stored, copied, sent, or
returned by a nested function. Every normal handler path must perform exactly
one such transition. Abandonment, cancellation, actor failure, or restart
before that transition transfers the producer and payload to the generated
supervisor recovery node (`Recovery`), which resolves the caller endpoint. No
execution can create a second receipt, strand `P`, or expose an error before
returning ownership. The annotation is forbidden on non-drivers, async
handlers, multiple moved inputs, mismatched brands/types, and methods whose
bodies can finish without a terminal producer transition.

`RequestContext[R]` is a sealed second-class admission descriptor with
proof-only region brand `R`, request identity/epoch, ancestry, deadline, and
priority. It has no ordinary storable layout and cannot be returned, captured,
formatted, or placed in a message except through an admission operation that
atomically creates a strict child registration before enqueue. Stale, canceled,
and expired admission returns a typed error without consuming other payloads.

Within the dynamic extent of a `with request(...) as req:` scope,
`RequestContext[R]` is ambient: an ordinary actor call or request-consuming
operation implicitly carries the lexically enclosing request's admission
descriptor without declaring it as a formal parameter. `[region R]` and
`RequestContext[R]` therefore leave an ordinary method signature; only the
scope that mints one (`request(...)`, §12) names it. Code that needs a
*different* lineage than the ambient one overrides it exactly once per call
with an explicit `request=` argument, for example `request=req.context()`; an
activation marked `@detached` opts out of ambient inheritance entirely instead
of overriding it. Tooling displays the inferred ambient lineage at every call
site. `RequestMetadata` is the separate explicitly copyable bounded diagnostic
value; it carries no admission authority or region brand.

## 6. Time

`Duration` is a nonnegative checked span represented by a target-independent
integer number of nanoseconds. Named constructors `ns`, `us`, `ms`, `seconds`,
`minutes`, `hours`, `days`, and `weeks` are ordinary phase-neutral functions:
each is comptime-callable when its argument is comptime and otherwise callable
at runtime. There is one surface, not a runtime/comptime twin pair.

Arithmetic and comparison on `Duration` are the standard `Add`, `Sub`, and
`Ord` interface implementations rather than named methods; `min`, `max`, and
`clamp` follow from `Ord`, and `clamp(value, lower, upper)` requires
`lower <= upper`. `d.as_nanoseconds() -> u64` is the sole accessor into the
backing scalar. Overflow and underflow use ordinary checked arithmetic: a
comptime evaluation that overflows is a build error, and a runtime evaluation
abandons. The contract does not separately specify a bound assertion beyond
what checked `Add`/`Sub` already establish for the backing integer width.

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

## 7. Tasks, wake, and task failure

Every local or nursery-installed async activation resolves once with:

```text
declared R             -> Result[R, AsyncExit[never]]
declared Result[T, E]  -> Result[T, AsyncExit[E]]
AsyncExit[E] =
    Operation(E) | Cancelled(Cancelled)
  | DeadlineRejected(DeadlineRejected)
  | DeadlineExceeded(DeadlineExceeded)
```

Awaiting consumes the activation's completion. Actor transport composes these
exact causes into `ActorCallError[E]` as `Exit(AsyncExit[E])` rather than
duplicating their variants.

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
declares `Stop`, `RestartActor`, or `Escalate` for that event. Absence of a
policy is a build error; `Err` is never discarded.

## 8. Nurseries, joins, and races

`Nursery[..N]` owns at most `N` child activations. `start` consumes or copies
its arguments according to the child signature. Exiting the nursery waits for
or cancels and tears down every child.

For a statically heterogeneous set of children, `join_all` returns a fixed tuple
in start order. Tuple element ownership follows the language tuple rules. A
homogeneous dynamic count returns `List[T, ..N]` with an explicit maximum.

`race(a, b, ...)` is a sealed stdlib contract, not grammar: its surface is an
ordinary call expression, but the compiler build-proves and reserves all child
slots before evaluating or starting any alternative, so it is not an ordinary
eager function call. The build rejects a race whose setup capacity is not
proved. It returns a generated closed sum `RaceN[A, B, ...]` identifying which
alternative won; it cannot return a tuple because only one result exists.
Before returning the winner it cancels every loser, waits for all sealed
recovery completions, and proves that no loser retains a restoration obligation
or quarantined mutable region. Winner selection among simultaneously ready
alternatives uses argument order after the scheduler's recorded readiness set.

## 9. Bounded arrays, collections, and iteration

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

`List[T, ..N]` and `SlotMap[T, ..N]` never exceed `N`. Construction mints a
fresh non-wrapping map instance ID. `SlotMap.Key` is the explicitly copyable
`(map_id, index, generation)` value. `get` and `get_mut` validate all parts
and return second-class
`Option[view T]`/`Option[mut view T]`. `remove` increments before reuse and
permanently retires a slot rather than wrapping; insertion may return
`GenerationExhausted`. Image-resident instances receive compile-time IDs;
runtime construction draws from a bounded ID pool and may return
`MapIdExhausted` rather than wrapping.

### 9.1 Iteration

Revision 0.1 iterates over a closed builtin set: integer ranges (`0 .. n`),
fixed arrays including the consuming `take` form above, and the per-container
operations named below for `List[T, ..N]` and `SlotMap[T, ..N]`. A general
user-defined `Iterable` protocol is deliberately excluded from revision 0.1;
its exclusion and the evidence bar for revisiting it are tracked in the
conformance inventory, not restated here.

`List[T, ..N]` iterates with `for element in list.items()` (`read view T` in
index order) or, for exclusive access, `for element in list.items_mut()`
(`mut view T`). `SlotMap[T, ..N]` iterates with `keys()` (owned, copyable
`Key` values), `values()`/`values_mut()` (`read view T`/`mut view T` by
occupied index order), and `pairs()`/`pairs_mut()`
(`(Key, read view T)`/`(Key, mut view T)`).

A `_mut` iteration form's view lives only inside the loop body: the `mut view
T` (or `mut view T` component of a pair) produced by one step cannot be
stored, returned, or retained past that step, and at most one such view is
live at a time. Iteration holds the corresponding lexical access to the
container itself for the loop's duration.

## 10. Bounded formatting

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

### 10.1 External formats and wire values

`Validated[F, T]` is a sealed owned wrapper minted only by the declared
`FormatValidator[F, T]` operation:

```text
validate(data: Bytes) -> Result[Validated[F, T], F.Error]
Validated[F, T].into_value(take self) -> T
```

`Validated[F, T]` is one instantiation of the evidence-wrapper family
unified elsewhere (`Untrusted[T]` taint-in, `Validated[F, T]` proof-out); this
chapter does not restate that unification, only this wrapper's own contract.
The compiler enforces use of the wrapper when an API declares that precondition;
it proves memory/bounds/ownership safety of the validator but does not claim a
theorem that arbitrary user validation matches an external prose format.
Standard validators have independent fixture/conformance obligations.

`Bytes.read_wire[W](offset)` exists only for `@wire W`; it checks the complete
encoded extent and decodes the declared endian/version/layout into an owned
`Result[W, WireError]`. There is no `read_struct` operation for ordinary or
`@dma` structs.

## 11. `InterruptCell`, MMIO, and virtqueues

`InterruptCell[T]` is only for ordinary/ISR-visible state and exposes the operation
set in [Hardware safety](05-hardware-safety.md). RMW methods are
interrupt-atomic and contribute to the masked-interval report when implemented
by masking.

`Mmio[L]`, `iso[P] T` for `@dma T`, `DmaShared[P, L]`, `VirtQueue`, queue permits, prepared
operations, and receipts are sealed protocol types. Their public contracts must
encode the authority partitions, ordering, ownership transitions, complete
descriptor reservation, epochs, untrusted control validation, and deferred
recovery rules of chapter 05. Untrusted control validation is exactly where the
evidence-wrapper family (§10.1) applies on the device side. `P` may be spelled
with the actor-associated alias form defined in §4. A replacement
implementation cannot expose a raw address, ordinary view of shared control
memory, droppable receipt, or unpartitioned register mapping.

## 12. Construction and scope intrinsics

`Image`, `request`, `nursery`, actor admission, and pool construction are
compiler-recognized semantic intrinsics even when a standard package supplies
their surface declarations.

- `Image(name, target)` is comptime-only and produces one linear
  `ImageBuilder`. Its mutation is deterministic graph construction, not runtime
  allocation.
- `device[D]` produces a proof-only `DeviceDecl[D]`; `driver[A]`,
  `service[A]`, and `app[A]` each produce one proof-only `ActorDecl[A]`.
  Their constructor arguments must exactly match `A.init` after generated
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
  bounded request region for fresh `R`; every call inside it ambiently
  inherits that context (§5). `nursery(capacity=N)` is a suspend-safe
  scope owning exactly `N` child slots. Their cleanup contracts are chapters 03
  and 04, not replaceable destructor conventions.

An alternative standard library may rename wrappers around these intrinsics but
cannot alter their graph nodes, generativity, phase, access effects, failure
points, or cleanup/wait-for edges.

## 13. Operator interfaces

The closed operator interfaces named by
[Source language](02-source-language.md) are declared in the standard-library
module `core.ops` with exactly these shapes:

```wrela
pub interface Add:
    fn add(read self, right: Self) -> Self

pub interface Sub:
    fn subtract(read self, right: Self) -> Self

pub interface Ord:
    fn less_than(read self, right: Self) -> bool
```

Operands are `read`: an operator expression never moves or mutates its
operands, and an implementation constructs its result from field reads (with
any non-scalar duplication written explicitly inside the implementation body).
`Ord::less_than` is a strict total order over the implementing type.

Operator expressions on a nominal type with a visible implementation desugar
to direct specialized calls with the ordinary left-to-right operand evaluation
of chapter 02:

- `a + b` is `Add::add(a, b)`; `a - b` is `Sub::subtract(a, b)`.
- `a < b` is `Ord::less_than(a, b)`; `a > b` is `Ord::less_than(b, a)`;
  `a <= b` is `not Ord::less_than(b, a)`; `a >= b` is
  `not Ord::less_than(a, b)`.

Both operands are evaluated as written before the call regardless of the
argument mapping. Compound assignment desugars through the same interface: on
a nominal type, `a += b` is `a = a + b` through the visible `Add`
implementation, and `a -= b` is `a = a - b` through `Sub`, in both cases with
the destination place `a` evaluated exactly once. Compound assignment
introduces no interface of its own.

Structural `==`/`!=` on copyable structs and enums remain compiler-generated and
do not consult an interface. `Eq` for non-structural equality, heterogeneous
`Mul`, and the remaining named peers follow the same declaration pattern and are
specified when their first standard implementation lands. Core scalar operators
are built in and never desugar through these interfaces.

`Duration` implements `Add`, `Sub`, and `Ord`; its checked overflow contract
in section 6 is unchanged by the desugaring.

## 14. Deriving contracts

The closed derivable set is exactly `Eq`, `Format`, and single-variant/single-
field `From`, invoked with the sealed `deriving(...)` clause fixed by
[Source language](02-source-language.md); this chapter specifies only what
each name generates, not the clause's grammar.

- `deriving(Eq)` extends the compiler-generated structural `==`/`!=` (§13) to
  a type that is not itself `Copy`: every field must itself satisfy the same
  structural-equality obligation, and the generated comparison reads both
  operands without moving or duplicating them.
- `deriving(Format)` generates the bounded formatting contract of §10: a
  compile-time `max_formatted_len(spec)` summed from each field's own bound,
  and a writer that cannot exceed it.
- `deriving(From)` requires the type carry exactly one variant or one field
  and generates the unique `From` implementation that postfix `?` consumes
  (§3); deriving it on any other shape is a build error.

An alternative library MAY hand-implement any of these three interfaces
instead of deriving them, subject to the same obligations.

## 15. The `_proven` naming convention

A `*_proven` name requires an additional build-time proof argument or context
— a reservation, capacity, or admission proof already established earlier in
the same scope — and is the canonical name for the statically-proved variant
of an otherwise possibly-failing operation. `VirtQueue.reserve_proven` and
`IsoPool.allocate_proven`/`from_str_proven` in the worked example follow this
convention. A standard or alternative library MUST name every statically-proved
variant this way rather than inventing an unrelated name or silently changing
an existing method's failure mode.

## 16. API naming

- Enum variants are CamelCase constructors; ordinary functions and methods are
  snake_case.
- A statically-proved variant follows the `*_proven` convention (§15).
- A capacity/occupancy generic parameter that names a bound rather than an
  exact extent is spelled `..N` in a type's public signature — `List[T, ..N]`,
  `SlotMap[T, ..N]`, `Nursery[..N]` (§8–§9) — while a fixed exact extent stays
  plain `N`/`[T; N]`.
- A function or method with exactly one non-receiver operand SHOULD declare
  that parameter with the `_` declaration-owned label
  ([Source language](02-source-language.md)) so calls are positional, for
  example `ns(42)` rather than `ns(value=42)`.
