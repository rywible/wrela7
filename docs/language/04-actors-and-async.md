# Actors and async

## 1. Why the actor is the unit of mutable concurrency

Single-core execution prevents two ordinary instructions from running at the
same instant. It does not prevent one async operation from suspending halfway
through a state change and another operation from invalidating its assumptions.

wrela therefore gives every runtime root one owner and one mailbox. Structs
marked `@app`, `@service`, and `@driver` are actors and are implicitly linear.
Their fields are private mutable state. Other actors hold generated typed
handles, not object references. Apps are top-level workload leaves, services
are reusable image dependencies, and drivers alone may own hardware authority;
all three use the same turn and mailbox semantics.

This is not Erlang. There is no actor registry, no dynamically assembled
supervision topology, and no runtime process discovery. Every concrete
`Actor[T]` handle is minted once by the image graph
([Comptime and images](06-comptime-and-images.md)) and wired at build time;
nothing spawns, registers, or looks up an actor while the target is running.
This is deliberate: revision 0.1 trades Erlang-style dynamic topology for
whole-image analyzability — the wait-for graph, mailbox capacities, and
supervision tree described in this chapter all depend on the call graph being
closed before boot.

```wrela
@service
pub struct Storage:
    cache: BlockCache
    disk: Actor[BlkDriver]

    pub async fn read_file(mut self, ino: u32,
                           take out: iso[AppBuffers] Bytes)
        -> Result[iso[AppBuffers] Bytes, FsError]:
        ...
```

The handle exposes only public actor methods. Calling one creates a logical
typed message admission and eventually returns a typed reply. The reference
lowering places arguments in bounded static message storage. A compiler may
elide physical serialization, copying, or a scheduler round trip only under the
actor as-if rule in [Optimization model](09-optimization-model.md).

## 2. Message payloads

A cross-actor message may contain:

- scalar values, copied into the message;
- a non-scalar copyable value produced by an explicit `copy` expression and
  then moved into the message;
- explicit `Static[T]` handles to immutable image data;
- values transferred with `take` through `iso` or sealed linear runtime handles.

It MUST NOT contain a `view`, `mut view`, `mut` parameter, ordinary object
identity, or an unbounded container. Every payload layout is known at build
time.

Consequently, a public actor method cannot declare a non-receiver `mut`
parameter. To let another actor transform a buffer without copying, transfer it
and receive it back:

```wrela
pub async fn compress(mut self, take input: iso[Packets] Bytes)
    -> Result[iso[Packets] Bytes, CodecError]:
    ...

data = await codec.compress(input=take data)?
```

Read-only non-copy values also require transfer unless they are immutable
image-static data. The absence of mutation does not make a runtime alias safe to
share with a future multi-core actor.

Revision 0.1 actor handles are **image-wired**. The image graph mints each
concrete `Actor[T]` value and may install it in actor fields through
construction or restart provisioning. A handle cannot appear in a message,
actor reply, runtime collection, or mutable runtime input. It cannot be created
from or selected by a runtime actor ID. Consequently every possible
cross-actor call edge is a concrete image-graph edge. Mobile actor handles
require a future capability-flow analysis and are outside this revision.

### 2.1 Brand aliases

An actor-root struct may declare an associated `brand` alias for an
image-bound pool it depends on:

```wrela
@service
pub struct Storage:
    brand Payloads
    cache: BlockCache
    disk: Actor[BlkDriver]

    pub async fn read_file(mut self, ino: u32,
                           take out: iso[Storage.Payloads] Bytes)
        -> Result[iso[Storage.Payloads] Bytes, FsError]:
        ...
```

Image construction binds `Storage.Payloads` to a concrete minted pool brand
([Comptime and images](06-comptime-and-images.md)) exactly once, the same as
any other brand. A public signature written against `Storage.Payloads`
keeps compiling if the image later reshuffles which concrete pool backs it —
only the construction site changes, not every method that names the alias.

## 3. Non-reentrant turns

An external message starts an actor **turn**. The actor remains assigned to that
turn until the handler returns, propagates an error, or abandons. If the handler
awaits a dependency, other actors may run, but no new external message is
admitted into the suspended actor.

This is stronger than ordinary reentrant actor systems. Actor state before an
`await` cannot be changed by a second external request while the first turn is
suspended.

Internal synchronous calls on `self` are ordinary calls and do not create an
actor edge. A call through a different actor handle always creates a semantic
actor edge, even when its physical enqueue or dispatch is optimized away.

### 3.1 Unified wait-for graph

The compiler builds one directed wait-for graph. Nodes include concrete actor
turn locks, nursery/task activations, actor replies, device/timer completions and
their producers, mailbox admission slots, queue permits, bounded pools,
scope-cleanup nodes, and generated recovery lanes. An edge `A -> B` means that
`A` can retain ownership of its node while waiting for `B`. Producer edges are
included: a receipt points to the bottom-half/recovery node capable of resolving
it, and a child join points to every unfinished child.

Every reachable strongly connected component containing a hold-and-wait edge is
a build error unless a sealed primitive proves that an external event resolves a
specific node without acquiring any node in the component. A timer or hardware
event may be such an external producer; merely labelling an operation a
completion is not proof. The diagnostic gives the full resource cycle.

```text
error[wait-cycle]: blocking resource cycle
  Storage.turn -> child[0] -> Logger.turn -> Storage.turn
  Storage.turn is non-reentrant while child[0] is joined
  help: move the child behind a receipt, make the notification one-way,
        or merge/shard the state
```

The analysis is conservative across runtime branches and is performed after
comptime specialization, so IRQ-vs-poll and target-specific branches that were
removed do not contribute edges.

Because actor handles and producer identities are image-wired, the graph is
obtained from concrete fields, specialized calls, task slots, and sealed resource
contracts; no runtime points-to approximation is needed. Runtime-selected use of
a bounded slot contributes edges to every slot it can select.

A nursery child may not borrow actor-owned mutable state from a parent that
retains the actor turn lock. It receives copied or moved owned inputs. A public
`@driver` handler is synchronous in revision 0.1: it validates, reserves or
rejects, publishes, and returns a receipt without awaiting. Bottom-half and
recovery tasks run only between such handler turns. Queue waiting therefore
occurs in a client-side admission proxy or returns a typed admission failure; a
driver handler never waits for work whose producer needs the same driver.

### 3.2 One-way messages

`send` enqueues a unit-returning actor method without waiting for its turn to
run:

```wrela
send logger.record(event=take event)
```

One-way sends do not create reply-wait edges, but their admission and request
registration edges remain in the unified graph. The compiler permits an
infallible `send` only when mailbox capacity analysis proves a slot is
available. `try send actor.method(...)` is the nonblocking alternative. It
checks/reserves admission before evaluating any argument, so `Rejected(reason)`
leaves every source value initialized and suppresses every argument side effect.
On success it evaluates arguments left-to-right and atomically commits the
message; only that transition consumes `take` arguments. Its result is the
ephemeral `AdmissionResult` (outcome taxonomy, §3.5) — a second-class
control-flow carrier that cannot be stored or propagated with `?`.

```wrela
match try send logger.record(event=take event):
    case .Admitted:
        pass                         # `event` was moved
    case .Rejected(reason):
        retain_for_later(reason, event=take event)  # source still owned it
```

A one-way handler cannot return a value to the sender. Errors are handled by the
receiver's supervisor policy.

During restart, selection of new turns is stopped but the bounded mailbox may
continue accepting messages. An infallible `send` is legal only when capacity
analysis includes the maximum messages admitted during the target-bounded
restart window. Accepted messages remain FIFO and become eligible after the
actor reopens. When that bound cannot be proved, source must use `try send` or an
explicitly awaitable admission API. No proven-infallible send silently
disappears or waits on an unmodeled edge.

### 3.3 Observable actor semantics

The following are semantic and survive every lowering:

- successful admission occupies one logical mailbox slot until that message is
  selected;
- admitted messages are selected FIFO by logical admission sequence within each
  actor mailbox;
- one external turn owns the actor until it completes, errors, or abandons;
- priority, deadline, checkpoint, and cancellation behavior remains equivalent;
- abandonment is attributed to the same actor and invokes the same supervisor;
  and
- deterministic record/replay observes the same logical admissions, turns,
  replies, and faults.

Actor object addresses, mailbox slot addresses, numeric actor IDs, state-machine
addresses, and the number of physical scheduler hops are not observable in the
safe language. The compiler may use a direct handler call, continuation
forwarding, or fused machine code when the observable rules above are unchanged.
It MUST NOT coalesce, discard, duplicate, or reorder logical messages merely
because their handlers appear idempotent. Such semantics require an explicit
standard-library operation.

### 3.4 Failed peers and replies

Every cross-actor request has a generated reply completion, including methods
whose declared successful result is `unit`. If the callee abandons or is torn
down for restart before resolving it, the completion resolves exactly once with
`PeerFailed`, carrying the concrete actor identity, supervision epoch, and a
bounded non-secret failure category.

The effective result of every actor request is `Result[R, ActorCallError[never]]`
or `Result[T, ActorCallError[E]]` — the composed carrier defined once in the
outcome taxonomy below (§3.5). Variants impossible for a call may be
eliminated after whole-image analysis but remain part of its source type.
Postfix `?` converts them only through explicit `From` implementations. A
caller cannot hang waiting for an actor epoch that no longer exists, and
cancellation/deadline behavior is never a hidden control effect.

For a call with any `take` argument, its effective result is an
ownership-conditioned second-class carrier until immediately consumed by `?`
or `match`. In `NotAdmitted(reason)`, reservation failed before ordinary
argument evaluation and every source remains initialized. Every other result
means admission committed and those sources are uninitialized. Joining match
arms must converge their linear initialization states. A call with no `take`
argument has an ordinary storable result.

A successful mailbox admission consumes every `take` argument irrevocably. Peer
failure, cancellation, forwarding, or abandonment does not reconstruct the
caller's source place. A method that promises to return an input expresses it in
all result variants, for example `Result[(Reply, P), (OperationError, P)]`.
Protocols requiring recovery after publication use the sealed strict
`Receipt[P]` state machine (§13) with a typed commit boundary: before it
reaches its committed state every failure returns `P`; after, recovery follows
the protocol's specified quiescence path or yields `OutcomeUnknown`. The
compiler verifies the receipt implementation, not an implicit whole-program
value-tracing promise.

Peer failure, reply resolution, restart admission
closure/reopening, and mailbox acceptance during restart are deterministic
record/replay events.

### 3.5 Outcome taxonomy

wrela has one failure vocabulary for suspending activations, defined once
here; no other section restates its variants.

`AsyncExit[E]` is the core sealed outcome of any non-actor async activation:

```text
declared R             -> Result[R, AsyncExit[never]]
declared Result[T, E]  -> Result[T, AsyncExit[E]]

AsyncExit[E] =
    Operation(E)
  | Cancelled(Cancelled)
  | DeadlineRejected(DeadlineRejected)
  | DeadlineExceeded(DeadlineExceeded)
```

`ActorCallError[E]` composes it for every cross-actor request rather than
redeclaring its variants:

```text
declared R             -> Result[R, ActorCallError[never]]
declared Result[T, E]  -> Result[T, ActorCallError[E]]

ActorCallError[E] =
    Exit(AsyncExit[E])
  | PeerFailed(PeerFailed)
  | NotAdmitted(AdmissionError)
```

`AdmissionResult` is the ephemeral carrier returned by `try send` and other
explicit admission APIs (§3.2):

```text
AdmissionResult = Admitted | Rejected(AdmissionError)
```

It shares the same `AdmissionError` that `NotAdmitted` carries: an admission
failure has one representation whether it surfaces from a one-way `try send`
or from a two-way actor call. `AdmissionResult` and the ownership-conditioned
actor-call outcome (§3.4) are both ephemeral types
([Values, views, and regions](03-values-views-regions.md)): produced only by
an admission or call operation and consumed immediately by binding, `match`,
or `is`. `AdmissionResult` permits only `match`/`is`, never `?`; the
actor-call outcome additionally permits `?`, through explicit `From`
conversions of its `ActorCallError`/`AsyncExit` causes.

## 4. Mailbox and turn bounds

Every actor has a fixed-capacity logical mailbox in the image region. The
reference representation is a tagged FIFO ring. A compiler MAY instead use a
small ordering ring plus per-method payload banks, statically assigned lanes, or
another bounded representation with equivalent admission and selection
behavior. The compiler derives a minimum logical capacity from:

- the finite set of senders;
- each sender's maximum live task and request count;
- bounded loop multiplicity;
- one-way burst bounds; and
- calls already serialized by non-reentrancy.

The image may reserve more capacity, never less. If the compiler cannot derive a
finite upper bound, the build fails and names the unbounded send path.

Physical storage need not equal `capacity * largest_payload`. The compiler
SHOULD use the closed sender graph and per-method live bounds to avoid padding
every slot to the largest variant. The image report gives both logical capacity
and physical bytes by message kind.

Each actor has a bounded number of turn-frame slots. The normal non-reentrant
case needs one active turn plus mailbox storage. Explicit sharding or child
actors provide concurrency; accidental reentrancy does not.

## 5. Async lowering

Every `async fn` lowers ahead of time to a concrete state machine. Its frame
contains:

- a state discriminator;
- values live across each `await`;
- owned child/request handles;
- result and cancellation state; and
- statically known teardown metadata.

There is no boxed future, runtime-polymorphic future, or runtime frame
allocation. The compiler computes the frame layout after monomorphization and
reserves the required number of slots.

Every non-actor async activation completes with the sealed `AsyncExit[E]`
outcome defined once in the outcome taxonomy (§3.5).

The effective outcome belongs to the awaitable/task boundary rather than being a
catchable exception inside a canceled frame. Local/nursery callers handle or
convert it explicitly; an actor transport maps the same causes into
`ActorCallError[E]`. An image-installed root task instead delivers its declared
operation error or async-exit cause to its supervisor policy.

The layout is state-sensitive. The compiler SHOULD color non-overlapping live
ranges into shared frame storage, scalar-replace aggregates, erase proof-only
zero-sized values, and recompute cheap pure values when that does not violate a
work budget. A tail await MAY reuse or forward a continuation instead of
materializing an otherwise redundant caller frame. Cleanup, cancellation, and
abandonment must still behave as if the complete source frame existed.

`@task` may also mark a synchronous event turn, such as a driver bottom half.
Such a task owns a generated static handle, runs to completion under its budget,
and has no persistent active turn while waiting for a wake. An `@task` on an
async function uses the normal generated state-machine slots.

The handle is not a first-class bound method and is never stored in actor state.
`wake(Type.task_method)` names a statically bound image task identity; the
compiler resolves it to that actor instance's generated slot and checks the ISR
effect. An async task returning `Result[unit, E]` reports `Err` to its declared
task-failure supervisor action after lexical teardown. A unit-returning task
cannot use `?` to discard an error.

`async` describes whether the function body may suspend; it does not describe
message transport. An async function may call a sync function at no scheduling
cost. A sync function cannot directly call an async function without an async
context or bounded task installation. Calling any public method through
`Actor[T]` performs asynchronous admission and returns an awaitable regardless
of whether the handler itself is `fn` or `async fn`. Thus a quick driver
submission handler is a plain `pub fn`, while its caller writes `await
driver.submit(...)`.

### 5.1 Recursion and stack sizing

The compiler analyzes both graphs:

- async call cycles determine frame activation bounds; and
- synchronous call cycles determine executor stack depth.

Unbounded recursion in either graph is a build error. A recursion cycle is legal
only when source or a generic constant supplies a finite depth and the compiler
can account for every activation. Tail calls MAY be eliminated, but a safety
bound cannot depend on optional optimization.

Because one core polls ordinary work sequentially, the executor needs one stack
sized for the maximum synchronous poll path, plus target-defined ISR and fault
stacks. All sizes appear in the build report.

## 6. Suspension rules

`await expression` evaluates an awaitable. If the awaitable is strict-linear,
`await` consumes it exactly as `take`; it cannot be awaited twice or inspected
afterward. If ready, it produces a result without suspension. Otherwise it stores
the live state in the current frame, registers a wake target, and returns control
to the event loop.

At every suspension point:

- no `view` or `mut view` may be live;
- no non-suspend-safe `with` scope may be active;
- every partially moved field must be protected by the current non-reentrant
  turn and have a generated cancellation repair/teardown path;
- every linear value is owned by the frame or a nested region; and
- the current deadline and priority are propagated to downstream work.

A whole-value `read` or `mut` access rooted at the actor assigned to the current
turn is frame-safe under the turn-scoped rule in
[Values, views, and regions](03-values-views-regions.md). It is not a view: the
frame records a stable actor field path, no other external turn may run, and
moving an ancestor creates a restoration obligation. Access to an external
argument remains forbidden across suspension.

`yield_now()` is an awaitable checkpoint. It yields to other actors and ready
tasks but does not admit another external turn into the current actor.

## 7. Completion and park/wake

`Completion[T]` is a sealed, single-resolution awaitable. A producer may resolve
it once; any later resolution attempt is an abandonment-level runtime bug. Wake
is idempotent: waking an already-ready task does not enqueue duplicate mutable
access to its frame.

The runtime's conditional park operation has normative **mask–arm–recheck**
semantics:

1. mask the relevant interrupt source or enter the target's equivalent atomic
   publication section;
2. test the level predicate;
3. if false, install the current task's wake target;
4. re-test the predicate after publication;
5. park only if it is still false; and
6. restore the interrupt state as part of the park/continue transition.

An interrupt that arrives before, during, or after publication therefore cannot
be lost. A source-level check followed by an unrelated park is not a legal
synchronization primitive.

`InterruptCell[T]` and ISR ordering are specified in
[Hardware safety](05-hardware-safety.md).

## 8. The scheduler

The standard revision 0.1 executor is a cooperative, priority-banded event loop.
The image has three default bands:

1. device bottom halves and deadline-critical runtime work;
2. normal service and app turns; and
3. background maintenance.

Targets MAY refine the bands, but priorities remain build-time values. The
compiler analyzes bounded priority inversion through actor waits, queue permits,
and scoped resources. It rejects a hard-deadline path whose lower-priority
dependency has no sufficient inheritance or ceiling.

The executor repeatedly:

1. drains ready work in priority/deadline order;
2. polls each selected state machine until its next suspension/checkpoint;
3. services configured poll tasks; and
4. sleeps for an interrupt only when no ready work or mandatory poller exists.

The scheduling key of a ready actor is the priority and effective deadline of its
oldest admitted message; later messages never raise that actor ahead of its FIFO
head. This intentional head-of-line blocking is semantic and appears in the
capacity/deadline report. A standalone task uses its own key. The reference
choice among ready actors/tasks is normative: select the highest priority band;
within it select the earliest effective deadline, treating no deadline as
infinity; among equal deadlines select by a round-robin cursor over static
actor/task IDs and advance the cursor after selection. The selected actor
consumes its FIFO head. Target
specialization may change representation and eliminate scheduler hops only when
the resulting logical selection sequence is equivalent. Record/replay logs
nondeterministic readiness before applying this deterministic policy.

Revision 0.1 does not silently promise starvation freedom across priority bands:
an unbounded stream in a higher band could starve lower work. A conforming image
must either prove finite arrival/work bounds that give every declared
`@task(..., must_service_within=Duration)` task a response bound, apply an explicit server/budget
policy that replenishes lower bands, or report that lower-band service is
best-effort. Hard deadlines are rejected when this proof is absent.

Ready queues, task tables, and handles are fixed-capacity generated structures.
They are specialized to the sealed image rather than required to use a generic
executor representation. A target may use static task IDs, direct wake targets,
priority bitsets, and precomputed masks. Ordinary actor-to-actor paths on the
single application core require no atomic read-modify-write; publication shared
with an ISR still uses the target's checked interrupt-ordering primitive.

## 9. Work budgets and checkpoints

A single `@budget` attribute bounds uninterrupted work, at both function/task
level and loop level, not device latency spent suspended. `@task(...,
budget=...)` bounds a task's uninterrupted work between scheduling points:

```wrela
@task(priority=normal, budget=us(200))
async fn drain(mut self):
    ...
```

Every loop back edge lexically inside an async function/closure is a semantic
checkpoint unless the loop itself is annotated `@budget(bound=...)`, which
replaces that checkpoint with a build-proven maximum uninterrupted-cost bound
instead of a scheduling point. At a checkpoint cancellation is observed and
the scheduler may run other ready actors/tasks, while the current
non-reentrant actor turn remains assigned to its frame. Implementations may
elide a checkpoint only when the actor as-if rule proves that cancellation,
scheduling, teardown, and record/replay observations are unchanged.

A synchronous `fn`, synchronous `@task`, projection, scope abort/exit, and ISR
never checkpoints or suspends implicitly. Every loop in such code—including a
sync helper called by async code—must have a compiler-proven finite iteration and
target-cost bound, which contributes uninterrupted work to every caller. A
comptime loop is governed instead by the evaluator quota. This keeps function
color independent of inlining and call context.

The compiler proves the bound using the selected target's conservative cost
model. A loop between suspension points is handled as follows:

- an ordinary async loop is segmented at its semantic back-edge checkpoint;
- a loop annotated `@budget(bound=...)` contributes its proven maximum
  iteration cost;
- every synchronous/ISR loop contributes its proven maximum cost; and
- if the checkpoint is illegal because a non-suspend-safe access is live, source
  must shorten that access or use a proven `@budget(bound=...)` annotation.

A runtime async checkpoint is a suspension point. The compiler MUST NOT accept one while a
view, mutable projection, turn-external access, or non-suspend-safe scope is
live. It may shorten a provably dead access before the back edge, but it cannot
change source-observable teardown or exclusivity. If the live access prevents
the semantic checkpoint, the build fails with a diagnostic naming the access and
suggesting a `@budget(bound=...)` annotation only when one can be proved.

Budget reports distinguish proven instruction-time bounds from configuration
estimates. A target without a defensible timing model may verify structural
checkpoint bounds but cannot claim hard microsecond conformance.

## 10. Deadlines

A request deadline is inherited across actor calls, queue submission, timers,
and child tasks. The effective deadline is the minimum of the inherited deadline
and any narrower local deadline.

The scheduler may use remaining deadline for ordering. A callee cannot widen a
deadline. If admission analysis proves work cannot meet a hard deadline, it
returns a recoverable `DeadlineRejected` before starting. A runtime miss returns
or triggers the request's timeout path; it is never silently ignored.

`DeadlineRejected` occurs only inside
`NotAdmitted(AdmissionError.DeadlineRejected)`, before argument evaluation.
Once admitted, expiry closes the request lineage with cause
`DeadlineExceeded`, runs its complete cleanup graph, and resolves the actor call
with that typed cause. An explicitly committed external operation may additionally
return its protocol's `OutcomeUnknown`; deadline expiry does not imply that an
external side effect did not occur.

Priority inheritance and deadline inheritance are generated from the same
closed await/resource graph.

## 11. Structured task creation

There is no detached, unbounded `spawn`. Child concurrency uses a nursery with a
compile-time capacity:

```wrela
with nursery(capacity=4) as children:
    children.start(fetch_part, index=0)
    children.start(fetch_part, index=1)
    results = await children.join_all()
```

`children.start(...)` reads the ambient request lineage of its call site
(§12); a child body neither receives nor forwards a context argument to
inherit it.

A nursery:

- owns its child task-frame slots;
- cannot outlive its parent scope;
- propagates parent cancellation, deadlines, and ambient request lineage;
- waits for or tears down every child before exit; and
- has a statically included mailbox/frame footprint.

Starting beyond capacity returns `CapacityError` only when the API explicitly
chooses runtime admission; image profiles may require proof that it cannot
happen.

## 12. Request scopes and ambient lineage

`with request(...)` opens one structured operation domain:

```wrela
with request(deadline=now() + ms(50), budget=us(200)):
    result = await storage.read(path)?
```

Every `async fn` implicitly carries the **ambient request lineage** of its
lexically enclosing `with request(...)` scope; a function with no enclosing
scope carries its task root's lineage instead. Actor-call admission,
`nursery.start`, and deadline/cancellation propagation all read this ambient
lineage — an ordinary signature never declares, receives, or threads a
request parameter. `storage.read(path)` above is admitted under the lineage
opened one line earlier, with nothing in its argument list carrying that
fact.

Earlier drafts of this chapter wrote the same call as
`await storage.read(req, path)?`, against a `req[region R]` binding and a
`RequestContext[R]` parameter on `read`. Both disappear from ordinary
signatures; the ambient lineage replaces them without changing any
admission, deadline, or cancellation rule below — the request still mints a
fresh proof-only region brand internally, it is simply no longer spelled out
as a generic parameter.

Two escapes exist:

- an explicit `request=` argument overrides the ambient lineage for a call
  that must run under a *different* one — genuinely rare, since it matters
  only when a call is not lexically inside the lineage it must join; and
- a declared `@detached` attribute marks work that is deliberately
  independent of any enclosing request — it starts its own task-root lineage
  rather than inheriting one.

```wrela
with request(deadline=now() + ms(50), budget=us(200)) as req:
    send logger.record(event=take event, request=req)
```

`req` above has the sealed `RequestContext` type: a second-class admission
descriptor carrying that lineage's request identity and epoch, inherited
deadline/priority, cancellation ancestry, and proof-only region brand. It has
no storable ordinary layout: it may be used repeatedly only as the immediate
`request=` argument to a nursery or actor admission, and cannot be stored,
returned, captured, formatted, or sent as unregistered data. Copyable
diagnostic fields are obtained separately as `RequestMetadata`. Outside that
override argument, `RequestContext` is otherwise a tooling-facing type only:
**tooling MUST display, for every `async fn`, the lineage its body is
inferred to run under** — a specific enclosing `with request(...)`, the task
root, or `@detached` — since source no longer spells it out.

The request owns:

- a request region;
- its deadline and cancellation state;
- child request/task slots;
- a cleanup dependency graph with deterministic ready-node ordering;
- any queue permits and completion tokens; and
- any request-scoped `iso` or DMA buffers.

Admission validates that the lineage is open and atomically creates a strict
child-registration node before occupying the mailbox/task slot, whether that
lineage was read ambiently or supplied through `request=`. The admitted
message owns that node even while queued; the receiving turn consumes it on
completion. A stale, canceled, or expired lineage fails admission without
moving any other argument. This applies equally to request-associated one-way
messages. A callee may register nested children, receipts, and cleanup nodes only
through its owned registration, so the parent cannot resolve while queued or
running descendants remain.

Nested requests inherit cancellation and deadline. A child may narrow but not
detach from its parent, except by declaring `@detached`.

### 12.1 Cancellation delivery

Cancellation becomes observable at `await`, explicit checkpoints, and admission
operations. It does not asynchronously run arbitrary source code between
ordinary instructions.

On cancellation, the runtime:

1. atomically closes admission, so later attempts return a typed failure without
   consuming payloads;
2. marks child registrations canceled and recursively activates their cleanup
   graphs;
3. transfers each strict device receipt to a generated high-priority recovery
   turn on the driver that owns the queue/MMIO authority;
4. quarantines affected request regions and pool slots so they cannot be read,
   reclaimed, or reused;
5. runs every ready cleanup node in deterministic reverse source order while
   leaving nodes with unmet recovery dependencies pending;
6. lets the scheduler continue unrelated work while the driver completes its
   target-bounded reset/quiescence protocol; and
7. activates newly unblocked exit nodes as recovery completes; and
8. releases quarantine and resolves `Cancelled` to the parent only after the
   cleanup graph is empty and every child registration is consumed.

This ordering means a caller never observes a race winner while a losing branch
still owns mutable memory or an active device request.

No source abort/exit action suspends and the canceled user frame never resumes.
Waiting belongs to generated cleanup-graph nodes, not to a source destructor. The sealed
recovery turn is part of the queue/request protocol, executes in driver context,
inherits the request's recovery priority and deadline policy, and is included in
the actor, budget, and blocking-resource analyses. If the target recovery bound
cannot coexist with hard deadlines, the image is rejected or must declare a
bounded quarantine/target-fatal policy.

### 12.2 Queue permits and backpressure

A device request reserves a complete submission unit before exposing anything
to hardware. With runtime backpressure, the generated driver proxy waits before
admitting the synchronous driver handler. For a split virtio-blk request using
three direct descriptors:

```wrela
permit = await disk.admit(request_shape=VirtioBlkDirect3)?
receipt = await disk.submit(permit=take permit, buffer=take buffer)?
```

The permit owns the exact descriptor chain. With `QDEPTH = 128`, at most
`floor(128 / 3) = 42` such direct-chain requests can be in flight, with two
descriptors left unused. Indirect descriptors or a different request shape have
different capacities that the queue API computes.

The proxy reservation is a wait-for node produced by the driver's bottom half;
it owns no driver turn while waiting and returns all proposed moved payloads on
failure. A proven-capacity image may replace it with the handler's synchronous
`reserve_proven`. Individual unchecked `alloc_desc()` operations are not a
conforming public queue API.

### 12.3 Race and select

`race(...)` is a sealed standard-library call contract, not user-definable
source. It reserves all child slots before evaluating an alternative; `race`
requires that capacity to be build-proven and is a build error otherwise. After
reservation, alternatives
are evaluated and staged left-to-right, including their explicit moves, and none
becomes runnable until all are staged. A downstream admission failure is that
child's immediate typed result and leaves that call's arguments unevaluated.
Staging may suspend while reserving actor admission before that
alternative's argument evaluation; those reservations and the current actor
turn appear in the unified wait-for graph, and cancellation releases every
uncommitted reservation without evaluating its arguments. When one alternative produces a value,
the runtime cancels and fully tears down every loser before returning the winner:

```wrela
outcome = await race(
    disk.read(lba),
    timer.after(ms(20)),
)
```

An implementation cannot treat losing-future drop as sufficient when the loser
may own an in-flight device buffer.

## 13. Device receipts and throughput

A non-reentrant driver actor must not hold its mailbox turn for the entire
duration of every hardware operation if it wants several requests in flight.
The standard pattern is submission followed by a sealed receipt.

`Receipt[P]` is the single sealed, strict-linear state machine used by every
protocol that publishes work and later resolves or recovers it. It replaces
the earlier separate `TransferReceipt[P]` and `IoReceipt[P]` types with one:

```text
Receipt[P] =
    Submitted
  | Committed
  | Resolved(P)
  | Recovery
```

A receipt begins in state `Submitted` at admission commit. While `Submitted`,
any failure — cancellation, actor abandonment, driver reset — resolves it to
`Recovery` and hands back `P` unconditionally: the underlying operation has
not yet crossed its protocol's commit boundary, so nothing external can have
happened. Crossing that boundary moves the receipt to `Committed`; a failure
from there still attempts the protocol's specified quiescence path, which may
itself resolve the receipt to `Recovery` with `P`, or may leave the outcome as
the protocol's `OutcomeUnknown` when quiescence cannot be established.
Successful completion resolves the receipt to `Resolved(payload)`, returning
ownership of `P` together with the completion status the caller inspects
afterward. Like every strict-linear awaitable, a `Receipt[P]` reaches its
final resolution exactly once. The compiler verifies a conforming receipt
implementation against this state machine; it is not an implicit
whole-program value-tracing promise.

A public synchronous driver method returning `Receipt[P]` for moved input `P`
MUST declare `@receipt_handoff(input=parameter)`. This is an explicit
compiler-verified proxy contract, not ordinary actor restoration. After
reservation and argument evaluation, the admission commit atomically:

1. moves `P` and a sealed receipt-producer endpoint into the message,
   entering state `Submitted`; and
2. installs the paired strict recovery receipt in the caller frame.

The generated proxy resolves its admission await with that caller-owned receipt
at commit; it does not wait for handler execution. If the actor abandons before
the handler publishes/rejects, supervisor cleanup consumes the queued producer
endpoint and resolves the receipt to `Recovery` with `P`. The compiler
verifies that every handler path consumes the producer exactly once, by
publishing (`Resolved`), typed rejection, or supervised recovery (`Recovery`).
The annotation is legal only on `@driver`, names exactly one `take` input,
and the returned receipt payload must be exactly that input type/brand.
Other actor methods receive no such behavior.

```wrela
# Quick actor turn: validate, reserve, publish, return receipt.
receipt = await disk.submit(op=take operation)?

# Receipt wait; its concrete bottom-half producer is in the wait-for graph.
completion = await receipt
operation = take completion.payload
completion.status?
```

The receipt linearly owns the submitted operation, its completion identity, and
the right to recover the transferred buffer. Resolution returns ownership before
the caller propagates the operation status. The driver actor may accept another
submission after returning the first receipt. Its bottom-half turn drains
completions and resolves receipts without re-entering a suspended external
handler.

A client proxy MAY present these two steps as one `await disk.read(...)` call,
but wait-for, ownership, and cancellation analysis must retain the two-stage
semantics.

A non-reentrant service has no equivalent mechanism of its own:
`@receipt_handoff` is legal only on `@driver` methods, so a service cannot
hand a client an owned recovery receipt the way a driver can. A service whose
state truly requires serial consistency may await a dependency while
retaining its turn; the concurrency it can offer several clients is
expressed explicitly through sharding or child actors, not through
reentrancy or a receipt of its own.

### Open problem (revision 0.1): service-level interleaving

A non-reentrant service that holds its turn across an I/O `await` serializes
every other client behind that one turn — head-of-line blocking at the
service, not merely FIFO ordering in its mailbox. This revision does not
specify an answer. Candidate directions include a declared interleaving
contract that lets specific methods run concurrently against disjoint state,
canonized sharding patterns that turn one hot service into several
independent actors, and head-of-line diagnostics that surface the blockage
before it reaches production. All three are deliberately left unspecified
until the reference appliance produces evidence about which pattern actually
recurs. Until then, the actor-chatter diagnostic
([Build contract](08-build-contract.md)) is required to also report this
specific shape — "this turn awaits I/O while N senders queue" — naming the
blocked turn and its queue depth, even though the design question it points
at remains open.

## 14. Polling and idle behavior

A task marked `poll=True` is polled on every event-loop pass and contains a
checkpoint per pass. If any mandatory poller exists, the executor does not enter
the target's idle sleep.

IRQ versus poll is an image binding choice. App and service APIs observe the same
completion receipts in either mode. A hybrid driver may poll while work is hot,
then arm interrupts and allow sleep after a bounded idle threshold.

The event loop, policy, and queue abstractions are standard-library code. The
atomic park transition and state-machine suspension are compiler/target
primitives.

## 15. Multi-core compatibility

Revision 0.1 implements one scheduler on one core. Its semantic actor model is
already the `N = 1` case of a future per-core scheduler:

- actor state is private;
- mailbox payloads copy or move `iso` values;
- device vectors have exclusive owners; and
- public APIs contain no locks, `Send`/`Sync` bounds, or shared mutable aliases.

A future multi-core revision may change mailbox transport and actor placement.
It may not retroactively weaken the revision 0.1 guarantee that actor messages
share no mutable state.
