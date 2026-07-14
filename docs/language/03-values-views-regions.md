# Values, views, and regions

## 1. One model, three access verbs

wrela has value semantics. Source code names values, not addresses, and a
function requests one of three forms of access:

| Access | Meaning | Aliasing |
|---|---|---|
| `read` | Observe a value for the duration of the call. This is the default. | May coexist with other reads. |
| `mut` | Mutate the caller's value in place. | Exclusive for the access duration. |
| `take` | Transfer ownership into the callee or destination. | The source becomes uninitialized. |

The compiler chooses registers, stack slots, in-place storage, or pointers in
the ABI. Those representation choices are not source semantics.

```wrela
fn hash(data: Bytes) -> u64:                 # read
    ...

fn fill(mut data: Bytes):                    # exclusive mutation
    ...

fn send(take data: iso[Packets] Bytes):      # move
    ...

h = hash(data)
fill(mut data)
send(take data)
```

No call marker means read access, not an implicit copy. Core scalars duplicate
implicitly. Every independent non-scalar duplicate is written `copy value`;
otherwise assignment and value construction move their operand.

## 2. Copyable and linear values

Scalars, structs, arrays, tuples, and enums composed entirely of copyable
payloads are copyable. Copyability is structural and has no size heuristic.
Duplicating a non-scalar copyable value requires the explicit `copy` expression
and produces an independent value.

Classes, capabilities, queue permits, completion tokens, `iso` handles, region
handles, and values that contain any of them are linear. A linear value has one
owner and cannot be implicitly copied or silently overwritten. Linear values
belong to one of two teardown classes:

- **Reclaimable linear** values have a compiler-known, non-failing consume
  action. Branded `iso` pool handles and compiler-owned arena slots are the
  primary examples. Early return, `?`, cancellation, failed initialization, and
  abandonment cleanup may invoke that action implicitly. Reclaiming destroys
  the payload and returns its bounded backing slot; an API that promises to
  preserve the payload must instead return it explicitly.
- **Strict linear** values carry protocol or authority meaning that cannot be
  represented by forgetting them. Capabilities, queue permits, device receipts,
  repair tokens, and active protocol states are strict. Every control-flow edge
  must explicitly consume, return, transfer, or protect them with a scope whose
  exit contract does so.

A composite is strict when any field is strict; otherwise it is reclaimable
when all non-copy fields have generated reclaim actions. The compiler records
each implicit reclaim in teardown metadata and tooling. Bounded byte and string
buffers are non-copyable by default so that large copies remain visible. They
provide explicit operations such as `copy()` and `to_bytes()` when a copy is
intended.

```wrela
point2 = copy point1             # copyable Point: independent value
packet2 = take packet1          # Packet is linear
snapshot = buffer.copy()        # explicit bounded copy
```

An implementation MAY elide any copy or move when observable value behavior and
teardown order remain unchanged.

## 3. Exclusivity

While `mut x` is active, no other access path may read, mutate, take, or move
the same storage, except a read projection explicitly derived from that mutable
access. Deriving such a read projection temporarily freezes mutation until the
read ends.

Exclusivity is checked on storage paths, not merely variable names. The compiler
must recognize overlap through fields, indexes when equal or potentially equal,
and projections returned by accessors.

```wrela
fn combine(mut left: Bytes, mut right: Bytes):
    ...

combine(mut buf, mut buf)
# error[access]: two exclusive arguments may refer to `buf`
```

Disjoint constant fields and array indexes MAY be proven separate. When
disjointness cannot be proved, source can move values into separate locals or
use a standard-library split operation whose contract proves separation.

## 4. Views: second-class projections

`view T` is a read-only projection of storage owned elsewhere. `mut view T` is
an exclusive read-write projection. Neither is a general reference and neither
has a source-level lifetime parameter.

```wrela
projection header(read packet: Packet) -> view Header from packet:
    yield packet.header

hdr: view Header = header(packet)
validate(hdr)
```

### 4.1 Lexical lifetime

A view's lifetime is derived lexically:

1. it begins after the binding or argument is initialized;
2. it extends through every control-flow path on which that binding may be used;
3. it ends at its last lexical use, and no later than the end of the containing
   block; and
4. a control-flow join conservatively retains the view when any incoming path
   retains it.

This is not runtime reference counting. The compiler computes the interval from
source structure and reports the source path it freezes.

A yielded view is a re-projection of storage owned by a receiver or parameter in
the projection's declared `from` set. It receives a new lexical lifetime in the
caller. Only a `projection` may yield it; ordinary functions cannot return a
view of any source, local, or call-region temporary. The source's `read` or
`mut` access is extended through the projection activation rather than ending
at the call boundary.

```wrela
projection longer(a: Bytes, b: Bytes) -> view Bytes from a, b:
    if a.len() >= b.len():
        yield a
    else:
        yield b
```

The result conservatively depends on both inputs. Neither source may be mutated
while the caller's result remains live.

### 4.2 What a view cannot do

A view MUST NOT:

- be stored in a class or struct field;
- be inserted into a collection or `iso` value;
- be captured by an escaping closure;
- be included in an actor message;
- be submitted to a device;
- remain live across `await`, `yield_now`, task suspension, or an ISR return;
- outlive its source; or
- cross a scope whose teardown may invalidate its source.

```wrela
class Holder:
    held: view Bytes             # compile error: fields cannot contain views

async fn bad(mut self):
    block = self.cache.peek(7)
    await timer.sleep(ms(1))     # compile error: `block` is live across await
    consume(block)
```

The complete diagnostic must name the view binding, its source, the suspension
point, and the last use keeping it live.

An async function cannot expose a `view` in an actor API. A `read` or `mut`
access to an external argument cannot survive suspension; the function must
take ownership or end the access before `await`.

There is one actor-local exception: a whole-value access rooted at the actor of
the current non-reentrant turn may survive suspension. This includes an access
to a transitively owned ordinary class such as `self.fs` or
`self.fs.cache`. The frame stores a compiler path rooted at the actor and
re-derives it on resume; it does not store a source-visible pointer or view.
Exclusivity still applies against internal calls and structured child work. The
access cannot be sent to a child, and moving any ancestor of the path requires a
suspend-safe restoration obligation before suspension. Actor restart tears down
the turn and actor together, so the path is never resumed into a replacement
instance.

A private helper on an external argument is legal only when that argument's
access ends before its first reachable `await`. In every case an async return
type cannot contain a view.

### 4.3 Read and mutable projections

A `view T` freezes its source against mutation but may coexist with other read
views. A `mut view T` exclusively loans the projected storage; the entire source
path from which it was projected is inaccessible unless the accessor contract
proves a disjoint path.

Direct field and index projections are built in. A type may define a computed
projection accessor:

```wrela
projection entry(mut self, key: Key)
    -> Result[mut view Item, MissingKey] from self:
    index = self.resolve(key)?
    yield self.items[index]
```

A projection accessor is a synchronous coroutine with exactly one active
`yield` on every successful path. Code before `yield` establishes the
projection; code after it performs synchronous projection teardown. It cannot
`await`, detach work, or transfer ownership of its source.

```wrela
item: mut view Item = table.entry(key)?
item.count += 1
# accessor teardown runs when `item`'s lexical access ends
```

This is the zero-copy read/modify/write mechanism. It replaces holding a stored
reference or copying an entire cache line merely to patch one field.

A view leaf, tuple of projection carriers, `Option[carrier]`, or
`Result[carrier, E]` is legal only as a second-class projection carrier. The
carrier is consumed immediately by a view binding/destructure, `?`, or
`match`; only selected lexical views or the owned error/`None` path survives.
It has no ordinary storage layout, cannot be rebound as a value, and cannot
itself cross `await`. Multiple mutable leaves require a compiler proof that
their paths are disjoint. An unsuccessful projection path executes no `yield`
and releases every temporary access before returning.

```wrela
(left, right) = buffer.split_mut(mid)?
# The names are inferred lexical views; the carrier itself is never bound.
```

### 4.4 Iteration

An iterator that yields `view T` holds a read projection of its collection for
the iteration. Mutation of that collection during the loop is a compile error.
An iterator yielding `mut view T` holds exclusive access and may expose only one
element projection at a time.

## 5. Actor boundaries and `iso`

An `iso[P] T` is a uniquely owned handle to a free-standing region containing a
`T`, branded by its backing pool `P`. No readable or writable alias to the
region exists outside the handle. The handle can therefore move through a
mailbox without copying or locking.

```wrela
packet: iso[NetPackets] Packet = NetPackets.packet(capacity=2048)?
await nic.transmit(payload=take packet)
```

Creating an `iso` value requires an explicit bounded pool or a pool inferred
from an enclosing request/image contract. The brand is inferred in private code
but mandatory in exported signatures and actor messages. The build report
identifies every brand, pool, allocation authority, owner, and capacity. `iso`
does not mean “garbage collected” and does not make an unbounded allocation
legal.

Brands are generative capabilities, not user-chosen zero-sized tags. Every image
pool declaration mints a fresh nominal brand whose identity includes the image
node, even when two declarations use the same display name or element type. A
source brand name may only bind that minted identity; it cannot be reused by a
second pool. Every dynamic request activation similarly introduces an unnameable
fresh brand parameter `R`. Equality, conversion, or substitution between two
fresh brands is impossible, and no cast erases a brand. The compiler rejects a
brand that escapes the declaration/scope that minted it.

A request-backed brand `R` is scoped to that exact dynamic request lineage. It
cannot be named outside the scope, stored in an image-lifetime field, returned
outside the request, or sent to an actor turn that was not atomically admitted as
a child of that request. A durable image-pool brand may be stored in actor state
and transferred between actors. These are type/provenance rules, not an
optimistic escape-analysis convention. Reclaiming any `iso[P] T` returns the
slot to the one pool that minted `P`, regardless of which actor owns the handle.

Calling a method through an `iso` handle automatically derives a call-local
whole-payload read or mutable access according to the method receiver. For
example, `buffer.capacity()` reads and `buffer.set_len(n)` mutates the payload;
neither consumes the handle. The derived access cannot escape, cross an actor
boundary, or remain live across suspension. A `take self` method consumes the
handle explicitly.

At an actor boundary:

- scalar message values are copied into bounded message storage;
- a non-scalar copyable message value crosses only when the caller writes
  `copy value`; the resulting temporary is moved into message storage;
- immutable image-static values cross through explicit `Static[T]` handles;
- a non-copy value crosses only through `take` as a branded `iso` handle; and
- `view`, `mut view`, `mut` arguments, and ordinary object identity cannot
  cross.

The logical copy establishes value semantics. The optimizer may place the value
directly in its final slot, pass it in registers on a proved actor fast path, or
remove a copy whose source is dead, provided the actor as-if rule in
[Optimization model](09-optimization-model.md) is preserved. Moving an `iso`
handle never copies its payload.

This makes actor granularity an explicit zero-copy decision. A filesystem and
its block cache may live inside one storage actor and exchange views internally.
The storage actor and disk-driver actor exchange owned DMA buffers.

An actor reply may return ownership:

```wrela
pub async fn read(mut self, lba: u64,
                  take buffer: iso[BlockPayloads] DmaBlock)
    -> IoCompletion[iso[BlockPayloads] DmaBlock]:
    ...

completion = await disk.read(lba, buffer=take buffer)?
buffer = take completion.payload
completion.status?
```

Ordinary actor admission transfers `buffer` irrevocably when enqueue succeeds.
A later peer failure does not reconstruct it. APIs that promise return of an
input must encode that promise in their reply type and implementation, for
example `Result[(Reply, P), (CallError, P)]`, or consume it into a sealed
`TransferReceipt[P]` before publication. Such a receipt owns the payload until
a typed `commit` transition; before commit every failure returns `P`, while
after commit failure may be `OutcomeUnknown` unless the external protocol proves
quiescence. Device receipts use this explicit model. A suspend-safe outer scope
may move a field only into an awaitable whose type carries the required return or
recovery contract.

## 6. Region classes

Every allocation is assigned to exactly one of the following region classes.

### 6.1 Image region

The image region lives for the image. It holds:

- the actor graph and owned actor state;
- mailboxes, ready queues, task slots, and supervisor metadata;
- declared static pools and device tables;
- immutable baked data; and
- allocations promoted because their required lifetime is image-wide.

Image objects have fixed addresses or fixed placement within the emitted image
and its reserved memory. “Image region” does not imply writable data is placed
in the executable file; the target may reserve zero-filled memory at boot.

### 6.2 Task-frame region

Each async activation occupies a generated task-frame slot. The frame region
holds the state discriminator and every value live across an `await`. It is the
task arena; there is no second implicit per-task heap.

The compiler computes a maximum frame size and a maximum number of simultaneous
activations. Frame slots are reserved in the image region and reset after
completion or supervised teardown.

Frame size is the size after required state-sensitive layout. Values live in
mutually exclusive suspension states MAY share storage, and values MAY be
recomputed instead of stored when doing so preserves effects and work budgets.
Two simultaneously live activations never share mutable backing. Any storage
overlay used to satisfy a memory budget is part of deterministic layout, appears
in the image report, and is verified independently of optional backend
optimization.

### 6.3 Call region

The call region holds synchronous temporaries that do not survive suspension.
It is implemented with the generated executor stack, registers, or bounded
stack-like scratch storage. Views live only in call regions.

The compiler computes the maximum synchronous call depth. Unbounded recursion
or a call graph whose stack bound cannot be established is a build error.

### 6.4 Request region

A request region is a nested, suspend-safe region opened by
`with request(...) as req[region R]`, where `R` is a fresh unnameable brand for
that activation. It owns a deadline, cancellation state, cleanup dependency
graph, child task slots, queue permits, and request-scoped buffers. It may live
across `await` because its handle is part of the task frame. The source may omit
`[R]` when it never names a request-backed type; tooling always displays it.

Normal completion resets it. Cancellation or abandonment first initiates its
generated teardown. Pure memory/resource actions run immediately; in-flight DMA
may quarantine the region while a generated high-priority turn on the owning
driver establishes quiescence. Only that completion permits reset. Request
regions are detailed in
[Actors and async](04-actors-and-async.md).

### 6.5 `iso` and pool regions

An `iso[P]` region has a lifetime defined by brand `P`. A bounded pool owns its
backing storage; a unique handle owns each occupied slot or subregion. Moving
the handle moves the lifetime responsibility without erasing its provenance.

Long-lived rings of transferable buffers therefore use a pool region, not a
task region. The ring owns some handles, actors temporarily own others, and the
total count remains the pool capacity.

## 7. Region inference

The compiler assigns regions using whole-image escape and liveness analysis.
The source usually names no region. The following rules make inference
predictable:

1. A value reachable from the image graph belongs to the image region.
2. A local live across `await` belongs to its task-frame region unless it is an
   owned handle to a nested request or `iso` region.
3. A local not live across suspension belongs to the call region.
4. A value moved through a mailbox belongs to a durable branded `iso`/pool
   region whose public type exposes that brand.
5. A container and its owned elements are region-homogeneous unless the
   elements are `iso` handles.
6. A closure cannot escape its region unless every non-copy capture is moved
   into an explicitly bounded `iso` region.
7. A value's region cannot depend on a runtime branch. The compiler takes the
   least common enclosing region at a control-flow join.
8. A request allocation belongs to that request. Moving it cannot change its
   brand or lifetime; conversion into a durable pool requires an explicit copy
   or consuming transfer operation whose destination slot was reserved in that
   pool.

The no-stored-view rule makes access lifetimes syntactic; it does not make
allocation lifetime inference infallible. When a required lifetime cannot be
kept local, the compiler may promote the allocation to the image region only if
doing so remains statically bounded.

## 8. Promotion and budgets

Every promotion to the image region is a build diagnostic with a why-chain:

```text
warning[region-promotion]: `buffer` promoted from task frame to image region
  allocated at storage/log.wr:41
  escapes through `self.pending` at storage/log.wr:48
  `self.pending` is reachable from image actor `Logger`
  footprint contribution: 64 KiB × 8 slots = 512 KiB
```

`@no_promote` on an allocation, function, actor, or module turns such a
promotion into a build error. A hard memory `@budget` implies `@no_promote` for
unaccounted promotion inside its scope.

The compiler MUST NOT silently turn an unbounded allocation into image storage.
If neither a finite region bound nor legal promotion exists, the build fails.

## 9. Bounded allocation

There is no ambient heap. Runtime-variable allocation occurs only through a
bounded region or pool whose capacity is visible to whole-image analysis.

```wrela
with arena(capacity=256.KiB) as frame:
    scene = frame.list[Node](max=4096)
    compose(mut scene)
# one reset releases the frame
```

If the compiler proves that an allocation cannot exceed its region capacity,
the operation is infallible. Otherwise the allocating API returns a recoverable
`CapacityError`. An image profile may forbid capacity failures in selected
actors and require a proof instead.

Resetting an arena is O(1) only after all values requiring teardown have been
torn down. The compiler emits those actions before resetting the bump pointer.

## 10. Graph-shaped data

Stored object references and intrusive pointers are not the revision 0.1 graph
model. The standard pattern is `SlotMap[T, N]`:

```wrela
map: SlotMap[Node, 1024]
key = map.insert(value=take node)?
match map.get(key):
    case Some(node):
        inspect(node)
    case None:
        return Err(GraphError.stale_key)
```

`SlotMap[T, N]` mints a fresh non-wrapping instance ID at construction, and its
`Key` is the copyable `(map_id, index, generation)` value. Removing a slot
increments its generation before reuse. A generation never wraps: a slot at its
maximum generation is permanently retired, and insertion returns
`GenerationExhausted` if no unretired free slot exists. `get` and `get_mut`
compare all three fields and return `None` for a foreign-map or stale key,
preventing cross-map confusion and ABA reuse.
Their `Option[view T]` results are second-class carriers consumed by the
immediate `match`. Links between nodes store keys. Accessors return lexical
views, never storable references.

A container and its elements share a region. A container of `iso[P] T` owns
only the handles; the branded pointed-to regions remain independently
transferable.

Builders accumulate owned values or keys. A builder cannot retain a view of a
previously added element.

## 11. Deterministic teardown and `with`

`with` is the universal scoped-effect construct:

```wrela
with irqs_masked():
    update_route()

with request(deadline=deadline) as req[region R]:
    ...

with device.claimed() as claim:
    ...
```

Library and application types define a custom scope with `scope`, `enter`, an
optional acquisition `abort`, and `exit`. A scope's result is an owned value,
never an implicit view:

```wrela
@suspend_safe
scope transaction(mut self) -> Transaction:
    enter self.begin_transaction()
    abort:
        self.abort_partial_transaction()
    exit transaction:
        self.finish_or_rollback(mut transaction)
```

An actor-local suspend-safe scope may protect temporarily incomplete actor state
with a compiler-sealed repair token. The token records only the owning actor,
field path, and exit action; source cannot dereference, store, send, or copy it.
The non-reentrant turn remains the sole owner while suspended. This is how a
cache can move a line into a request, await I/O, and still have a deterministic
rollback without storing a mutable projection in the frame.

Moving a field out of a suspend-safe scope into structured child work creates a
**restoration obligation**. The move is legal only when the awaitable's explicit
result or sealed cancellation contract returns that owned value, or when the
scope's exit contract explicitly permits consuming it. Ordinary actor calls do
not provide restoration merely because they accept `take`. Generated
cancellation runs child teardown and discharges the obligation before making the
dependent outer exit action runnable.

Entering a `with` scope evaluates the acquisition prefix and `enter`
expression before the scope becomes active. Before `enter`, source may perform
read-only validation freely. After its first mutation, move from an external
place, or strict-resource acquisition, every path that can leave or abandon the
prefix MUST be covered by an explicit non-suspending `abort` clause that restores
those places and consumes those resources. If `abort` is omitted, the compiler
must prove that the prefix cannot leave, fail, abandon, mutate external state, or
create an obligation. `enter` commits acquisition atomically, transfers the
result into the scope, and registers the exit node. An abort failure is a double
fault and escalates to the target-fatal policy after all independent cleanup
nodes have been attempted.

The abort clause runs for `?`, explicit return/control exit, and generated
abandonment cleanup before `enter`. It may reference only parameters and locals
definitely initialized on every covered pre-enter exit. Acquisitions with
different partial states must initialize an `Option`/state enum before the first
effect or be decomposed into nested scopes; the compiler never guesses which
resources exist.

Active scopes and strict obligations form a statically shaped cleanup dependency
graph, not merely a stack. Source nesting adds reverse-acquisition edges, while a
moved field adds an edge from its recovery/return node to the exit action that
needs it. On teardown, every ready node runs in deterministic reverse source
order; a blocked node waits for its sealed producer while unrelated ready nodes
continue. The runtime resolves cancellation only after the graph is empty. Exit
actions therefore run in reverse acquisition order except where an explicit
resource dependency delays one. They run on:

- fallthrough;
- `return`, `break`, and `continue`;
- `?` propagation;
- structured cancellation; and
- supervisor cleanup after abandonment.

An abort or exit action MUST NOT contain a source `await`. It may use only
memory and authority retained by the scope. It cannot fail with an ignored
recoverable error: a scope protocol must either return an error before entry succeeds,
complete teardown, or escalate to abandonment/target-fatal handling when safe
teardown is impossible. A sealed device/request exit may hand a strict receipt
to a generated driver recovery turn and quarantine its region. That is deferred
reclamation, not an async source destructor: the canceled frame never resumes,
the owning driver retains hardware authority, and the event loop may continue
running unrelated work.

Each scope type declares whether suspension is allowed while it is active.
Request and nursery scopes are suspend-safe. A live view, mutable projection,
IRQ-masked scope, or ordinary device-register transaction is not. `await` inside
a non-suspend-safe scope is a compile error.

`@suspend_safe` requests verification; it is not an unsafe promise. The compiler
must prove that the scope stores only owned/frame-safe state, that every moved
resource has an explicit restoration or consumption path, that the cleanup graph
is acyclic, and that abort/exit actions need no live view or forbidden effect.

Strict-linear resources cannot be created and then forgotten. They must be
moved to another owner, returned, installed in the image graph, or acquired
under a scope whose exit action consumes them. Reclaimable-linear resources may
be consumed by their compiler-generated reclaim action on an abnormal lexical
exit; that action and its pool destination are part of the build report.

On every ordinary block/function exit, remaining reclaimable locals and
callee-owned `take` parameters are reclaimed in reverse successful
initialization order after dependent scope exit nodes. Composite reclaim visits
initialized fields in reverse field-initialization order. Copy-only values need
no action. Revision 0.1 has no arbitrary implicit user destructor: an effectful
or fallible teardown protocol must be expressed by `scope`. Overwriting a live
linear place is always an error; source must move, reclaim through its sealed
operation, or close its scope first.
