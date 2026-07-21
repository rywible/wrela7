# Faults and reliability

**Implementation status:** partial — restricted `Result` and assertions
exist; supervision, restart provisioning, and record/replay are `gap` in the
[conformance inventory](conformance-inventory.md).

## 1. Failure taxonomy

wrela separates failures by whether source is expected to recover.

| Class | Representation | Meaning |
|---|---|---|
| Build error | Compiler diagnostic | The source, image graph, target contract, or required proof is invalid. No artifact is produced. |
| Recoverable fault | `Result[T, E]` | An expected adverse condition that the current operation can report and its caller can handle. |
| Recoverable task failure | `@task -> Result[unit, E]` | A top-level task ended with an expected error; its declared supervisor action receives the owned error value. |
| Structured async exit | `AsyncExit[E]` / `ActorCallError[E]` | An activation was canceled, rejected/expired by deadline, or returned its declared operation error. |
| Peer failure | `PeerFailed` / `ActorCallError[E]` | An awaited actor epoch abandoned or restarted before resolving its reply. |
| Abandonment | Uncatchable actor failure | A bug or violated invariant makes continuing the current actor unsafe. Its supervisor decides recovery. |
| Target-fatal outcome | Generated terminal path | The runtime cannot safely isolate, quiesce, or recover the failure. The target halts or reboots according to policy. |

The target-fatal path is an outcome of failed recovery, not a fourth catchable
language mechanism.

The `AsyncExit[E]`, `ActorCallError[E]`, and `AdmissionResult` variants
summarized above are defined exactly once, in the outcome taxonomy of
[Actors and async](04-actors-and-async.md); this table cites their carrier
types but does not restate their variants.

## 2. Recoverable faults

Expected failures use `Result[T, E]`. Examples include:

- device-not-present or feature negotiation failure at boot;
- I/O status errors;
- invalid UTF-8 or corrupt on-disk data;
- bounded pool or mailbox admission failure where runtime admission is allowed;
- deadline rejection and timeout;
- stale `SlotMap.Key`; and
- authorization or protocol input rejection.

Postfix `?` propagates `Err` after running all lexical teardown between the
expression and the function boundary.

```wrela
pub async fn load(mut self, path: PathKey)
    -> Result[iso[FileData] Bytes, LoadError]:
    inode = self.lookup(path)?
    data = await self.read_inode(inode)?
    return Ok(take data)
```

There are no catchable exceptions. An API's return type is its recoverable
failure contract.

An image-installed task returning `Err` first performs ordinary lexical
teardown, then delivers a bounded owned `TaskFailed[E]` event to the supervisor
action declared for that task. The policy may stop the task, restart its actor,
or escalate. It is not converted into abandonment merely to cross the task
boundary. A unit-returning task cannot use `?` without handling the error.

If an actor abandons with replies outstanding, each reply resolves with
`PeerFailed` before the failed epoch is discarded. The caller observes the
effective actor-call error defined in
[Actors and async](04-actors-and-async.md), never an indefinitely pending reply.

A boundary must not disguise hostile or corrupt external data as a bug. For
example, a bad filesystem superblock is a mount error; an impossible internal
cache state after validated construction is abandonment.

## 3. Abandonment

Abandonment means that a source or runtime invariant was violated and the
current actor cannot safely continue from the next statement. Causes include:

- `panic(message)`;
- failed runtime `assert`;
- checked integer overflow, division by zero, or invalid shift;
- out-of-bounds access not expressed through a checked API;
- use of an invalid internal state or duplicate completion;
- violation of a proven contract caused by a compiler/runtime defect; and
- exhaustion of a resource that the image declared infallible.

Abandonment is not catchable inside the actor. The executor stops the turn,
marks the actor failed, and transfers control to generated cleanup and its
supervisor.

`panic` formatting must be bounded. The target has a device-independent,
allocation-free fatal reporting path so a panic does not depend on the driver
that may have failed.

An ISR cannot perform ordinary abandonment cleanup. An ISR invariant violation
enters the target's bounded interrupt-fatal path because actor teardown is not
safe in top-half context.

## 4. Compile-time assertion

`comptime assert` and `@layout_assert` failures are build errors. They never
become runtime panics.

```wrela
comptime assert QDEPTH.is_power_of_two()

@layout_assert
fn memory_ceiling(report: ImageReport):
    assert report.peak_memory <= 64.MiB
```

An assertion about actual device state cannot be comptime. The driver validates
it at boot and reports an appropriate boot fault or target-fatal rollback.

## 5. Supervision tree

The image graph is also a supervision tree. Every app, service, driver, and
explicit task group has a parent policy. Standard strategies are:

- `OneForOne` — restart only the failed child;
- `OneForAll` — tear down and restart all siblings; and
- `RestForOne` — restart the failed child and children initialized after it.

Each supervisor declares a restart-intensity bound: at most `max` restarts
within a fixed interval. Exceeding the bound causes the supervisor itself to
abandon and escalates to its parent.

```wrela
img.supervise(
    children=[disk, storage, notes],
    strategy=Restart.OneForAll,
    intensity=RestartIntensity(max=3, within=seconds(10)),
)
```

The root supervisor chooses target reboot, halt, or a target-specific degraded
mode. No failure is silently restarted without a declared policy.

## 6. Zero-allocation restart, precisely

Task frames, actor storage, mailbox storage, and region backings are already
reserved. Restart normally requires no fresh runtime allocation. It is not,
however, a raw `memset` over live resources.

Generated restart performs:

1. stop selection of new turns and children while applying the specified
   bounded mailbox behavior for messages arriving during restart;
2. atomically close request admission for the failed epoch and cancel/tear down
   its child registrations;
3. activate the generated cleanup dependency graphs and quiesce or reset any
   device that may own DMA;
4. run every ready strict/reclaim node in deterministic reverse source order,
   delaying nodes whose receipt/recovery dependencies are unresolved;
5. return or invalidate every branded `iso`/pool handle according to its owner
   contract;
6. resolve every outstanding reply with `PeerFailed`; successfully admitted
   `take` arguments remain consumed unless an explicit receipt/result contract
   returns them;
7. clear task frames and actor fields only after they own no live
   external resource;
8. obtain each linear constructor argument from its manifest restart provision:
   remint a quiesced device capability, redraw reclaimed branded pool handles,
   or retain a declared immutable dependency;
9. run the actor's possibly fallible initializer, rolling back fields in reverse
   initialization order on `Err`; and
10. resume FIFO mailbox selection after invariants are re-established.

The compiler must prove that every frame and actor field is covered by this
teardown. A live `iso` handle outside the frame is followed to its declared pool
owner or transferred to a supervisor cleanup action; it is never leaked by
resetting the handle bits.

Every linear initializer argument must have exactly one recovery source in the
image graph. A missing or ambiguous provision is a build error. A reminted
capability belongs to the new device epoch and cannot coexist with authority
from the failed epoch; reclaimed pool slots cannot be redrawn until teardown has
returned all handles required by the provision.

Supervision epochs never wrap. If the fixed-width epoch reaches its maximum, the
runtime escalates to the root target-fatal reboot/halt policy before creating
another epoch. The same rule applies to request, task-slot, and recovery
identifiers whose reuse could make stale state appear current.

If cleanup cannot establish device quiescence, the policy may quarantine a
bounded device/pool pair or escalate. It cannot reuse possibly device-owned
memory.

## 7. Partial state and actor recovery

Non-reentrant actor turns may temporarily move a field out while awaiting a
dependency. Definite-initialization analysis guarantees normal paths restore
the actor invariant. The async frame's teardown table covers abnormal paths.

An actor may define a bounded recovery hook that consumes validated persistent
state and manifest dependencies. It does not receive arbitrary access to the
failed frame. A recovery hook that fails causes normal supervisor escalation.

Persistent application data is not automatically rolled back with an actor.
Storage APIs must define transaction/idempotence semantics separately.

## 8. Device failure outcomes

Device timeouts and reset require more precision than success/failure. An
operation can report:

```wrela
enum CompletionOutcome:
    Completed
    NotCompleted
    Unknown
```

`Unknown` is especially important for writes: the device may have completed the
write before reset even when no completion was observed. Callers may retry only
when the operation is idempotent or protected by a higher-level transaction or
deduplication key.

Reset errors identify every operation invalidated by the reset epoch. A
per-queue or device reset can therefore fail sibling requests; it cannot pretend
only the request that triggered cancellation was affected.

## 9. Deterministic record/replay profile

The one-core, cooperative, closed runtime permits a deterministic-recording
profile. This profile is optional for a target but normative when advertised.

In record mode the target records every nondeterministic input at a sealed
boundary, including:

- device completion/configuration events and every byte range written by DMA or
  returned by an external read;
- interrupt arrival plus its logical injection point when it can affect ordinary
  execution;
- timer values and deadline-clock observations;
- entropy or random values exposed through an approved capability;
- boot-time device/configuration inputs that affect runtime logic; and
- any target instruction whose result is nondeterministic; plus
- the operation kind, byte extent, and deterministic digest of each externally
  visible output used for divergence checking.

Ordinary code cannot read raw TSC/cycle counters, `RDRAND`, or equivalent
sources. It uses target capabilities that record or virtualize them.

The executor has deterministic tie-breaking for equal-priority ready work.
Record mode stores enough event order and data to reproduce every state
transition from the same sealed image and declared initial persistent state. An
injection point is a compiler-emitted semantic checkpoint ID plus its activation
counter. A target that permits interrupts between checkpoints must instead log a
precise target instruction/branch counter and prove replay can inject at the same
architectural boundary. Arrival order alone is not conforming.

Replay mode does not consult live devices for recorded inputs. A virtual typed
boundary supplies recorded register-read results and DMA bytes, injects
interrupts at their recorded points, and suppresses real device writes. It MUST
verify output operation kind, extent, order, and digest against the recorded
sequence. It verifies that the program requests inputs in order; any operation,
byte extent, checkpoint, or output mismatch is a replay diagnostic.

### 9.1 Log bounds and confidentiality

Record buffers are bounded pools. The image declares whether a full buffer:

- stops recording with an explicit marker;
- streams through a dedicated logging device; or
- abandons because complete replay is a hard requirement.

Dropping events silently is forbidden. Replay logs may contain sensitive input;
their storage/encryption policy is outside the language but must be explicit in
the image profile. `Secret` values are not automatically safe to log.

### 9.2 Time-travel debugging

A debugger may take bounded checkpoints of image regions and replay forward to
simulate reverse execution. Checkpoint format is a tool/target concern. The
language contribution is deterministic scheduling and a finite set of typed
input boundaries.

True multi-core execution would invalidate this simple determinism theorem and
requires a different record/replay specification.

### 9.3 Recovery debuggability

The record/replay profile and the image report MUST expose the
cleanup-dependency-graph states named in
[Actors and async](04-actors-and-async.md) — child registration, quarantine,
pending/ready cleanup nodes, receipt/recovery transfer, and mailbox
reopening — as first-class replay events, not only their net effect. A
conforming implementation must let a deterministic replay viewer answer "why
is my request not resolving" by walking the exact cleanup-dependency graph a
stalled or canceled request left behind: which nodes are still pending, which
recovery dependency they wait on, and which quarantined region or receipt
blocks them. This is a requirement on the profile's event/state exposure, not
new replay semantics; the determinism guarantee of section 9 is unchanged.

## 10. Sealed-image deployment

Installing or changing an application rebuilds and reseals the image in revision
0.1. There is no app store, plugin loader, or `dlopen` equivalent.

A/B image deployment is compatible with the model. Persistent formats carry
versioned layout/schema hashes. If a new image changes a persisted type's
declared layout or schema, the deployment build must provide a comptime-checked
migration path or reject the update package.

In-memory region layouts are not hot-migrated. An update boots the new image and
reconstructs runtime state from declared persistent formats and provisioned
secrets.

Verified install-time bytecode is a possible separate product tier, not an
implicit future compatibility promise of this specification.

## 11. Contracts and checks

Critical standard-library protocols may expose preconditions, postconditions,
and invariants to the compiler. Revision 0.1 requires executable checks and
whole-image proofs for the specific rules named by this specification—bounds,
effects, ownership, queue states, and protocol transitions.

A general user-facing design-by-contract or proof language is deferred. The
absence of that general syntax does not permit a driver library to omit the
required queue and DMA checks.
