# Hardware safety

The reference virtio contracts in this revision target the modern split-ring
model of OASIS VIRTIO 1.2. Each target package MUST pin the protocol revision it
implements. Later features are available only when named in that versioned
contract; the per-queue recovery path below is the `VIRTIO_F_RING_RESET`
feature, with full device reset as the baseline fallback.

## 1. Authority, not privilege rings

A wrela image has one address space. Driver/application separation is enforced
by typed authority and role effects rather than a userspace/kernel transition.

Hardware operations require unforgeable values minted while the image binds a
declared device to a driver:

- `DeviceCap[D]` — authority over one branded device instance;
- `Mmio[L]` — a bounded typed register layout derived from that device;
- `IrqCap[V]` — authority over one interrupt vector;
- `DmaPool[P, N]` — a bounded DMA region with a purpose brand; and
- target-specific narrow capabilities such as a queue notifier.

Capabilities are linear. Their constructors are not source-visible. A numeric
address, an imported type name, or a cast cannot create one.

```wrela
@driver
pub struct BlkDriver:
    irq_regs: Mmio[VirtioIrqMmio]
    queue: VirtQueue[..128]

    init(mut self, take cap: DeviceCap[VirtioBlock],
                take pool: DmaPool[BlockDma, 256.KiB]):
        claimed = VirtioBlock.claim(take cap)
        self.irq_regs = claimed.map_partition(VirtioIrqMmio)
        ...
```

`@driver` takes no device argument; it only marks the constructor eligible to
receive capabilities. The bound device is named once, at the image binding
(§13), by `img.driver(BlkDriver, device=blk_device)` — the single source of
truth for that association.

## 2. Role checking

The compiler assigns hardware effects transitively over the call graph.

- Only an `@image` binding may receive an unbound device declaration.
- Only the matching `@driver` constructor receives its `DeviceCap`, IRQ caps,
  and DMA pools.
- A function using MMIO, DMA submission, IRQ registration, or reset must be
  reachable through the matching driver authority.
- `@app` and ordinary `@service` actors cannot have hardware capabilities in
  fields, parameters, messages, or captured closures.
- A driver may export safe actor APIs. It cannot export raw capabilities or
  typed MMIO values.

Module privacy reinforces this boundary but is not the proof: even a public
capability type remains unconstructible and role-checked.

```wrela
@app
struct Notes:
    fn poke(mut self):
        mmio_write(0x0a00_0050, 0)
        # error[capability]: no MMIO authority is in scope
```

## 3. Typed MMIO

Raw integer-address MMIO is not part of the safe source language. A driver or
sealed protocol object partitions a capability into declared, non-overlapping
layouts:

```wrela
@mmio(endian=little)
struct VirtioIrqMmio:
    @offset(0x060) interrupt_status: ReadOnly[u32]
    @offset(0x064) interrupt_ack: WriteOnly[u32]
```

The compiler and target ABI check field width, alignment, non-overlap, mapping
bounds, and endianness. Reserved or write-sealed fields use target-library
wrapper types. A driver cannot compute an unchecked register offset.

Minting a layout consumes the covered byte ranges from the device claim. Two
live `Mmio` values, including a protocol object's private mapping, cannot cover
the same register or aliasing range. `map_partition` leaves the uncovered claim
available to the sealed protocol state while returning only the named subset.
An overlapping layout mint is a build error with both field/range declarations.

For modern VIRTIO 1.2 MMIO, the sealed transport protocol—not the application
driver—owns the complete initialization, queue, notification, status, and
configuration partition. Its internal layout includes `DeviceFeaturesSel`
(0x014), `DriverFeaturesSel` (0x024), queue address pairs at 0x080–0x0a4,
optional `QueueReset` (0x0c0), `ConfigGeneration` (0x0fc), and device
configuration beginning at 0x100. It selects both 32-bit feature banks, accepts
mandatory `VIRTIO_F_VERSION_1` bit 32, and may negotiate
`VIRTIO_F_RING_RESET` bit 40. The worked driver maps only the disjoint
interrupt-status/acknowledge partition needed by its ISR. This prevents raw
driver access from bypassing the typed protocol-state machine.

MMIO field access is volatile and effectful. It cannot be eliminated, merged,
or reordered across target-defined I/O ordering boundaries. `Mmio[L]` is tied to
the device brand from which it was derived and cannot outlive that device claim.

Physical-address extraction is not a general `phys(value)` operation. Only
sealed DMA/queue APIs may obtain and publish addresses belonging to their DMA
pool.

## 4. DMA layout and memory kinds

`@dma` marks a device-visible layout:

```wrela
@dma(endian=little, packed=true)
struct VirtqDesc:
    addr: u64
    len: u32
    flags: u16
    next: u16
```

For every `@dma` type the compiler MUST report size, alignment, field offsets,
padding, and target endianness. A layout with implicit or target-dependent
padding is rejected unless the ABI declaration explicitly specifies it.

`@wire(endian=..., version=..., packed=...)` is the separate annotation for
persistent or network bytes. It fixes every field's scalar encoding, offset,
padding, total size, and schema version independently of the target ABI.
Ordinary structs and `@dma` structs cannot be passed to a byte-decoding
`read_struct` operation; the type must be `@wire` or source must parse fields
explicitly. `@wire` values confer no device authority and cannot contain
linear structs, capabilities, views, native-width integers, floats without an
explicit IEEE encoding, or fields whose representation depends on a target.

wrela distinguishes two kinds of DMA memory.

### 4.1 Transfer payload memory

The one source type for CPU-owned transfer memory is `iso[P] T`, where `P` is
the fresh brand of a device-bound DMA payload pool and `T` has an `@dma`
layout. `DmaBuffer` is not a second ownership type in revision 0.1. While the
CPU owns the handle, code may read or mutate its payload through call-local
access. Publishing it to a device consumes the handle. Source no longer has a
readable buffer; instead it owns `Receipt[iso[P] T]`.

```wrela
prepared = queue.prepare(
    permit=take permit,
    payload=take buffer,
    direction=DeviceWrites,
)
receipt = queue.publish(operation=take prepared)

# `buffer` and `prepared` are unavailable while the device owns the payload.
completion = await receipt
buffer = take completion.payload
completion.status?
```

The receipt represents the device-owned state in the task/request frame. On a
normal used-ring completion, ownership transitions back to the CPU and the
payload is returned before its `status: Result[unit, IoError]` is propagated.
Touching device-owned payload is unrepresentable, not a runtime convention.

A consuming submission that may reject before publication must either return
the payload inside its rejection value or have an explicit teardown contract
that consumes it. The standard proven-capacity submit path is infallible before
publication; device failure is reported only after payload ownership returns.

### 4.2 Shared control memory

Descriptor tables, available rings, used rings, and similar control structures
are shared with the device for their configured lifetime. They are represented
by `DmaShared[P, L]`, not an `iso[P] T` transfer payload. `P` binds them to
the device/control pool that minted them.

`DmaShared` exposes only field-wise typed operations supplied by its protocol
library. It cannot yield a normal view, be copied into a `Bytes`, or be accessed
with plain loads and stores. Its operations carry the volatile, cache, and
memory-order semantics required by the target.

This distinction prevents a permanently shared ring from pretending to switch
between whole-buffer CPU/device ownership.

## 5. DMA pools and confinement

A DMA pool is declared in the image with a compile-time size, purpose, device
reachability, alignment, and coherency policy. A network pool cannot be passed
to a block driver when their purpose brands differ.

All memory reachable by a device must originate from one of its bound pools.
Where the target offers an IOMMU or second-stage page tables, the target SHOULD
map only those pools writable by that device. Without such hardware, the
language still checks provenance but cannot contain a malicious bus master.

Coherent targets emit ordering barriers. Non-coherent targets additionally
clean caches before device reads and invalidate them after device writes. A
target that cannot implement the declared coherency contract cannot support the
driver safely.

## 6. Queue reservation and submission

A queue API reserves complete operations, not unchecked individual descriptors.
The reservation owns all descriptor slots needed by the selected representation
and prevents capacity underflow.

```wrela
permit = queue.reserve_proven(request=request, descriptors=3)
prepared = queue.prepare(
    permit=take permit,
    header=header,
    payload=take buffer,
    status=status,
)
receipt = queue.publish(operation=take prepared)
```

`reserve_proven` is synchronous and exists only when whole-image analysis proves
that every admitted handler has a complete unit available. When runtime
backpressure is intended, a generated driver proxy waits on queue capacity before
admitting the public synchronous handler and moves a sealed permit in its
message. The handler itself never awaits a permit whose producer is its own
bottom half.

If a request uses three direct descriptors, maximum concurrent capacity is
`floor(queue_depth / 3)`. The queue may use negotiated indirect descriptors, but
that choice is part of its typed representation and build report.

The queue MUST track each operation by at least:

- descriptor head or device-visible operation ID;
- slot generation;
- queue/reset epoch;
- operation kind and direction; and
- owning request/receipt.

Generations and reset epochs never wrap. A queue slot whose generation reaches
its maximum is retired until the next reset; an epoch at its maximum forces a
target-fatal device shutdown before any identifier can be reused. The build
report states widths and the resulting retirement capacity. A device-visible
descriptor head does not authenticate the software generation: the driver must
not reuse that head until the protocol establishes completion or reset
quiescence, and generation checks protect software bookkeeping rather than
distinguishing a malicious stale device completion after unsafe reuse.

Completion is keyed by the ID read from the device's used ring, not submission
order. All payloads in a completed descriptor chain transition ownership as one
operation only after the completion identity and epoch validate.

Stale, duplicate, unknown, or already-completed IDs are driver faults and cause
abandonment or device recovery according to the supervisor policy. They never
index unchecked memory.

## 7. Ordering belongs in protocol operations

Portable driver source does not place standalone `fence_release()` calls around
ordinary ring fields. The standard queue protocol defines operations such as:

- `write_descriptors`;
- `publish_available`;
- `load_used_index`;
- `read_used_element`; and
- `notify_queue`.

Their normative ordering is:

1. descriptor and device-readable payload writes happen before publication;
2. publication of the available entry happens before publication of the new
   available index;
3. the available-index publication happens before the MMIO doorbell;
4. an acquired used index happens before reading its corresponding used entry
   and device-written payload; and
5. ownership returns to the CPU only after all required acquire/invalidate work.

The target library lowers these operations to the correct compiler barriers,
CPU fences, cache maintenance, and I/O barriers. The revision 0.1 AArch64 target
is weakly ordered; a compiler may not assume stronger host ordering.

A custom queue library MAY replace the standard implementation only by
implementing the sealed target ordering interface. It cannot bypass the DMA
ownership transitions.

## 8. Evidence wrappers

An **evidence wrapper** is a sealed generic type that gates a
capability-relevant use of a value until an explicit check clears it. It adds
no field beyond what the check requires; narrowing either succeeds into a
plain value or fails with a typed error, and the wrapper itself grants no
capability. wrela has two instances of this family: `Untrusted[T]`, defined
below, gates a value coming in from outside the trust boundary until it is
checked-narrowed; `Validated[F, T]` (defined in
[Standard library contracts](10-standard-library-contracts.md)) gates
downstream use of a value that has passed a declared format's parser. A build
report or conformance ledger that counts evidence wrappers counts these two as
one family.

Device **protocol/control** values that can influence an index, length,
allocation, completion identity, or control-flow bound have type
`Untrusted[T]`. Examples include used-ring IDs and lengths, configuration
fields, queue sizes, and transport-reported counts. They cannot be used directly
as an array index, slice bound, or allocation size.

```wrela
reported: Untrusted[usize] = completion.written_len
written = reported.checked_le(buffer.capacity())?
text = buffer.prefix(written)
```

Checked narrowing validates both the protocol limit and the actual destination
capacity. Arithmetic on untrusted values preserves untrusted status unless the
operation proves a tighter bound.

Bulk payload bytes written by a device are not automatically taint-tracked as
`Untrusted` element by element. After the queue protocol validates the reported
extent and returns CPU ownership, the payload is ordinary data. Its consumer
must validate the payload's own format before using fields as bounds or
authority—for example, a filesystem validates inode magic, block counts, and
disk extents. Standard parsing APIs return checked values or format-specific
recoverable errors. This keeps transport control validation in the sealed
driver layer without pretending an arbitrary payload format is already valid.

This rule applies even when the virtio backend is normally a trusted
hypervisor; virtio devices can also be hardware.

## 9. Interrupt topology

The ownership unit is an interrupt **vector**, not an entire driver and not an
arbitrary shared line.

- Each vector is bound to exactly one ISR entry.
- A driver may own multiple MSI-X vectors, including one vector per queue and a
  configuration-change vector.
- A virtio-MMIO device may have one dedicated IRQ whose ISR demultiplexes the
  transport's interrupt-status bits.
- Revision 0.1 PCI targets support MSI or MSI-X. Shared legacy INTx is rejected
  by image validation.

The generated vector table and routing metadata come from the image graph.
Source cannot register an ISR for an unowned vector.

For the revision 0.1 target, whole-image lowering resolves each ISR's declared
device binding to the target package's GICv3 SPI/INTID pair. MachineWir retains
that binding, INTID, and unique no-argument handler. Codegen emits the canonical
runtime-ABI route table sorted by INTID; the target runtime supplies the 2 KiB
aligned exception table and dispatcher. A missing, duplicate, spurious-range,
or package-mismatched INTID is a compiler error, not a boot-time discovery.

## 10. The `isr` color

An `isr fn` is a compiler-checked top half. Its transitive effect set is limited
to:

- reading and writing typed MMIO for its bound device;
- acknowledging its bound interrupt source;
- reading or writing explicitly ISR-safe `InterruptCell[T]` state owned by that
  driver;
- invoking other functions proven `@isr_safe` with the same effect subset; and
- calling the runtime wake primitive on a statically bound task/completion.

It MUST NOT:

- allocate or reset a region;
- `await`, park, block, or take a lock;
- call an app, service, or ordinary actor method;
- read or mutate device-owned DMA payload;
- drain an unbounded queue;
- panic through a heap-backed formatter;
- use floating point or SIMD state; or
- invoke a destructor with effects outside the ISR set.

```wrela
isr fn on_blk_irq(self):
    status = self.irq_regs.interrupt_status.read()
    handled = status & (INT_VRING | INT_CONFIG)
    if handled != 0:
        self.pending.fetch_or_release(handled)
        self.irq_regs.interrupt_ack.write(handled)
        wake(BlkDriver.drain_used)
```

An interrupt-status register is untrusted device control. The ISR MUST intersect
it with the transport's declared handled-bit mask before publication or
acknowledgement, MUST ignore undefined bits, and MUST NOT write undefined bits to
an acknowledgement register. The pending level is published before
acknowledgement in the reference lowering; a transport may use another order only
through a sealed operation that proves it cannot lose a level-triggered event.

All substantive work happens in the driver actor's bottom-half turn after the
ISR returns.

## 11. ISR-visible state

An ISR and ordinary code are different compiler contexts even on one core. A
plain `bool` is not a valid communication channel because the optimizer could
cache, merge, or reorder access.

`InterruptCell[T]` provides `load_acquire`, `store_release`, `swap_acquire`,
`swap_release`, `fetch_or_release`, `fetch_or_acq_rel`, and
`fetch_and_acq_rel` for supported scalar types. Every read-modify-write is
interrupt-atomic with respect to every vector
that may access that cell. A target may lower it to one architecture atomic
instruction or to a compiler-generated interrupt-masked section; a sequence of
ordinary load/store operations is not conforming. The compiler includes any
masked implementation in the maximum interrupt-masked interval report.

`InterruptCell` is synchronization between ordinary code and an ISR; it is not
the language's MMIO-volatility abstraction. Typed MMIO and `DmaShared`
operations separately carry volatile/device ordering and cannot be replaced by
an `InterruptCell`.

On a one-core coherent target, non-RMW acquire/release operations may require no
hardware coherence fence while still preventing compiler reordering. DMA
ordering remains separate and may require real fences.

The bottom half waits on a level predicate using the runtime's
mask–arm–recheck park primitive. A wake before park is safe; repeated wakes
coalesce.

The compiler reports the maximum duration of every generated
interrupt-masked section, including ready-queue handle resolution. A target
profile may impose a hard latency ceiling.

Revision 0.1 masks the current vector on entry, forbids same-vector reentry, and
disables nested preemption entirely. Its target contract fixes GICv3 exception
entry, 16-byte stack alignment, no SIMD save or ISR SIMD use, the spurious INTID
range, and acknowledgement/masking/end-of-interrupt order. A future target may
support nesting only with a versioned semantic/backend contract and a strict
static priority order; only a strictly higher-priority vector may preempt, and
the compiler must then include the maximum nesting chain in ISR stack and
masked-interval bounds. Equal/lower-priority vectors remain pending.

## 12. Bottom halves

A bottom half is a high-priority driver turn or task. It:

1. consumes the ISR's level signal;
2. acquires and drains a bounded number of used entries;
3. validates each ID, generation, epoch, and device-reported length;
4. resolves the matching receipt and transfers payload ownership back; and
5. yields at its budget checkpoint if more work remains.

The ISR never invokes app code or mutates an app-visible object. Data reaches an
app only after the bottom half resolves a typed receipt and the scheduler resumes
the owning request.

Driver submissions and bottom halves are serialized as turns of the driver
actor. Public submission handlers are synchronous and return a receipt or typed
admission failure promptly; they cannot await hardware, a queue permit, or
another actor while retaining the driver turn.
When a submission moves a recoverable payload, its public method uses
`@receipt_handoff`: the generated proxy installs the caller-owned receipt in the
same atomic admission transition that transfers the payload. The handler's
source-level receipt return resolves that pre-existing pair; it never creates a
new caller endpoint. Actor failure before publication routes the queued producer
and payload through supervised recovery.

## 13. IRQ, poll, and hybrid modes

Driver mode is a constant generic of the driver struct whenever it changes the
ISR, actor, task, or effect graph:

```wrela
blk = img.driver(
    BlkDriver[DriverMode.Irq],
    device=blk_device,
)
```

The image API does not also accept a runtime or separate `mode=` value. This
single specialization input governs `comptime if MODE`, vector binding, poll
tasks, idle policy, reachability, and reporting. More generally, any option that
changes the actor/ISR/effect graph MUST be a comptime type or constant argument,
never runtime configuration.

In IRQ mode the image binds vectors, emits ISR entries, and may sleep when idle.
In poll mode:

- unused ISR code and vector entries are eliminated;
- the driver asks the device to suppress interrupts when the protocol supports
  it;
- its bounded poll task runs every event-loop pass; and
- the executor does not enter idle sleep while mandatory polling is active.

A hybrid policy is standard-library code: poll while completions remain hot,
then arm interrupts with race-free protocol ordering and permit idle sleep.
Actor callers and receipts are identical in every mode.

## 14. Device protocol states

Device initialization uses typed protocol states so operations cannot occur out
of order. A virtio driver follows a transition equivalent to:

```text
Reset
  -> Acknowledged
  -> DriverClaimed
  -> FeaturesNegotiated
  -> FeaturesAccepted
  -> QueuesConfigured
  -> Running
```

Queue notification and payload publication require the `Running` state. Reset
consumes `Running` and produces a new reset epoch; receipts from an old epoch
cannot complete in the new one.

The manifest may declare required device features and reject an incompatible
target contract at build time. Actual device feature registers do not exist at
comptime. Boot must still negotiate and verify the real device, returning a
boot fault or entering target-fatal startup rollback on mismatch.

The typed protocol API encodes mandatory transition order. Revision 0.1 does not
otherwise define a general session-type language.

## 15. Cancellation and reset

Once a virtio available index exposes a descriptor chain, a driver cannot
generally retract that one request. Dropping its future or forgetting its
receipt is therefore illegal.

When cancellation reaches an in-flight operation, generated request teardown:

1. moves the strict receipt into a generated recovery completion and marks its
   request/queue epoch dead;
2. quarantines every affected request region and DMA slot against access,
   reclaim, or reuse;
3. enqueues a generated highest-band recovery turn on the driver actor that owns
   the queue and MMIO capability;
4. asks the protocol for a non-destructive cancel only if that operation exists,
   treating it as an optimization rather than proof of quiescence;
5. uses negotiated per-queue reset when available, otherwise performs a full
   device reset and reinitialization;
6. invalidates every receipt in the old reset epoch and resolves affected
   owners with the same reset cause;
7. returns or tears down all affected DMA regions after the driver proves
   quiescence; and
8. resolves recovery completions and only then permits request-region reuse.

A queue reset may cancel requests other than the initiating request. Every
affected owner receives a reset error carrying the same new epoch.

After a reset begins, a write may have completed, not completed, or have an
unknown outcome. Recovery reports this explicitly:

```wrela
enum CompletionOutcome:
    Completed
    NotCompleted
    Unknown

struct IoTimeout:
    outcome: CompletionOutcome
```

Source MUST NOT automatically retry a non-idempotent operation with
`CompletionOutcome.Unknown`.

No arbitrary source async destructor is introduced: the canceled source frame
does not resume or execute cleanup code after handing off the receipt. Recovery
is nevertheless scheduler-visible rather than a busy wait on the only core.
The generated driver turn retains the only authority to reset hardware, runs
under a declared target recovery bound and priority, and allows unrelated actors
to run while the region remains quarantined. The compiler includes its actor,
deadline, and work-budget effects in analysis.

If the target cannot prove quiescence within its declared recovery bound, it
must keep the device and bounded DMA region quarantined under an explicit
supervisor policy or enter a target-fatal state. It MUST NOT reclaim possibly
device-owned memory.

## 16. Residual trusted computing base

The following remain trusted:

- the compiler and generated state/teardown code;
- target boot, interrupt, MMIO, DMA, cache, and reset implementations;
- the standard sealed capability constructors;
- firmware and hypervisor behavior assumed by the target contract; and
- hardware isolation configuration such as an IOMMU.

The language prevents an app from naming MMIO and prevents a safe driver from
publishing arbitrary memory. It cannot make a single-address-space target as
fault-contained as mutually isolated hardware processes. Documentation and
security claims MUST preserve that distinction.
