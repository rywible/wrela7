# Wrela image and runtime

> Part 2 of the Wrela design sketch. Companions:
> [core-model.md](core-model.md) — the thesis, the load-bearing assumption,
> and rules R1–R18 (referenced throughout as "R*n*").
> [examples/virtio-appliance.wr](examples/virtio-appliance.wr) — the worked
> virtio appliance.
>
> This is aspirational design, not current compiler input.

This document is the machinery that turns the core model into a bootable
appliance: phases and layers, provenance discipline, the capability classes,
the runtime interfaces, the explicit runtime graph, the generated executor, and
the target/image contract DSLs.

## Phases and layers

Phases answer "when can this code run?" Runtime is the unwritten default
(R15): only boot and fault code is ever marked.

```
phase boot
phase runtime
phase fault
```

Layers answer "which logical surface is this code part of?" A layer is declared
once per class and inherited by methods (R15). Names remain organization and
review structure, while capability effects form a rigid transitive boundary:
wrapping MMIO/DMA/reset authority behind an ordinary interface does not erase
the effect, and a higher layer cannot implement or receive an interface whose
effect ceiling exceeds its vocabulary. There is no platform
layer: root capabilities belong to the image root, which sits above the layer
system.

```
layer driver
layer kernel
layer service
```

## Provenance and layer discipline

Layers name user-writable code: driver, kernel, service. The image root (the
boot fn and executor construction) is not layered code; it is the wiring level where root
capabilities exist. Root capability types (`BootPlatform`, `Firmware`,
`CpuSetup`, `BootMemory`, `PhysicalMemory`, `PciRoot`, `FaultPlatform`) are
sealed intrinsics and boot/fault-phase only. Layer rows below restrict both
which sealed capabilities a layer may name and the maximum transitive effects
of interfaces callable there. Call organization and style remain review-level;
authority effects do not. The compiler also rigidly enforces boot/runtime
reduction, sealed capability identity, provenance lifetimes, and cleanup order.

Ordinary classes and values may wrap capability-derived state, but wrapping
does not erase its provenance or transitive effects. Driver code remains trusted
for protocol semantics; the compiler still tracks where such state came from so it can prove that
boot-only roots do not cross into runtime, derived capabilities do not outlive
their sources, and target/DMA resources clean up in the correct order.

A row without a phase is a runtime row (R15). These rows are both the naming
vocabulary for sealed capability classes and the maximum transitive effect set
for interfaces exposed to that layer:

```
layer vocabulary:
    # Driver binding code may consume claimed hardware capabilities and
    # convert them into typed runtime driver state.
    allow driver boot:
        Claimed[PciFunction]
        Mmio[T]
        DmaPoolBuilder[P, S]
        DmaBuffer[T, N]
        DmaShared[Layout]
        PostBoot

    # Driver code may retain typed MMIO/DMA state and implement executor source
    # hooks, but never the platform root, firmware, PCI root, or boot memory.
    # Driver code is synchronous: `async` is not permitted here (R10).
    allow driver:
        DeviceClaim
        Mmio[T]
        DmaArena[P, S]
        DmaBuffer[T, N]
        DmaShared[Layout]
        DmaRing[T, N]
        Pollable
        DoorbellSource        # implement-only; callable only by generated executor
        ResettableDevice
        PollBudget

    # Kernel code normally names only reduced service contracts and runtime-safe
    # capabilities wired through task handles. Kernel code may be async; waiting
    # is spelled `await` and requires no authority (R12). Recovery is sealed and
    # possessed only where the image wires it (R9).
    allow kernel:
        Console
        Network
        BlockDevice
        Clock
        PanicSink
        Recovery

    # Service/application code is even smaller: domain contracts and
    # runtime-safe capabilities the image or kernel wires to it. The `service`
    # layer is the intended extension point above the kernel; not exercised in
    # the example.
    allow service:
        Console
        Network
        BlockDevice
        Clock
```

**The authority-reduction point** is the most important phase rule:

```
boot fn boot(...) -> Result[RuntimeObjects, BootError]
```

may use boot-only values while constructing the runtime object record, but
boot-only values may not cross the return boundary unless their type is
runtime-safe. Returning bound drivers, Clock, and PanicSink is legal; a
RuntimeObjects field typed `PciRoot` is not, because PciRoot is boot-phase and
nothing after the reduction may depend on it.

## Error vocabulary

Ordinary enums (R6); variants marked `widen` are the `?` lift targets.

```
enum QueueError:
    full
    badDescriptor

enum PciError:
    notPresent
    wrongDevice(found: PciIdentity)
    configFailed

enum MemoryError:
    exhausted
    misaligned

enum DmaError:
    poolExhausted
    tooLarge

enum FirmwareError:
    unsupportedRevision
    memoryMapFailed

enum CpuError:
    pagingFailed

enum RegisterError:
    unknownEnum(raw: U64)
    reservedBits(raw: U64)
    invalidAggregate
    outOfBounds
    misaligned
    unsupportedWidth

enum ResetError:
    unsupported
    quiescenceFailed
    reinitFailed

enum BindError:
    wrongDevice(expected: StaticString, found: PciIdentity)
    missingFeature(feature: VirtioFeature)
    featuresNotAccepted
    badQueueSize
    widen pci(PciError)
    widen memory(MemoryError)
    widen dma(DmaError)

enum BootError:
    contractViolation
    widen bind(BindError)
    widen firmware(FirmwareError)

enum NetError:
    down
    txFull
    frameTooLarge(length: USize, max: USize)
    widen queue(QueueError)
    widen dma(DmaError)

enum IoSideEffect:
    sideEffectFree
    idempotent
    mayStillHappen
    requiresResetBeforeContinuing

enum BlockError:
    ioError(effect: IoSideEffect)
    outOfRange(index: U64, blockCount: U64)
    widen queue(QueueError)
    widen dma(DmaError)

enum ConsoleError:
    full
    lineTooLong
    widen queue(QueueError)

enum ResourceError[T, E]:
    failed(error: E, recovered: T)

# Opaque, source-branded and non-wrapping. Only a sealed claim/reset transition
# can create the initial epoch or its successor.
primitive type ResetEpoch
```

## Boot capabilities

Handed to the image boot function by the generated UEFI entry code. All of the
capability classes in this document are sealed compiler-provided declarations
from the intrinsic prelude (R1). User code cannot construct or counterfeit any
of these. Each one that owns hardware state has compiler-provided structural
drop glue (release the claim, unmap the BAR, return the DMA region — R4), which
is what makes the reverse-order cleanup on failed boots work.

```
boot class BootPlatform:
    fn split(consume self) -> BootCaps
    fn panic(self, message: StaticString) -> Never


boot type BootCaps:
    firmware: Firmware
    cpu: CpuSetup
    memory: BootMemory
    physicalMemory: PhysicalMemory
    pci: PciRoot
    clock: Clock         # runtime-safe, may cross the reduction
    panic: PanicSink     # runtime-safe, may cross the reduction
    recovery: Recovery   # runtime-safe; wire sparingly (R9)


# The tiny authority handed to the generated CPU-fault path. Not available
# to boot, driver, kernel, or service code.
fault class FaultPlatform:
    fn panic(self, message: StaticString) -> Never


boot class Firmware:
    fn uefiRevision(self) -> U32
    fn memoryMap(self) -> Result[UefiMemoryMap, FirmwareError]
    # Real ExitBootServices requires the current memory-map key and may need
    # the get-map/retry dance; the generated implementation handles it. All
    # firmware-dependent allocation must precede this call; all device DMA
    # enablement must follow it. The compiler requires every other boot-only
    # capability to have been consumed by its retire transition first. The
    # generated retry is target-bounded; exhaustion enters target fatal, so the
    # consuming transition is infallible and cannot violate R4.
    fn exitBootServices(consume self) -> PostBoot


# Proof that firmware services are gone. It is source-unconstructible and is
# required by every bus-master/start transition. It may be lent to several
# sequential starts, then dropped before returning RuntimeObjects.
boot class PostBoot

# After a function obtains PostBoot, no control-flow path may return a
# recoverable boot error or invoke a boot-only capability. It must return the
# fully constructed runtime graph or enter the target-fatal startup rollback.


boot class CpuSetup:
    fn maskDeviceInterrupts(self)   # doorbells stay masked while code runs (R13)
    fn enablePaging(self, consume tables: PageTables) -> Result[(), ResourceError[PageTables, CpuError]]
    fn retire(consume self)
    fn halt(self) -> Never


boot class BootMemory:
    fn reserveStatic(self, name: StaticString, size: USize, align: USize) -> Result[BootRegion, MemoryError]
    # Returns post-exit runtime-owned DMA memory: reserved from firmware
    # reclamation, target-DMA-safe, aligned, coherent or cache-managed by target
    # contract, and charged to the compiler's computed DMA demand.
    fn dmaPool[P, const S: USize](self, name: StaticString) -> Result[DmaPoolBuilder[P, S], MemoryError]
    fn pageTables(self, size: USize) -> Result[PageTableArena, MemoryError]
    # Legal only after every derived builder has been consumed into a runtime
    # arena or cleaned up. Sealing an arena adopts its reserved physical region,
    # so the arena is a new runtime provenance root rather than a BootMemory child.
    fn retire(consume self)


boot class PhysicalMemory:
    fn claim(self, range: PhysicalRange) -> Result[Claimed[PhysicalRange], MemoryError]
    fn retire(consume self)


# PciRoot does not mean "all PCI forever." It is boot-only. It can verify
# and claim one contract-named function, producing a narrower
# Claimed[PciFunction].
boot class PciRoot:
    # Claim begins by disabling bus mastering and interrupt delivery and by
    # reaching the target-certified initial quiescent/reset state. A function
    # that cannot reach it is not claimable.
    fn claim(self, address: PciAddress, expect: PciExpectation) -> Result[Claimed[PciFunction], PciError]
    # Legal only after every child claim was relinquished, cleaned up, or
    # sealed into an independent runtime DeviceClaim.
    fn retire(consume self)


boot class PciFunction:
    fn address(self) -> PciAddress
    fn identity(self) -> PciIdentity
    fn enableMemoryAccess(self) -> Result[(), PciError]
    fn maskInterruptDelivery(self) -> Result[(), PciError]   # arming is executor business (R13)
    # Registers must be a target/ABI-certified layout for this exact claimed
    # function/region. User-written layouts cannot reinterpret a BAR, and
    # overlapping incompatible mappings are rejected by provenance.
    fn mapBar[Registers](self, index: U8) -> Result[Mmio[Registers], PciError] where Registers is certified_mmio_layout


# Exclusive ownership of a claimed resource. Cannot be copied; a claimed PCI
# function cannot be claimed again. Method calls lend the claim (it forwards
# T's methods); it is consumed only by `relinquish`, `sealRuntime`, or a `consume` parameter
# (R2). Dropped without being consumed, its cleanup runs (R4). Values
# derived from a claim (Mmio via mapBar) must be stored alongside it (R4) --
# a bound driver keeps its claim in `storage:` for as long as it exists.
# Claimed[PciFunction]'s boot cleanup resets/quiesces the function before
# derived mappings are destroyed, so a failed negotiation cannot leave an
# acknowledged or queue-enabled device behind.
class Claimed[T]:
    # Relinquishing destroys the authority; it never returns a second raw
    # object that could race a later claim.
    fn relinquish(consume self)
    fn currentResetEpoch(self) -> ResetEpoch where T is PciFunction
    # Provenance-adopting (R4): derived nodes (the Mmio mappings from mapBar)
    # re-parent onto the returned DeviceClaim, so sealing is legal while
    # derivatives are live.
    fn sealRuntime(consume self) -> DeviceClaim where T is PciFunction


# Runtime-safe proof that a device remains claimed. It carries provenance,
# reset identity, and the narrow post-exit operations a driver still needs.
class DeviceClaim:
    fn enableBusMastering(self, postBoot: PostBoot) -> Result[(), PciError]
    # reset/restart have reset_transition visibility: callable only from the
    # generated executor transition, not from arbitrary driver methods.
    fn reset(self, oldEpoch: ResetEpoch) -> Result[ResetEpoch, ResetError]
    fn restartAfterReset(self, epoch: ResetEpoch) -> Result[(), ResetError]
    # Sets a bounded executor-visible flag; it does not perform reset reentrantly.
    fn requestReset(self)
    fn fatal(self, message: StaticString) -> Never

    # DeviceClaim internally tracks quiescent/running state. Its generated
    # pre-drop barrier performs a target-proven disable/reset transition while
    # all DMA dependents still exist; dependent glue then runs, and only then is
    # the claim released. Failure enters target fatal without reclaiming memory.


# Raw MMIO is target/ABI-package-only and cannot be named by image or driver
# source. Drivers receive typed Mmio[T].
abi class MmioRaw:
    # Every access checks mapping bounds, alignment, overflow, and the target's
    # legal width table before touching the bus.
    fn read8(self, offset: USize) -> Result[U8, RegisterError]
    fn read16(self, offset: USize) -> Result[U16, RegisterError]
    fn read32(self, offset: USize) -> Result[U32, RegisterError]
    fn read64(self, offset: USize) -> Result[U64, RegisterError]
    fn write8(self, offset: USize, value: U8) -> Result[(), RegisterError]
    fn write16(self, offset: USize, value: U16) -> Result[(), RegisterError]
    fn write32(self, offset: USize, value: U32) -> Result[(), RegisterError]
    fn write64(self, offset: USize, value: U64) -> Result[(), RegisterError]
```

## Driver capabilities

```
# Typed MMIO. Reads and writes are side-effecting and must not be optimized
# like normal memory. The generic parameter is a `registers` layout, so
# driver code can only access declared fields at declared widths. Register
# reads produce register-safe values; constrained protocol values require
# checked conversion before use. Register access mutates device state, so Mmio
# is an object and lending it grants use (R2). Its deinit unmaps the BAR (R4);
# objects never copy, so a mapping cannot fork.
class Mmio[Registers]:
    fn read[field F of Registers](self) -> F.Type where F.CpuAccess includes public_read
    fn readChecked[field F of Registers](self) -> Result[F.Type, RegisterError] where F.CpuAccess includes public_read
    fn write[field F of Registers](self, value: F.Type) where F.CpuAccess includes public_write
    # Sealed write sides have no ordinary write accessor. Their ABI
    # helpers accept provenance-bearing objects and emit the certified access
    # width/order (including split 32-bit accesses for a 64-bit PCI field).

    # Device-specific sealed helpers may be generated for register layouts
    # that need DMA provenance, such as virtqueue installation. Such helpers
    # derive target bus addresses internally from live DMA objects and write
    # the declared registers without exposing an address-shaped value. Every
    # sealed lowering obeys the publication contract (R8): device-read
    # payloads copy into device-owned staging before publication, the
    # ring-index advance is the publication point, and caller loans end
    # inside the synchronous call.


# Boot-only builder for bounded, purpose-typed DMA memory. There is no ambient
# allocator: a driver gets exactly the pools and buffers boot constructs for it.
# Everything a device can reach lives in memory allocated here (R8), and the
# runtime arena/provenance token is stored alongside the derived memory (R4).
boot class DmaPoolBuilder[Purpose, const Size: USize]:
    # alloc/shared/ring zero-initialize all bytes before returning; there is no
    # public uninitialized DMA state.
    fn alloc[T, const N: USize](self, name: StaticString) -> Result[DmaBuffer[T, N], DmaError] where T is dma_plain
    fn shared[Layout](self, name: StaticString) -> Result[DmaShared[Layout], DmaError] where Layout is register_safe
    fn ring[T, const N: USize](self, name: StaticString) -> Result[DmaRing[T, N], DmaError] where T is dma_plain
    # Provenance-adopting (R4): allocated buffers, shared layouts, and rings
    # re-parent onto the returned DmaArena; the arena also adopts its reserved
    # physical region from BootMemory and can survive BootMemory.retire.
    fn sealRuntime(consume self) -> DmaArena[Purpose, Size]


# Runtime-safe provenance token for a boot-allocated DMA region. V1 does not
# expose runtime allocation from this arena; future versions may add bounded
# runtime allocation as an explicitly analyzed resource.
class DmaArena[Purpose, const Size: USize]


# TRANSFERABLE payload memory (R8). While held, a DmaBuffer is ordinary
# owned memory: lend it, view it, fill it. Consuming it into submit
# machinery is the only way the device ever sees it; it comes back through a
# completion. CPU access to in-flight memory is unrepresentable -- you do
# not hold the value.
class DmaBuffer[T, const N: USize] where T is dma_plain:
    # Public CPU-side methods are ordinary buffer methods. Device addressing is
    # consumed by sealed descriptor/register builders so raw bus addresses do
    # not become programmable scalar values in source.
    fn view(self) -> View[T]
    fn slice(self) -> Slice[T]
    # A device-writable completion restores ownership but marks every value
    # foreign-derived; only guarded access may use it for protocol decisions.


# SHARED control memory (R8): virtqueue rings and their cousins, watched by
# the device forever. Never CPU-owned: no lends, no Views, no plain loads.
# Access is typed, volatile, and field-wise through the same
# `registers`-declared layout discipline Mmio uses -- the same rules for the
# same reason: a concurrent reader/writer on the other side. Reads are
# acquire, writes are release (R8): the fences the target's DMA coherence
# model requires are emitted here, so an index read never observes a torn
# or reordered entry.
class DmaShared[Layout]:
    # Device addressing is consumed by sealed descriptor/register builders.
    fn read[field F of Layout](self) -> F.Type where F.CpuAccess includes public_read
    fn readChecked[field F of Layout](self) -> Result[F.Type, RegisterError] where F.CpuAccess includes public_read
    fn write[field F of Layout](self, value: F.Type) where F.CpuAccess includes public_write
    fn read[field F[I] of Layout](self, index: USize) -> F.Type where F.CpuAccess includes public_read
    fn readChecked[field F[I] of Layout](self, index: USize) -> Result[F.Type, RegisterError] where F.CpuAccess includes public_read
    fn write[field F[I] of Layout](self, index: USize, value: F.Type) where F.CpuAccess includes public_write


# A typed submit/drain queue over shared DMA memory, for drivers that want
# the common shape prebuilt rather than hand-rolling over DmaShared.
class DmaRing[T, const N: USize] where T is dma_plain:
    # Device addressing is consumed by sealed descriptor/register builders.
    fn submit(self, consume value: T) -> Result[(), PushError[T]]
    # Pull completed entries out of device-written memory, charging the
    # budget; returned in place (R2). Elements are foreign-derived until a
    # verified guard discharges their fields. Empty list = no progress.
    fn drain(self, budget: PollBudget) -> List[T, N]


# A generated per-pass step ceiling for poll work. Images do not configure this
# explicitly in source; it is derived from the target and the compiler's bounded
# work summaries. Objects never copy (R4), so a budget cannot be silently
# doubled.
class PollBudget:
    fn spend(self, count: USize) -> Bool
    fn exhausted(self) -> Bool
```

Budget units are target-defined but compiler-auditable. The generated summaries
charge at least one unit for each descriptor examined, wait/token registry entry
touched, bounded loop iteration, and bulk copy chunk above the target scalar
threshold; `deinit` of bounded containers is charged by initialized element
count. Entering target fatal exits the budget model because no Wrela object will
resume afterward. Charging is compiler-inserted from the verified cost summary;
driver source cannot omit a `spend` call to evade it. The explicit PollBudget
methods let a driver stop early, but they are not the accounting authority.

## Runtime services

```
class Clock:
    fn now(self) -> Instant
    fn after(self, delay: Duration) -> Wait   # droppable awaitable (R9);
                                             # uses the target's wrap-safe
                                             # deadline predicate


# The panic path is generated, device-independent, bounded, and doorbell-free:
# it writes a best-effort message to the target's dumb escape channel (raw
# serial/debug port or a hypervisor console knock), may truncate, and then
# enters the target's DMA-safe fatal state. It cannot depend on any driver --
# the hung device may be exactly why we are panicking.
class PanicSink:
    fn panic(self, message: StaticString) -> Never


# The authority to accept quarantine/leak semantics (R9): token.tryAbandon
# demands one. Minted at boot through BootCaps and wired only to code
# designated to make hung-device decisions -- typically one supervisor task.
# An image that wires no Recovery has no abandon path at all,
# unrepresentably.
class Recovery
```

Wiring `Recovery` exposes fallible `tryAbandon` for sources with a bounded
quarantine. `abandonProven` additionally requires a static bound on total
unreclaimed quarantine population across loop iterations and tasks. A full
quarantine returns the still-live token. Reset replenishes capacity only after
quiescence; otherwise the image escalates to the target-fatal path.

## Runtime interfaces

An interface is a compile-time contract, monomorphized and erased (R7):
kernel tasks are written against these contracts and never name the
concrete drivers behind them, but by runtime only the concrete objects
remain — no references, no vtables.

Each interface declaration also carries a compiler-emitted effect ceiling:
panic/target-fatal, bounded work, token/Wait source identity, DMA/MMIO/reset
effects, and capability vocabulary. Implementations and forwarding wrappers may
have fewer effects but never more. These ceilings are part of conformance and
the target manifest even where the sketch omits repetitive `effects:` syntax.

Two deliberate flavors, chosen per device and stated out loud:

- **Network and Console are READINESS-flavored**: frames and console text
  are small, so the driver copies between DMA memory and CPU memory at the
  boundary during poll/write (R8), and the kernel-facing calls are
  synchronous and non-blocking. Console write pays one bounded copy. The
  worked network receive path also pays one bounded copy: DMA to a
  driver-owned staging `PacketBuffer` during `poll`; `recv` then swaps
  ownership, returning the staged buffer to the caller and taking the
  caller's spare buffer back for future staging. The documented evolution
  for high-throughput targets is a lease model over transferable DMA
  buffers. V1 keeps the safer ownership swap. Transmit descriptors submitted
  by readiness-flavored devices are still owned by someone: the driver keeps
  bounded tx-inflight state until `poll` reaps the used descriptor, a proven
  reset recovers it, or the target fatal path takes over. No user token is
  minted, but no queue slot or DMA staging buffer is ownerless.
- **BlockDevice is COMPLETION-flavored**: sectors are large, transfers are
  slow, and durability is an event. Every operation is submit → Token (R9).

The async convenience layer below is sugar over the token layer; the token
layer stays public for hand-written state machines, which redeem via
`token.tryComplete()` (R9).

```
type SectorBuffer = Bytes[512]   # virtio-blk's sector size; the concrete
                                 # drivers and tasks use it, while the
                                 # interface stays per-driver via blockSize


interface Console:
    fn write(self, text: View[U8]) -> Result[(), ConsoleError]
    fn writeLine(self, text: StaticString) -> Result[(), ConsoleError]


interface BlockDevice:
    # Each implementation fixes blockSize. Kernel code monomorphizes against
    # the concrete driver (R7), so Bytes[blockSize] is a concrete type after
    # wiring -- erasure makes per-device consts free.
    const blockSize: USize
    fn blockCount(self) -> U64       # nonzero, read with the transport's
                                     # configuration-stability protocol

    # Buffers are consumed on submit and handed back at completion (R8/R9):
    # while a request is in flight you provably cannot touch its memory,
    # because you do not have it. Redemption is on the token itself. Errors for
    # side-effecting operations must expose whether the write/flush may still
    # have happened; `BlockError.ioError(effect = ...)` is part of the public
    # correctness contract, not private driver bookkeeping.
    fn submitRead(self, index: U64, consume buffer: Bytes[blockSize]) -> Result[Token[Bytes[blockSize], ResourceError[Bytes[blockSize], BlockError]], ResourceError[Bytes[blockSize], BlockError]]
    fn submitWrite(self, index: U64, consume buffer: Bytes[blockSize]) -> Result[Token[Bytes[blockSize], ResourceError[Bytes[blockSize], BlockError]], ResourceError[Bytes[blockSize], BlockError]]
    fn submitFlush(self) -> Result[Token[(), BlockError], BlockError]


interface Network:
    # The caller gives a spare PacketBuffer. On .packet(frame), the driver
    # returns a staged full frame and keeps the spare for future rx staging; on
    # .noPacket(spare), the caller gets the spare back unchanged. A recoverable
    # error also returns the consumed spare through ResourceError, preserving
    # the fallible-consume law (R4/R6). This is the ownership-swap receive path:
    # one DMA->CPU copy in poll, no staging->caller copy in recv.
    fn recv(self, consume spare: PacketBuffer) -> Result[RecvStatus, ResourceError[PacketBuffer, NetError]]

    # Copies the frame into tx DMA memory (R8). Non-blocking: oversize frames
    # fail before descriptor construction, and a full tx ring is `err .txFull`,
    # which is backpressure, not failure.
    fn send(self, frame: View[U8]) -> Result[(), NetError]

    # Droppable awaitable, signaled when rx has work (R9). The idiomatic
    # task loop drains a bounded batch of recv calls, then awaits readiness
    # so every task-resume cycle satisfies R18.
    fn readable(self) -> Wait


executor interface Pollable:
    # True means progress was made. "Poll me again soon" is not a return
    # value: an unfinished driver simply exhausts the budget, and the
    # executor never sleeps on an exhausted pass (R12).
    fn poll(self, budget: PollBudget) -> Bool


executor interface DoorbellSource:
    # Driver classes may implement this, but only the generated executor may
    # name it as a callable surface or place it in a generated registry.
    fn armDoorbell(self)
    fn hasPending(self) -> Bool


executor interface ResettableDevice:
    # Executor-only surface for target-proven reset recovery. A token-minting
    # driver implements this if its target/device class supports runtime reset;
    # otherwise watchdog expiry escalates to the target fatal path.
    fn resetToQuiescent(self, budget: PollBudget) -> Result[ResetEpoch, ResetError]
    fn reinitAfterReset(self, epoch: ResetEpoch, budget: PollBudget) -> Result[(), ResetError]

# Implementing this interface alone does not certify a reset. The target ABI
# binds the two calls into a sealed linear transition:
# Running[oldEpoch] -> Quiescent[newEpoch] -> Running[newEpoch]. Hardware
# quiescence precedes registry failure and DMA reclamation; every token,
# readiness descriptor, quarantine entry, and staging buffer under oldEpoch is
# accounted for; reinit accepts only the branded newEpoch. Failure after reset
# begins enters target fatal rather than exposing a half-reset driver.


enum RecvStatus:
    noPacket(spare: PacketBuffer)
    packet(frame: PacketBuffer)


# A reusable frame buffer with headroom over the 1514 MTU. Ownership moves
# across Network.recv; its invariant survives every mutation because all
# writes go through methods.
class PacketBuffer:
    storage:
        data: Bytes[2048]
        length: USize

    invariant: length <= 1514

    boot fn emptyRing[const N: USize]() -> Ring[PacketBuffer, N]

    # Copy a frame in; one of two mutating entry points.
    fn load(self, frame: View[U8]) -> Result[(), BoundsError]

    # In-place frame construction (R3 Slice), the other mutating entry
    # point: sets length = n (checked against the invariant), then returns
    # the edit loan over exactly those bytes. The invariant holds before the
    # Slice is handed out (R5).
    fn build(self, n: USize) -> Result[Slice[U8], BoundsError]

    fn length(self) -> USize

    # A View projected from `self` (R3): valid only for the caller's loan of
    # this buffer, never storable, never live across an await.
    fn view(self) -> View[U8]:
        return data[..length]
```

### The async convenience layer

Pure sugar over the token layer, grouped as static async methods of a kernel
class. Task entries use the same class-method shape (R15), while `VirtioPci`
is the boot-side precedent for stateless helper classes. Each body is two lines
so the desugaring stays obvious. `await token` parks the frame; the executor's
driver poll makes the completion observable; resumption redeems via
`token.tryComplete()` (R10).

```
kernel class BlockIo:
    fn nextIndex(disk: BlockDevice, current: U64) -> U64:
        let count = disk.blockCount()       # interface contract: count > 0
        if current >= count - 1:
            return 0
        return current + 1

    async fn read(disk: BlockDevice, index: U64, consume buffer: Bytes[disk.blockSize]) -> Result[Bytes[disk.blockSize], ResourceError[Bytes[disk.blockSize], BlockError]]:
        let token = disk.submitRead(index, buffer)?
        return await token

    async fn write(disk: BlockDevice, index: U64, consume buffer: Bytes[disk.blockSize]) -> Result[Bytes[disk.blockSize], ResourceError[Bytes[disk.blockSize], BlockError]]:
        let token = disk.submitWrite(index, buffer)?
        return await token

    async fn flush(disk: BlockDevice) -> Result[(), BlockError]:
        let token = disk.submitFlush()?
        return await token

    # Durability note (virtio-blk semantics): a flush covers writes whose
    # completions were observed BEFORE the flush was submitted. "Make this
    # write durable" is therefore always two awaits -- write, then flush --
    # never two submits racing each other.
    async fn commit(disk: BlockDevice, index: U64, consume buffer: Bytes[disk.blockSize]) -> Result[Bytes[disk.blockSize], ResourceError[Bytes[disk.blockSize], BlockError]]:
        let buffer = (await BlockIo.write(disk, index, buffer))?
        match await BlockIo.flush(disk):
            .ok(_):
                return ok buffer
            .err(error):
                return err .failed(error = error, recovered = buffer)
```

## The runtime graph: objects, then executor construction

The reduction is two explicit, separated steps — the move, then task-object
construction:

1. **The move.** Boot returns a per-image record of the CONCRETE runtime
   objects: the drivers, plus the runtime-safe root services. Returning it
   is the single move into static storage — an ordinary value move, no
   hidden step. Nothing else survives boot.
2. **The executor construction.** The image's `executor fn execute(objects:
   RuntimeObjects)` constructs kernel/service task objects with named arguments
   and schedules their async entries:
   `schedule PacketPump.new(net = objects.net0, console = objects.console0).run()`.
   Conformance (`implements`) is checked when a concrete runtime object is bound
   to a task object's `needs:` field, the task monomorphizes against the concrete
   types, and every handle erases to a direct static address (R7). A scheduled
   kernel/service task may not request a concrete driver class directly in
   `needs:`; it receives the reduced interface surface unless it is explicitly
   trusted same-layer runtime code.

Move the runtime objects once, by returning them; construct task objects once, in
`execute`; then the generated executor owns the loop. The static graph is
literally readable in the image: runtime objects, then scheduled task objects.
`RuntimeObjects` storage remains encapsulated from ordinary code; the image boot
constructor and its paired `executor fn` have a narrow structural-field wiring
privilege. That privilege can move fields only into static storage/handles and
cannot call private driver surfaces.

```
# Per-image. Every field is mandatory (no defaults, R5).
class RuntimeObjects:
    storage:
        console0: VirtioConsole
        net0: VirtioNet
        disk0: VirtioBlock
        clock: Clock
        panic: PanicSink


executor fn execute(objects: RuntimeObjects):
    schedule PacketPump.new(
        net = objects.net0,
        console = objects.console0,
    ).run()

    schedule Journal.new(
        disk = objects.disk0,
        console = objects.console0,
        clock = objects.clock,
        panic = objects.panic,
    ).run()
```

**The executor-source derivation rule (R12):** the executor polls, arms, and
resets exactly the object fields that implement executor-only source interfaces
such as `Pollable`, `DoorbellSource`, and `ResettableDevice`. Driver classes may
implement these interfaces, but user code may not call them through an interface
parameter or store them as values; only the generated executor names them as
callable surfaces. The set is DERIVED from `implements`, never listed, because
an explicit list would create a forget-to-poll bug class — omit one driver and
its device silently never completes anything. Deriving from the type is
single-sourced and unforgettable. Any runtime method that mints a `Token` or
readiness `Wait` creates an effect summary requiring the owning object to
implement the corresponding source interfaces. A readiness-returning method also
declares its source predicate, doorbell source, bounded waiter storage, and
lost-wakeup recheck; `fn readable(self) -> Wait` is shorthand for a
level-triggered wait on that predicate, not a public Wait constructor.

Source derivation follows effect identities through wrappers and owned child
objects. If a top-level field forwards a child token or Wait, it must implement
a sealed delegation surface whose generated hook reaches that fixed child; a
forwarding wrapper cannot hide an unpolled source. Source objects and their
address-determining ownership ancestors are frozen in place after wiring.

## The generated executor

Emitted by the compiler from the image declaration; never written by users.
For specification purposes, the loop is:

```
loop:
    var madeProgress = false
    for each Pollable driver d in rotating order:
        madeProgress |= d.poll(generated per-source PollBudget)
    for each runnable task t in rotating order:
        resume t once under its generated worst-case slice
    re-evaluate every armed Wait predicate and token-ready bit
    let recoveryNeeded = reserved scan of expired tokens + reset-request flags
    if recoveryNeeded:
        run reset from reserved recovery budget or enter target DMA-safe fatal
    if not madeProgress and all tasks truly parked and no slice exhausted:
        arm DoorbellSources + timer, then re-check every ring, token, Wait
        predicate, reset-request flag, and deadline; sleep only if the complete snapshot is dry.
        On wake: mask/ack as target requires, continue.
```

An exhausted source slice means that source may have unfinished work, so the
executor never sleeps on an exhausted pass — that is the entire "poll me
again soon" protocol; drivers do not need to say it separately.

Watchdog deadlines are per token, grouped by issuing driver. Progress on a
healthy NIC cannot mask a wedged disk token. Defaults come from the target and
device class; a later version may expose tuning, but V1 does not need an image
executor stanza. Watchdog deadlines cover TOKENS only: readiness-flavored
devices mint none and fail SILENT by design — a dead NIC parks its consumer on
a Wait forever while the rest of the appliance runs. A task that must detect
readiness starvation makes that choice explicitly: `select` the Wait against
`clock.after(...)` and act. This is a decision, not an accident. A successful
reset reaches the device's declared quiescence condition, advances the reset
epoch, fails or recovers every in-flight token through resource-preserving
results, and reinitializes the driver. If the device has no target-proven
reset, the only recovery is the target fatal path. A reset transition is ordered
mechanically: capture `oldEpoch`, prove hardware quiescence, advance to
`newEpoch`, fail/recover every `oldEpoch` registry and inflight entry, then
reinitialize under `newEpoch`.

Post-ExitBootServices startup is a generated transaction boundary even when the
calls are written plainly in the boot function. Once any device is allowed to
bus-master, a later startup failure cannot return to firmware; it either rolls
back through target-proven reset of already-started devices or enters the
target DMA-safe fatal path.

V1 fairness is concrete: each pass polls every `Pollable` field once and gives
each runnable task at most one resume. Starting order rotates per pass, every
source/task has a nonzero certified slice, and watchdog/reset work has a
separate reserved slice, so a busy NIC cannot starve a disk or task. A task
that yields is not resumed again until the next pass. A parked task that is not
ready re-executes one
match/tryComplete check — a few loads. A ready-bitmap (driver poll marks which
task's token completed) is an executor-internal optimization with no language
surface.

There is no user-callable entry into this loop — no block_on, no
`driveUntil`, no executor capability (R12). A user-callable entry would
resume other tasks while the caller's loans are live and its frames occupy
the single runtime stack, breaking the interleaving theorem (R11) and the
stack budget. Waiting has exactly one spelling: `await`.

## Targets and image contracts

A `target` names the machine shape and fixes the hardware and target-runtime
contracts the compiler enforces end to end. This is a target certification
layer, not a decorative image checkbox: each target must provide evidence that
its declarations hold on the machine or hypervisor class it names.

A target is a signed/versioned package containing the startup and fault object
code, ABI-helper definitions, device/firmware/hypervisor compatibility range,
proof assumptions, machine-checkable layout/access/fence tables, and final-code
verification rules. The compiler records its content hash in the image proof
manifest. Facts observable at boot are checked there; facts such as SMI behavior,
DMA coherence, reset quiescence, and firmware-call termination remain explicit
certified assumptions, never inferred from a target stanza written by an image.
An uncertified or mismatched package is a build error.

- the **hardware contract**: the exact PCI functions (address, vendor,
  device, required features) the image expects. V1 is specific-image mode:
  boot validates exactly this contract and fails early; there is no broad
  discovery. The doorbell wiring — one MSI-X vector per queue — is derived
  from this block at image build time (R13).
- the **target runtime contract**: exactly one executing CPU or generated AP
  parking, interrupt/doorbell semantics that resume Wrela with interrupts
  masked, disabled/fatalized non-maskable asynchronous entries, DMA coherence
  class and cache-maintenance rules, shared-DMA atomicity/alignment widths,
  reset quiescence, MMIO boundedness or fatal timeout, IOMMU/vIOMMU isolation
  when the theorem must contain disobedient hardware, physical placement guarantees,
  extra-device behavior (`fatal`, `disabled`, or proven unable to DMA/interrupt),
  panic sink boundedness, boot firmware-call bounds, boot allocation bounds,
  optional FP/SIMD save-restore if floating point is enabled, post-exit startup
  rollback/fatal behavior, and default executor/fault behavior. The compiler
  computes static object, temporary, frame, stack, and DMA demand from the image;
  the image does not spell out a separate memory or executor-budget stanza.
  For transports that return no authenticated generation, the contract also
  states the protocol-compliant completion/uniqueness premise. Deadline
  durations are restricted to the target clock's unambiguous wrap-safe window.

The `image` block wires the boot function (returning the image's
RuntimeObjects) and the executor construction function that schedules the fixed
task set (R11/R7). The generated executor and default fault path are derived
from the target. See the worked example for the concrete
`target X86_64UefiKvmVirtioPci` and `image WrelaOS`.

**Testing note:** conformance is nominal and all wiring happens at the
reduction point, so polymorphism is per-image. A test image binds mock
driver classes behind the same contracts (a RAM-backed BlockDevice, a
scripted Network) and runs the same kernel tasks against them on a host
target. Mock drivers mint real tokens — mint/complete hooks are generated for
any class implementing a token-minting contract (R9). Kernel code cannot tell
the difference — which is the point.
