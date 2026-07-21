# The wrela language specification

**Status:** design specification, revision 0.1

**Target profile:** sealed, single-core, AArch64 bootable appliance images

wrela is a statically typed, Python-shaped systems language whose compilation
unit is a machine image. A build closes over the image manifest, every actor and
task, every driver and device contract, and every allocation site, then emits a
bootable artifact. There is no kernel/program boundary inside the image.

This specification turns that thesis into one coherent language model. In
particular, it incorporates the corrections from the design reviews: actors are
non-reentrant, cancellation owns DMA teardown, views have a precise lexical
lifetime, async frames are statically bounded, queue capacity is reserved per
request, public effects are visible, and modules and build phases are defined.

## Reading order

1. [Foundations](01-foundations.md) — scope, invariants, closed-world model, and
   safety boundary.
2. [Source language](02-source-language.md) — lexical grammar, modules,
   declarations, types, interfaces, and access effects.
3. [Values, views, and regions](03-values-views-regions.md) — value semantics,
   `read`/`mut`/`take`, projections, ownership transfer, regions, and teardown.
4. [Actors and async](04-actors-and-async.md) — messages, non-reentrancy, state
   machines, scheduling, structured concurrency, deadlines, and cancellation.
5. [Hardware safety](05-hardware-safety.md) — capabilities, MMIO, DMA, queues,
   interrupts, polling, and reset.
6. [Comptime and images](06-comptime-and-images.md) — compile-time evaluation,
   image construction, specialization, phases, tests, and boot.
7. [Faults and reliability](07-faults-and-reliability.md) — recoverable errors,
   abandonment, supervision, deterministic replay, and deployment consequences.
8. [Build contract](08-build-contract.md) — required analyses, diagnostics,
   footprint reports, and conformance.
9. [Optimization model](09-optimization-model.md) — the as-if rule,
   whole-image lowering, actor fast paths, frame compression, and the boundary
   between proved optimization and language semantics.
10. [Standard library contracts](10-standard-library-contracts.md) — normative
    contracts for errors, actors, time, tasks, collections, formatting, queues,
    and other load-bearing runtime types.
11. [Conformance inventory](conformance-inventory.md) — non-normative,
    chapter-by-chapter implementation, evidence, gap, and exclusion tracking.
12. [Worked virtio appliance](examples/virtio-storage.wr) — an illustrative,
    corrected block-driver/filesystem/app slice.
13. [Design decisions](design-decisions.md) — non-normative reconciliation of
    the source discussions and explicit exclusions.

## Authority and notation

The prose in files 01 through 10 is normative. The worked example is
illustrative; if it conflicts with normative prose, the prose wins. The decision
ledger explains intent but does not override the specification. Beyond this
revision, normative prose for the daily-use kernel follows implementation
evidence rather than leading it: a later edit advances a chapter only as far as
the reference toolchain has actually built and measured.

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** carry their usual
standards-language meanings. A paragraph headed “Rationale” is non-normative.
A paragraph headed “Deferred” is outside revision 0.1.

Code blocks use the proposed `.wr` surface. They are not Python, even where the
shape is familiar. A `wrela` block containing the literal token `...` is
explicitly a non-compilable fragment and `...` is not a language token. Every
other `wrela` block in normative chapters MUST parse and type-check, or produce
the diagnostic asserted by its surrounding text, when supplied with the
declarations named by that fragment. The conformance corpus records those
minimal implied declarations rather than treating unresolved illustrative names
as language magic.

## Normative external references

Revision 0.1 fixes the following external contracts. A later edition or erratum
does not silently change accepted source, ABI, or device behavior; adopting one
requires a language or target-package revision recorded in the image report.

- [Unicode 16.0.0](https://www.unicode.org/versions/Unicode16.0.0/) data files,
  [UAX #31 revision 41](https://www.unicode.org/reports/tr31/tr31-41.html)
  identifier rules, and
  [UTS #39 revision 30](https://www.unicode.org/reports/tr39/tr39-30.html)
  security skeletons;
  [UTS #55 revision 5](https://www.unicode.org/reports/tr55/tr55-5.html)
  supplies the mandatory source-display threat model.
- [IEEE 754-2019](https://standards.ieee.org/ieee/754/6210/) for
  binary32/binary64 operations, narrowed by chapter 02's canonical-NaN and
  no-fast-math rules.
- [UEFI 2.11](https://uefi.org/specs/UEFI/2.11/) for the AArch64 reference target.
- [AAPCS64 2025Q4](https://github.com/ARM-software/abi-aa/releases/tag/2025Q4)
  for the AArch64 procedure-call standard, narrowed by the target package's
  explicit UEFI entry convention.
- LLVM 22.1.3's pinned
  [target-triple mapping](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.3/llvm/lib/TargetParser/Triple.cpp#L970-L984)
  maps the UEFI OS to COFF, while its pinned
  [AArch64 call lowering](https://github.com/llvm/llvm-project/blob/llvmorg-22.1.3/llvm/lib/Target/AArch64/AArch64ISelLowering.cpp#L8313-L8351)
  selects AAPCS for non-Windows targets. The direct LLVM backend therefore uses
  `aarch64-unknown-uefi`; it does not depend on Clang's separate UEFI frontend.
  The target additionally applies LLVM's `+reserve-x18` feature because UEFI
  2.11 section 2.3.6.4 requires X18 to remain unused.
- Microsoft's [PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
  for ARM64 COFF objects and PE32+ images; the checked-in target package pins
  the accepted header, subsystem, relocation, and entry policy.
- QEMU's [AArch64 `virt` machine contract](https://www.qemu.org/docs/master/system/arm/virt)
  as realized by the developer's own installed `qemu-system-aarch64`. The
  target uses the versioned `virt-10.0` machine and explicit `cortex-a57` CPU
  rather than moving `virt` or `max` aliases.
- [Virtio 1.2 Committee Specification 01](https://docs.oasis-open.org/virtio/virtio/v1.2/cs01/virtio-v1.2-cs01.html)
  for the standard virtio transport/queue contracts. Virtio 1.3 is not silently
  included because its published latest stage is a committee-specification
  draft rather than this target package's pinned contract.

## Revision 0.1 in one page

- A build produces one sealed image. Dynamic loading, JIT code, runtime
  reflection, trait objects, and an ambient heap are absent.
- Runtime code has one address space, one core, and one event loop. Language
  safety is not equivalent to process or hardware fault containment.
- `struct` values, including uniquely owned `linear struct` values, form an
  ownership tree. Runtime roots marked `@app`, `@service`, and `@driver` are
  actors, declared on a `struct`.
- Actors share no mutable state. Cross-actor calls create typed logical messages
  and move scalar/explicitly copied values, provenance-branded `iso[P]` ownership, or
  sealed linear receipts; views and `mut` loans cannot cross an actor boundary.
  This is not Erlang/BEAM's actor model: the actor set, its mailboxes, and its
  supervision tree are closed and sized at build time, with no dynamic process
  spawning or hot code loading inside a sealed image.
- Actor handles are image-wired capabilities, not mobile values. An abandoned
  peer resolves outstanding calls with typed `PeerFailed`; a failed installed
  task produces a bounded supervisor event rather than dropping its error.
- Actor turns are non-reentrant even while awaiting a dependency. The compiler
  rejects cycles in a unified actor/task/resource/cleanup wait-for graph.
- Actor admission and ordering are semantic, but physical rings, payload copies,
  reply hops, and handler dispatch are not. Whole-image optimization may elide
  them only under the actor as-if rule.
- Parameters are read-only by default. `mut` grants exclusive in-place access;
  `take` transfers ownership. Both effects are mirrored at non-receiver call
  arguments. Public receiver effects are explicit.
- There is no general reference syntax. Only `projection` declarations may
  yield `view T`/`mut view T`, with implicit conservative provenance over their
  receivers and parameters. Views are
  lexical and second-class; they cannot be stored, sent, submitted to a device,
  or remain live across `await`.
- Allocation is assigned to image, task-frame, call, request, or branded
  `iso[P]` pool regions. Pool brands prevent a returned value from satisfying
  the wrong pool's capacity proof. Every runtime allocation count is statically
  bounded. Promotion to the image region is reported and can be forbidden.
- Every `async fn` lowers to a statically bounded state machine. Unbounded sync
  or async recursion is rejected. Async loop back edges are semantic checkpoints
  unless an explicit finite uninterrupted bound is proved; synchronous/ISR loops
  must always have a proven uninterrupted bound.
- `with request(...)` unifies a deadline, cancellation scope, request region,
  queue permit, and deterministic teardown. A submitted virtio request cannot
  simply be dropped; cancellation quarantines its mutable regions while a
  generated driver recovery turn resets the queue or device before reclaiming
  DMA memory.
- Hardware authority is unforgeable and manifest-minted. ISRs have a tiny,
  transitively checked effect set. DMA payload ownership moves between CPU and
  device; shared rings are accessed only through typed standard-library
  operations with defined ordering.
- `comptime` runs ordinary typed code under a deterministic target emulator and
  a finite step budget. It cannot perform I/O. Layout-dependent assertions run
  only after whole-image layout in a read-only second pass.
- Recoverable faults use `Result[T, E]` and postfix `?`. Bugs cause uncatchable
  actor abandonment. Supervisors choose restart, escalation, or image-fatal
  behavior; restart first performs generated resource teardown.
- The language holds a standing concept budget of roughly 100 user-facing
  concepts; a proposal that adds one normally must retire another (full rule
  in [Design decisions](design-decisions.md)).
