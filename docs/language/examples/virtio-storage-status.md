# Virtio storage appliance implementation status

This file tracks the executable status of
[`virtio-storage.wr`](virtio-storage.wr). The source is the normative integration
shape required by the build contract; it is not currently an executable fixture
and must not be reported as a successful appliance boot.

## Retained executable foundations

| Appliance dependency | Checked-in executable evidence | Current boundary |
|---|---|---|
| Sealed AArch64 UEFI image | `std/examples/minimal-image`; compiler and real-QEMU smoke gates | Boots only the supported scalar/minimum-image subset. |
| Actor activation and bounded mailbox | `crates/wrela-compiler/tests/actor_flow_vertical.rs` | One closed actor/task graph; no app-to-service request path. |
| One-way actor turn dispatch | `crates/wrela-compiler/tests/actor_one_way_send_vertical.rs` | One startup-produced unit message; no typed payload or reply. |
| Recurring native mailbox drain | `crates/wrela-codegen-llvm/src/ir.rs` and its mailbox tests | Drains admitted messages, but no general ready scheduler or FIFO mailbox set. |
| Target virtio transport location | `wrela-target` target package and `wrela-test-runner` QEMU arguments | The boot medium occupies the first virtio-block MMIO transport; source cannot yet claim/map it. |
| IRQ route and ISR proof boundary | `wrela-machine-wir` interrupt route fixture | Machine contract only; no source MMIO/IRQ declaration or driver lowering. |
| Tagged recoverable result | `crates/wrela-compiler/tests/runtime_result_vertical.rs` | Copy-scalar `Result[S, S]` only; no appliance error hierarchy or owned payload. |
| Flat checked duration | `core.time` and the stdlib time verticals | No `Instant`, `now`, deadlines, restart windows, or replayed time. |

## Next executable slices

The worked source becomes an executable fixture incrementally, without replacing
it with a mock device or hosted implementation:

1. admit three image-wired actors (`Notes`, `Storage`, and `BlkDriver`) with exact
   mailbox/storage reporting and recurring deterministic scheduling;
2. add typed actor requests, replies, receipts, cancellation, and linear payload
   return across the app-to-storage-to-driver path;
3. lower target-owned virtio-MMIO discovery, IRQ routing, DMA pools, queue
   ownership, barriers, descriptor publication, completion, and reset;
4. attach a deterministic data disk distinct from the UEFI boot medium and prove
   real read/write/flush behavior under the pinned QEMU/UEFI runner;
5. retain cancellation, queue-full, malformed completion, reset, supervision,
   restart, and record/replay scenarios as permanent image-test gates; and
6. reconcile emitted queue/DMA/mailbox/event-log reservations with the image
   report and independently inspected ARM64 EFI artifact.

A milestone may cite this appliance only for rows whose executable evidence is
listed above. Completion requires the full source to pass parsing, semantic and
ownership checks, all WIR validators, deterministic COFF/EFI production, and
pinned-QEMU storage and recovery scenarios.
