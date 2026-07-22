# Wrela runtime platform

Status: forward-looking design direction (not yet normative). Records the
execution-model, virtualization, boot, and snapshot/replay decisions taken on
2026-07-21. The current sealed pipeline is in
[`toolchain-architecture.md`](toolchain-architecture.md); this document says
where the *runtime* is heading. The backend self-hosting track (removing LLVM
and LLD) is a separate decision record:
[`adr/0001-native-backend.md`](adr/0001-native-backend.md). The two tracks touch
only at the canonical-image boundary (§3).

## Supersession notice

This document **supersedes** the runtime portions of the world-class roadmap's
[Lane C oracle track](superpowers/plans/2026-07-20-world-class-roadmap.md) and
the "Oracle track" paragraph in
[`toolchain-architecture.md`](toolchain-architecture.md). Specifically retired:

- Building the **`wrela-virt` AArch64 interpreter / machine model** (crates
  `wrela-aarch64-decode`, `wrela-aarch64-interpreter`, `wrela-machine-*`,
  `wrela-gicv3-*`, `wrela-pcie-model`, `wrela-virtio-pci-model`, etc., Lane C
  C1–C10).
- **Bundling QEMU / keeping it as a permanent runtime component.**

What survives from the roadmap: QEMU as a **temporary differential oracle that is
then removed** — but validated against the new **Wrela VMM and native backend**,
not the interpreter, and **never bundled** (§1, §6). Cross-architecture execution
is not a goal (AArch64 hosts only).

What survives, relocated: the **native codegen** and **native linker** goals move
to [ADR 0001](adr/0001-native-backend.md). Deterministic execution — the reason
`wrela-virt` existed — is provided instead by **record/replay at the virtio
boundary** (§4), which does not require an interpreter.

This also supersedes the earlier `runtime-and-backend-direction.md` draft.

---

## 0. Thesis

> **Wrela owns a tiny, observable virtual-hardware ABI and the entire
> sealed-image lifecycle; the host owns physical device diversity.**

Wrela wins where **the operator controls the deployment envelope** and can
standardize on Wrela's virtual-hardware ABI — appliances, local development,
edge hardware, managed fleets. Public cloud (rented, Linux-mediated) is a
**portability fallback**, not a target: it works if needed, but no one adopts
Wrela because of it, and we do not optimize or market for it.

Note on "owns the metal": in the 0.1 guest profile the *host* owns the metal,
the physical drivers, boot, and much of the trust base; Wrela owns the guest
execution contract. Literal metal ownership belongs only to the future
native-metal profile (§1).

---

## 1. Product / deployment profiles

Each profile is first-class and states who owns the metal, the boot mechanism,
the transport, and the determinism guarantee.

| Profile | Owns metal / drivers | Runtime | Boot | Determinism | Status |
|---------|---------------------|---------|------|-------------|--------|
| **Guest (0.1 target)** | host (thin Linux / driver domain) | bundled Wrela VMM on HVF (macOS) / KVM (Linux) | flat image + bespoke direct-boot | none (real-time execution) | primary |
| **Deterministic replay** | host | same VMM under record/replay | same | replayable within the recorded boundary (§4) | conformance/debug |
| **Native-metal (future)** | **Wrela** | Wrela directly on hardware | discovery boot (UEFI / device-tree) | — | deferred |

The "driver treadmill is permanently deleted" claim applies to the guest and
deterministic-replay profiles only. In the native-metal profile Wrela owns real
drivers, so that claim does **not** hold there; native-metal is a distinct
platform profile, not a variant of the guest one.

**QEMU and host architecture.** Wrela targets AArch64, and every profile runs on
an AArch64 host (Apple Silicon, arm64 Linux runners). Cross-architecture
execution is **not a goal** — there is no emulated arm64-on-x86 path, and QEMU is
**not bundled**. QEMU serves only as a **development-time differential oracle**:
during VMM and native-backend bring-up, the same image runs under QEMU and under
the Wrela VMM (and native backend) and their canonical event streams are
compared. QEMU is **removed** once parity criteria pass — e.g. N consecutive
divergence-free differential runs over the frozen corpus — leaving the Wrela VMM
as the sole runtime and test substrate. Its only lasting legacy is the frozen
corpus of fixtures its divergence checks produced.

---

## 2. Versioned Wrela virtual platform contract (v1)

This is the ABI between a Wrela guest and any Wrela-controlled VMM. It is
versioned; below is **v1**.

### 2.1 Transport

**virtio-mmio** (not virtio-pci). Device topology is fixed and handed to the
guest via boot-info (§3), so there is no PCIe ECAM, no enumeration, and no MSI-X
machinery on the fast path. Rationale: virtio-mmio is the minimal transport for
a fixed-device VMM (the Firecracker precedent), and it matches direct-boot's
no-discovery model. **virtio-pci is deferred to the native-metal / portable
profiles**, where real discovery is required and the heavier PCIe substrate
earns its cost.

> This reverses the (now-superseded) roadmap's virtio-pci + virtio 1.2 machine
> contract pin. See §6.

### 2.2 Two feature profiles (resolves require-vs-degrade)

- **Wrela fast profile — required, our VMM only.** Because we own both ends we
  *require* `VERSION_1`, `RING_PACKED`, `EVENT_IDX`, `IN_ORDER`,
  `INDIRECT_DESC`, `NOTIFICATION_DATA`. This is a contract with our own VMM, not
  a portability claim.
- **Portable virtio profile — negotiated, foreign hosts.** Assume nothing beyond
  `VERSION_1` and split virtqueues; negotiate `RING_PACKED`, `EVENT_IDX`, etc.,
  and degrade gracefully. `RING_PACKED` in particular is optional per spec (a
  device/driver may support packed, split, or both), so the portable profile
  must not assume it. Used only by the UEFI / foreign-host envelope (§3).

### 2.3 Device set (v1)

virtio-block, virtio-net, virtio-console, virtio-entropy, and a **dumb
framebuffer** display — scanout of CPU-rendered frames, a trivial device, not
accelerated virtio-gpu. (vsock is a later addition; **accelerated** GPU / 3D and
USB are explicitly out of v1.)

Display is **CPU field-based 2.5D rendering**: everything is defined as fields
(distance / implicit functions) evaluated per-pixel with NEON (FMLA + FP16,
§2.6) and depth-composited in 2.5D. This is a deliberate choice: it needs only a
framebuffer device (sidestepping the virtio-gpu passthrough soft spot), it is
embarrassingly SIMD-parallel and resolution-independent, and it is **a pure
function of its inputs → deterministic, replayable frames**, reinforcing Layer A
(§4.2). A GPU would be a nondeterministic black box that breaks that property.
Honest ceiling: excellent for 2D / UI / vector and modest software 3D, not a
match for GPU throughput on heavy 3D.

### 2.4 Status and lifecycle bits

- `DEVICE_NEEDS_RESET` (status bit 64) — **baseline since virtio 1.0**; used for
  device error recovery.
- Opportunistic, negotiated when offered: `VIRTIO_F_RING_RESET` (1.3) and the
  `SUSPEND` status bit (16, **new in 1.4**) — used for quiescence, suspend, and
  migration (§4).

### 2.5 Spec reference

Read and build against **virtio 1.4** (OASIS CS01, 8 April 2026) — the latest
spec and a strict superset. The contract pins the **feature bits above**, not a
spec version; host support lags the spec, so foreign hosts get the portable
profile and negotiation, never a mandate.

### 2.6 CPU / ISA baseline

Wrela targets AArch64 only (§1), so the backend and runtime commit to one ISA.
**Everything is decided at build time — there is no runtime feature dispatch.** A
Wrela image is sealed and compiled for one declared, static feature set, recorded
as image metadata; the loader performs **one up-front compatibility check** and
refuses a vCPU that does not meet it (a clean load-time error, never a mid-run
`SIGILL`). Fleet variation is handled by building **per-target profiles** at
build time, never by branching inside the image. This is correct under the
operator-controls-the-envelope thesis (§0): the hardware is known, so a static
build for it is the right choice, not a limitation — runtime dispatch exists to
cope with *unknown* hardware, which Wrela is not.

**Required feature set (the v1 build target):**

- **ARMv8.2-A** — the lowest modern target level (Raspberry Pi 5 / Cortex-A76,
  Graviton2, Ampere Altra, all Apple Silicon). Below it (v8.0 Pi 4) is dropped.
- **LSE** (v8.1 large-system atomics) — no ll/sc fallback loops.
- **Crypto** (AES/SHA/PMULL).
- **NEON** FP32/FP64 + **FMLA** — mandatory since v8.0; the float-SIMD workhorse
  for field-based rendering (§2.3).
- **FP16** (`FEAT_FP16`) — half-precision arithmetic; ~2× NEON lane throughput
  for pixel / field / colour math.
- **DotProd** (`FEAT_DotProd`) — int8 `SDOT`/`UDOT` for packed-byte pixel / blend
  paths (float dot products use FMLA, not this).

FP16 and DotProd are **required, not dispatched**: every target implements them
(Pi 5's A76, Apple Silicon, Graviton2+), so requiring them costs nothing and
removes all runtime dispatch — the hot graphics kernels simply always use them.
Both are plain SIMD compute instructions, exposed to guests by HVF/KVM without
special mediation, so the guest profile gets them too.

**Not in v1 (no "sometimes-on" features):**

Every feature is either **required** (above, load-checked) or **absent** (not
emitted). There is no emit-and-let-the-hardware-decide middle state: a feature
present on only part of the fleet would give non-uniform behaviour, which the
static model rejects.

- **PAC** (v8.3) and **BTI** (v8.5) — hardware control-flow integrity. Dropped
  from v1: they are NOPs on the flagship Pi 5 (v8.2) and often not exposed to
  guests, so they would harden only *part* of the fleet — a variable security
  property — while language-level memory safety is the primary mechanism
  regardless.
- **RNDR** (v8.5 hardware RNG) — entropy always comes from virtio-entropy (§2.3).
- **MTE** (v8.5+) and **SVE/SVE2** — no current target has MTE (Apple ≤ M4, Pi,
  standard cloud all lack it), and Apple lacks SVE entirely, so NEON is the only
  portable vector ISA.

Any of these can return in a future **native-metal build** that declares a higher
target (v8.3 / v8.5 / v9): there they become **required and load-checked** —
uniformly on, never sometimes-on — as a separate build profile chosen at build
time.

**Raspberry Pi 5 fit** (the stated constraint): Cortex-A76 satisfies the entire
required set — v8.2, LSE, crypto, NEON/FMLA, FP16, DotProd — so the v1 image runs
at full speed with no fallback and no dispatch. The unused features
(PAC/BTI/MTE/RNDR/SVE) are simply absent. Everything fits.

---

## 3. Canonical image and boot ABI

### 3.1 Canonical artifact

The canonical Wrela artifact is a **flat, relocatable image**: a single sealed
whole-program image plus relocation records, an entry point, and its boot-info
expectations. The VMM loads it directly into guest RAM. Rationale: the fast path
is the *target*, so its artifact is canonical; **PE32+/EFI is a later envelope,
not the canonical form.** This decision gates the native linker's first output
container — see [ADR 0001 §1](adr/0001-native-backend.md).

### 3.2 Boot-info ABI

The VMM places the image, fills a **versioned boot-info structure** — memory
map, device topology (the virtio-mmio device base addresses + IRQ lines), entry
point, RNG seed, timebase/clock parameters — and jumps to the entry with a
pointer to that structure in **`x0`** (AArch64). No firmware, no discovery: the
guest is *told* its hardware rather than probing for it.

### 3.3 Boot front-ends over one image core

Front-ends are thin entry shims over a byte-identical core; each reaches the same
`kmain`.

| Front-end | Reach | Speed | Role |
|-----------|-------|-------|------|
| **Bespoke direct-boot** (flat image + boot-info in `x0`) | Wrela VMM (HVF/KVM) | fastest | 0.1 default |
| **AArch64 direct-boot shim** (Linux arm64 convention, **DTB in `x0`**) | QEMU `-kernel`, Cloud-Hypervisor-style tooling | fast | standard fast path |
| **UEFI / PE envelope** | native cloud instance + real UEFI hardware + any hypervisor | slowest (firmware init) | universal backstop |

> Correction from the earlier draft: there is **no PVH front-end**. PVH is an
> x86-64 boot protocol; on AArch64 the standard direct-boot convention is the
> Linux arm64 protocol (kernel image + DTB pointer in `x0`), and Cloud
> Hypervisor's AArch64 path uses specialized UEFI, not PVH.

The fast path **bypasses** discovery; it must never **delete** the general
discovery path, or the native-metal door (§1) welds shut.

---

## 4. Snapshot and replay contracts

The controlled virtio boundary makes both **tractable**, not automatic. Neither
is "airtight" and a restored guest is not "byte-identical every time" — those
claims are withdrawn. Two *distinct* contracts:

### 4.1 Snapshot / restore

A running VM is guest RAM + vCPU registers + device-model state, but a
*deployable* snapshot is more. The contract must specify:

- **Quiescence** before capture (via `SUSPEND`, §2.4).
- **Storage generation / rebinding** — block backends are versioned and rebound
  on restore, not captured inline.
- **Network endpoint rebinding** — host-side sockets/taps are re-established.
- **Clock repair** — wall-clock and timebase are corrected on restore.
- **RNG / identity reseeding** — restoring the same snapshot more than once must
  not duplicate unique identities or cryptographic state (a documented
  Firecracker hazard). Reseed on every restore.
- **CPU-feature compatibility** — record the feature set; refuse incompatible
  hosts.
- **Format versioning** — snapshots carry a version and a compatibility policy.

Restore-from-a-post-init **golden snapshot** is the fast-start mechanism: cold
boot once to "ready," snapshot, and let future starts restore instead of
re-running init. With lazy paging + working-set prefetch, restore is single-digit
ms today, sub-ms at the frontier.

### 4.2 Deterministic replay — two layers

Determinism lives at **two distinct layers**, and conflating them is the trap
behind the withdrawn "airtight" claim. Neither comes from the fast VMM (real,
non-deterministic hardware timing) nor from an interpreter (the superseded
`wrela-virt`).

**Layer A — application-level determinism (event-sourcing). The product
substrate; always on.** Wrela state is a function of an ordered event log; if the
runtime and application logic are a *pure function of that log*, replaying the
events reconstructs state exactly, deterministically, **by construction — no VM
machinery**. This is where the product capabilities live: the intelligence
paradigm (dreaming-by-replay, verb mining, learning over history) and crash
recovery. The placement design already works this way — per-mailbox admission
order is recorded and replayed to assert identical event streams.

**Layer B — machine-level record/replay. A bounded test/debug tool; deferred.**
Reproducing an entire VM execution — interrupt injection timing, I/O completion
order, RNG draws, timer reads — for *arbitrary* code, by recording and
re-injecting those sources at the virtio seam with **divergence detection**. This
serves CI reproducibility and time-travel debugging (the deterministic-replay
profile, §1). Scope it minimally: **single-core first**. Full multicore
machine-replay (Level 2) is **deferred** until a concrete need appears, because
Layer A already covers the product cases.

Snapshot composes with Layer A: restore a golden snapshot, then replay the event
log *forward from there* — never from genesis. Snapshot enables fast *start*;
Layer A gives *determinism*; Layer B is a *tool* — three different mechanisms.

#### 4.2.1 The determinism discipline (decide now; cheap now, a rewrite later)

Layer A is free only if the runtime never admits ambient nondeterminism. Like the
boot-info seam (§3), this is a discipline to commit to from the start, not
machinery to bolt on later:

> **All nondeterminism enters through the event log.** Time is a
> logical/recorded clock, never an ambient `now()`; the RNG seed is an event;
> I/O completions are logged with their order; scheduler admission order is
> recorded. The runtime is a pure function of its event stream.

Commit to this in the runtime and standard library now and product determinism
is essentially free and the Layer-B tool is a small add-on. Skip it and later
want dreaming-by-replay, and you are retrofitting purity into a runtime full of
ambient nondeterminism — the expensive failure mode.

---

## 5. Performance budgets and benchmark definitions

Every headline number names its finish line and host state; adjectives are
replaced with budgets.

- **Boot / restore.** Distinguish *cold boot* (runs init) from *restore from
  golden snapshot* (does not). Benchmark: time from VMM start-of-restore to the
  first guest-serviced request, on a **warm host**. Target: restore < ~single
  digit ms; stretch sub-ms with working-set prefetch. "Beat Firecracker" is a
  **guest-spin-up** claim on a warm host, not a power-on claim (host boot is a
  separate, amortized cost; see §1).
- **I/O fast mode.** The claim is **"zero-notification steady-state under
  sustained load"**, not "zero-exit VM" — idle transitions, timers, exceptions,
  config access, and fallback notification paths still cause exits. Budget:
  notification exits/sec at load (target ≈0), tail latency, throughput,
  **host-core consumption** (the polling cost), **guest-core consumption**, and
  **idle power**. State the adaptive-fallback threshold (spin window before
  re-arming notifications).
- **Nested tax** (fallback profile only). Report compute overhead % and
  exit-multiplication *under the I/O fast mode*, where near-zero notifications
  keep the tax near the compute floor.

---

## 6. Migration from today's UEFI / QEMU architecture

Current behavior is real and normative; this is the target, and the delta is
explicit so "forward-looking" is never mistaken for "current."

| Concern | Today (normative) | Target (this doc) |
|---------|-------------------|-------------------|
| Runtime | QEMU `virt` + EDK2 UEFI ([`wrela-test-runner`](../crates/wrela-test-runner)) | bundled Wrela VMM (HVF/KVM); flat image + direct-boot |
| Transport | virtio-pci, virtio 1.2 CS01 (roadmap C6 pin) | **virtio-mmio**, Wrela fast profile (§2) |
| Boot | UEFI PE32+ via firmware | flat image + boot-info ABI (`x0`); UEFI a later envelope (§3) |
| Determinism | planned `wrela-virt` interpreter (Lane C) | **record/replay at the virtio boundary** (§4); no interpreter |
| Cross-arch | QEMU (temporary oracle) | **not a goal** — AArch64 hosts only; QEMU is a dev-time oracle, removed after parity (§1) |
| Codegen / link | LLVM 22.1.x + `lld-link` | native ([ADR 0001](adr/0001-native-backend.md)) |

The normative docs that currently pin the old model — the virtio-1.2 / QEMU
`virt` pin in [`language/README.md`](language/README.md), the "Oracle track" in
[`toolchain-architecture.md`](toolchain-architecture.md), and a driver-author
audience — update **only when this direction graduates from forward-looking to
normative**, not before.

---

## 7. Decision log

All three sub-decisions confirmed 2026-07-21:

1. **Transport: virtio-mmio** for the fast profile (§2.1) — confirmed. Firecracker
   precedent, no discovery; virtio-pci deferred to the native-metal / portable
   profile.
2. **Canonical artifact: flat image** (§3.1) — confirmed; reverses "EFI-first" and
   gates the native linker's first output container ([ADR 0001](adr/0001-native-backend.md)).
3. **Determinism: two-layer** (§4.2) — resolved. Product determinism at the
   event-sourcing layer (always on, via the §4.2.1 discipline); machine-level
   record/replay as a bounded, single-core-first test/debug tool; Level-2
   multicore machine-replay deferred.
