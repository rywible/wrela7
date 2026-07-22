# ADR 0001 — Remove LLVM and LLD (native AArch64 codegen and linker)

Status: proposed (forward-looking; not yet normative).
Date: 2026-07-21.
Related: [`../runtime-platform.md`](../runtime-platform.md) (canonical-image
boundary), [`../toolchain-architecture.md`](../toolchain-architecture.md)
(current pipeline).

## Context

The backend links two external **LLVM-project** artifacts:

- [`wrela-codegen-llvm`](../../crates/wrela-codegen-llvm) lowers
  `ValidatedMachineWir` → LLVM IR (`ir.rs`) → Inkwell/LLVM 22.1.x → AArch64,
  behind `feature = "llvm"`. The crate already owns its COFF container writer
  (`coff.rs`) and validation (`validate.rs`); Inkwell values never cross the
  crate boundary, and the LLVM version is pinned to 22.1.x.
- [`wrela-lld-sys`](../../crates/wrela-lld-sys) is a ~418-line shim that shells
  out to the host `lld-link`. [`wrela-link-efi`](../../crates/wrela-link-efi)
  (~10.7k lines) is a full policy + format layer over it: it inspects COFF
  object inputs, builds link arguments, and re-inspects the linked PE/EFI output
  (relocation provenance, base relocations, section alignment, `SizeOfImage`).

Dropping the C++ toolchain entirely requires removing **both** (both are
LLVM-project). This ADR captures the codegen/linker goals that previously lived
in the world-class roadmap's oracle track; the interpreter/QEMU-deletion goals
from that track are **superseded** by
[`runtime-platform.md`](../runtime-platform.md) and are not pursued.

## Decision

### 1. Native linker first

Most tractable: `wrela-link-efi` already owns the format knowledge on both
sides. Build the bounded link **engine** — cross-object symbol resolution,
relocation application, section layout, base-relocation generation — for a
single static AArch64 image. The target is narrow (one image, base 0, only the
relocation types our own codegen emits), which is the ideal condition for a
purpose-built linker.

**Output container is gated by the canonical-artifact decision** in
[`runtime-platform.md` §3](../runtime-platform.md). The link engine is
format-agnostic; only the emitted container differs. Because the fast-path
canonical artifact is a **flat, relocatable image**, the engine's **first output
target is that flat image**, with the **PE32+/EFI container as a later envelope**
(built when the UEFI portability profile is). This corrects the prior
"native EFI linker first" sequencing, which would have optimized the
compatibility path rather than the target path.

**First milestone:** inventory exactly which relocation types the codegen emits
today, and define the minimal engine that covers them. This is a bounded,
mechanical pass over the existing backend.

### 2. Native codegen second

The `wrela-codegen-llvm` boundary was designed for this swap: the input is
validated (`ValidatedMachineWir`), LLVM is quarantined behind `feature = "llvm"`,
and the COFF container is already ours. The net-new work is the hard middle:

- **instruction selection** from `MachineOperation` (still an LLVM-IR-level IR:
  `Arithmetic`, `Load`, `Store`, `Select`, `MakeStruct`, `MakeEnum`, …) to
  AArch64,
- **register allocation**, and
- a real **32-bit AArch64 instruction encoder**.

Mitigating factor: codegen runs at `OptimizationLevel::None`, so this is a
*correct simple backend* over a bounded ISA subset — no optimizer — which is the
classic single-pass backend scope, not a general compiler backend.

### 3. QEMU is the bring-up oracle, not a shipped component

During native-backend bring-up QEMU is the **differential oracle**: the same
image runs under QEMU and under the native codegen/linker output, and their
canonical event streams are compared. QEMU is **never bundled** and is **removed**
once parity criteria pass (see [`runtime-platform.md` §1](../runtime-platform.md));
cross-arch execution is not a goal (AArch64 hosts only). Writing a CPU
emulator/interpreter is explicitly not part of this work.

## Consequences

- Removes the Inkwell dependency and the LLVM 22.1.x host pin, and the
  `lld-link` host dependency — the sealed toolchain becomes hermetic with no C++
  toolchain.
- Locks the backend to the bounded AArch64 subset the codegen actually emits;
  anything outside it fails closed (matches house style).
- The linker's flat-image output must land alongside the
  [runtime platform](../runtime-platform.md) direct-boot work; the PE/EFI
  container becomes a second, later output mode rather than the first.

## Sequencing

1. Native linker **engine** → flat-image output (relocation inventory first).
2. Native codegen (isel + regalloc + AArch64 encoder) over `ValidatedMachineWir`;
   retire the `llvm` feature and Inkwell.
3. PE/EFI container output added when the UEFI portability profile is built.
