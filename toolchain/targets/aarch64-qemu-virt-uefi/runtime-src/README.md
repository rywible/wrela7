# AArch64 target runtime

`runtime.S` is the complete freestanding implementation of Wrela runtime ABI
version 1 for the pinned `aarch64-qemu-virt-uefi` target. It is reviewable
source rather than a generated C/C++ translation and has no undefined symbols,
ambient heap, hosted runtime, or default-library dependency.

The maintainer build accepts only a normalized absolute compiler path and the
exact SHA-256 of that executable. It clears `PATH`, locale, time-zone, home,
and source-date state, compiles for the exact `aarch64-unknown-uefi` target
twice in one private directory, requires byte identity, parses the COFF itself,
and publishes atomically only after checking ARM64 machine type, sections,
relocations, all ABI-v2 definitions, and undefined-symbol closure.

For example, with explicitly selected Python and compiler executables:

```sh
/absolute/python3 \
  /absolute/checkout/toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/build_runtime.py \
  --compiler /absolute/verified/clang \
  --compiler-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --output /absolute/checkout/toolchain/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj \
  --expected-object-sha256 37c2d541f2546acf3c2c220e39e6d98c4079e0bce710b4a978608e64130dffaa
```

`runtime-object.lock.toml` records the authenticated compiler, source, object,
size, relocation, and undefined-symbol evidence for the checked-in object. A
second build from a different absolute checkout path is byte-identical.

The first replay request is the explicit ABI transition from recording to
replay. The runtime's 64 KiB log is fixed storage and reserves an explicit
overflow record. Test frames use the canonical Wrela frame bytes inside an RFC
1055 SLIP envelope on the target's first PL011. The host transport decoder must
remove that envelope before invoking `wrela-test-protocol`.

`wrela_rt_v2_test_finish` does not fabricate a `RunFinished` event: its single
outcome argument cannot truthfully reconstruct passed/failed counts. Generated
test code must first send the canonical terminal event through
`wrela_rt_v2_test_emit`; finish verifies that aggregate outcome against the
terminal counts and invokes UEFI `ResetSystem(EfiResetShutdown, ...)`.

The one deliberate exception is a compiler-generated language fatal while a
test is active. `test_emit` records the exact active test ID only after a
canonical `TestStarted` frame is successfully transmitted. Stable fatal codes
5 and 6 distinguish checked-shift result loss from an invalid shift count while
the second ABI argument retains the packed Flow function/instruction site.
The fatal path builds the canonical `LanguageFatal` `TestFinished` and failed
`RunFinished` frames in one fixed 64-byte aligned stack reservation, transmits
both, and terminates the image. An unknown code, inactive test, exhausted event
budget, or transfer failure emits no invented successful lifecycle and halts
fail-closed.

`smoke.S` and `smoke_runtime.py` are the explicit slow integration path. The
runner requires absolute paths and SHA-256 values for the compiler, LLD, QEMU,
both firmware images, and runtime object. It links an ARM64 EFI application at
the UEFI-safe zero image base, requires a nonempty relocation directory, boots
the exact `virt-10.0`/Cortex-A57/single-TCG profile, exercises record/replay,
DAIF, cache clean, canonical frame validation, both SLIP escapes, active-test
tracking, and the target-synthesized typed-fatal four-event lifecycle, then
requires `ResetSystem` to terminate QEMU before its bounded timeout.
