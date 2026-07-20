# Toolchain inputs

This directory holds wrela's own pinned build inputs. It no longer builds,
acquires, or pins LLVM, LLD, QEMU, or EDK2 firmware: those come from whatever
copies are already installed on the developer's machine.

- `targets/aarch64-qemu-virt-uefi/` is the pinned AArch64 `virt` UEFI target
  profile (`target.toml`) plus its runtime object. The object is built by
  `runtime-src/build_runtime.py` from the reviewable `runtime-src/runtime.S`,
  and `runtime-src/runtime-object.lock.toml` enrolls the exact compiler,
  source, and object digests so a rebuild can be checked for byte identity.
  See `runtime-src/README.md` for the build/enrollment procedure. This is a
  real wrela artifact, not a bootstrap input.
- `oracles/` holds reference material used to cross-check target behavior
  (currently `qemu-edk2-aarch64`); it is not itself built or installed.

## LLVM, LLD, and QEMU

The native code-generation backend is opt-in via the `wrela-backend/bundled-backend`
Cargo feature. Enabling it turns on:

- `wrela-codegen-llvm/llvm`, which links `inkwell`/`llvm-sys` against the
  system LLVM. `.cargo/config.toml` sets `LLVM_SYS_221_PREFIX` (and
  `WRELA_LLVM_PREFIX`) to the on-disk install (Homebrew's `/opt/homebrew/opt/llvm`
  by default); override either variable to point at a different LLVM 22
  install.
- `wrela-link-efi/bundled-lld`, which makes the EFI linker shell out to the
  system `lld-link` executable instead of linking LLD in-process. Override
  with `WRELA_LLD_LINK`.

The workspace builds without LLVM by default (the feature is off).

Full-image tests resolve `qemu-system-aarch64` and the EDK2 AArch64 code/vars
firmware from the system at runtime (Homebrew defaults under
`/opt/homebrew/...`), overridable with `WRELA_QEMU`,
`WRELA_QEMU_FIRMWARE_CODE`, and `WRELA_QEMU_FIRMWARE_VARS`. Neither is sealed
by the toolchain manifest; the manifest still seals wrela's own frontend
binary, backend, standard library, and the target runtime object above.

There is no `cargo xtask llvm`, `cargo xtask qemu`, `cargo xtask linux-engine`,
`cargo xtask dist`, or `cargo xtask cargo-vendor`. `cargo xtask architecture-check`,
`slices`, `check`, `test`, `lint`, and `gate` are the only maintainer commands;
see the root [`README.md`](../README.md) for the development loop.
