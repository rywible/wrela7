# Private toolchain inputs

This directory contains declarative, reviewable inputs used to construct wrela
release bundles. It is not itself the installed layout.

- `llvm.lock.toml` pins the source and linkage contract for LLVM, LLD, and
  Inkwell.
- `emulation.lock.toml` pins the signed QEMU source, AArch64-only system target,
  versioned machine/CPU/TCG contract, and exact decompressed EDK2 code/variable
  firmware digests and license manifest.
- `cmake/WrelaLLVM.cmake` contains the common LLVM distribution cache settings.
- `targets/` contains the package copied under `share/wrela/targets` by the
  distribution task. Revision 0.1 ships only the full-image
  `aarch64-qemu-virt-uefi` machine profile, including its runtime and firmware.
- the distribution also ships a pinned `qemu-system-aarch64` for full-image
  integration and image tests.

`cargo xtask llvm` and `cargo xtask dist` are the only supported paths for
building and packaging these inputs once those commands land. Cargo package
build scripts must not download LLVM or consult a global `llvm-config`.
