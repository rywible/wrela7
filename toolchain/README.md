# Private toolchain inputs

This directory contains declarative, reviewable inputs used to construct wrela
release bundles. It is not itself the installed layout.

- `llvm.lock.toml` pins the source and linkage contract for LLVM, LLD, and
  Inkwell.
- `cmake/WrelaLLVM.cmake` contains the common LLVM distribution cache settings.
- `targets/` contains target packages copied under `share/wrela/targets` by the
  distribution task.

`cargo xtask llvm` and `cargo xtask dist` are the only supported paths for
building and packaging these inputs once those commands land. Cargo package
build scripts must not download LLVM or consult a global `llvm-config`.

