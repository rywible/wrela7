# wrela

`wrela` is a custom language compiler targeting MLIR and LLVM.

## Toolchain

This repo is configured for:

- C++23
- CMake presets and Ninja
- LLVM + MLIR 22.1.8
- GoogleTest unit tests
- LLVM-style `lit` + `FileCheck` compiler tests
- `clang-format`, `clang-tidy`, sanitizers, and `ccache`

On macOS, Homebrew LLVM is keg-only, so the presets point CMake at
`/opt/homebrew/opt/llvm`. The default local compiler is AppleClang because the
current Homebrew Clang 22 install can conflict with local Xcode SDK include-path
ordering. LLVM and MLIR libraries still come from Homebrew LLVM.

## Build

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Run the compiler:

```sh
build/debug/tools/wrela/wrela --version
build/debug/tools/wrela/wrela check test/check-empty.wrela
```

Sanitizer build:

```sh
cmake --preset asan
cmake --build --preset asan
ctest --preset asan
```

Format and lint helpers:

```sh
tools/format.sh
tools/lint.sh
```

Run benchmarks:

```sh
build/debug/benchmarks/wrela_benchmarks
```
