#!/usr/bin/env sh
set -eu

CLANG_TIDY="${CLANG_TIDY:-/opt/homebrew/opt/llvm/bin/clang-tidy}"
BUILD_DIR="${BUILD_DIR:-build/debug}"
SDKROOT="${SDKROOT:-$(xcrun --show-sdk-path 2>/dev/null || true)}"
LIBCXX_INCLUDE="${LIBCXX_INCLUDE:-/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1}"
HOMEBREW_INCLUDE="${HOMEBREW_INCLUDE:-/opt/homebrew/include}"

EXTRA_ARGS=""
if [ -n "$SDKROOT" ]; then
  EXTRA_ARGS="$EXTRA_ARGS --extra-arg=-isysroot$SDKROOT"
fi
if [ -d "$LIBCXX_INCLUDE" ]; then
  EXTRA_ARGS="$EXTRA_ARGS --extra-arg=-isystem$LIBCXX_INCLUDE"
fi
if [ -d "$HOMEBREW_INCLUDE" ]; then
  EXTRA_ARGS="$EXTRA_ARGS --extra-arg=-isystem$HOMEBREW_INCLUDE"
fi
EXTRA_ARGS="$EXTRA_ARGS --extra-arg=-std=c++23"

find lib tools unittests benchmarks -type f -name '*.cpp' -print0 \
  | xargs -0 "$CLANG_TIDY" --quiet -p "$BUILD_DIR" $EXTRA_ARGS
