#!/usr/bin/env sh
set -eu

CLANG_FORMAT="${CLANG_FORMAT:-/opt/homebrew/opt/llvm/bin/clang-format}"

find include lib tools unittests benchmarks -type f \( -name '*.h' -o -name '*.cpp' \) -print0 \
  | xargs -0 "$CLANG_FORMAT" -i
