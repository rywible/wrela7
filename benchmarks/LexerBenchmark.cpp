#include "wrela/Lex/Lexer.h"

#include <benchmark/benchmark.h>

#include <string_view>

namespace {

void lexFunctionSkeleton(benchmark::State& state) {
  constexpr std::string_view source = R"(
fn main() -> i32 {
  return 42;
}
)";

  for ([[maybe_unused]] auto _ : state) {
    auto tokens = wrela::lex::lexAll(source);
    benchmark::DoNotOptimize(tokens);
  }
}

BENCHMARK(lexFunctionSkeleton); // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

} // namespace

BENCHMARK_MAIN();
