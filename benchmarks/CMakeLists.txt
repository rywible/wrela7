find_package(benchmark REQUIRED CONFIG)

add_executable(wrela_benchmarks LexerBenchmark.cpp)
wrela_target_defaults(wrela_benchmarks)
target_link_libraries(wrela_benchmarks PRIVATE benchmark::benchmark wrela::lex)
