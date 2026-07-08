include(GoogleTest)

find_package(GTest REQUIRED CONFIG)

add_executable(
  wrela_unittests
  Basic/VersionTest.cpp
  Diagnostics/DiagnosticEngineTest.cpp
  IR/MLIRSupportTest.cpp
  Lex/LexerTest.cpp
  Source/SourceBufferTest.cpp)

wrela_target_defaults(wrela_unittests)
target_link_libraries(
  wrela_unittests
  PRIVATE GTest::gtest_main
          wrela::basic
          wrela::diagnostics
          wrela::source
          wrela::lex
          wrela::ir)

gtest_discover_tests(wrela_unittests)
