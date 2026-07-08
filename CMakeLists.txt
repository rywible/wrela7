cmake_minimum_required(VERSION 3.30)

project(
  wrela
  VERSION 0.1.0
  DESCRIPTION "A custom language compiler targeting MLIR and LLVM"
  LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(WRELA_ENABLE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(WRELA_ENABLE_WERROR "Treat compiler warnings as errors" OFF)
option(WRELA_ENABLE_CLANG_TIDY "Run clang-tidy during builds" OFF)
option(WRELA_BUILD_BENCHMARKS "Build compiler microbenchmarks" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(WrelaCompilerOptions)

find_package(LLVM REQUIRED CONFIG)
find_package(MLIR REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}: ${LLVM_DIR}")
message(STATUS "Found MLIR: ${MLIR_DIR}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${MLIR_CMAKE_DIR}")
include(AddLLVM)
include(AddMLIR)

include(CTest)

add_subdirectory(lib)
add_subdirectory(tools)

if(BUILD_TESTING)
  add_subdirectory(unittests)
  add_subdirectory(test)
endif()

if(WRELA_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
