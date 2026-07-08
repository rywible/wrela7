function(wrela_target_defaults target)
  target_compile_features(${target} PUBLIC cxx_std_23)

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(
      ${target}
      PRIVATE -Wall
              -Wextra
              -Wpedantic
              -Wconversion
              -Wdouble-promotion
              -Wformat=2
              -Wimplicit-fallthrough
              -Wnon-virtual-dtor
              -Wnull-dereference
              -Wold-style-cast
              -Woverloaded-virtual
              -Wshadow
              -Wsign-conversion
              -Wunused)
  elseif(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive-)
  endif()

  if(WRELA_ENABLE_WERROR)
    if(MSVC)
      target_compile_options(${target} PRIVATE /WX)
    else()
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()

  if(WRELA_ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
      target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
  endif()

  if(WRELA_ENABLE_CLANG_TIDY)
    find_program(WRELA_CLANG_TIDY_EXE NAMES clang-tidy PATHS /opt/homebrew/opt/llvm/bin)
    if(WRELA_CLANG_TIDY_EXE)
      set_property(TARGET ${target} PROPERTY CXX_CLANG_TIDY "${WRELA_CLANG_TIDY_EXE}")
    endif()
  endif()
endfunction()

function(wrela_target_include_dirs target)
  target_include_directories(
    ${target}
    PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:include>)
endfunction()
