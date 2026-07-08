find_program(WRELA_LIT_EXE NAMES lit PATHS "$ENV{HOME}/.local/bin")
find_program(WRELA_FILECHECK_EXE NAMES FileCheck PATHS "${LLVM_TOOLS_BINARY_DIR}" /opt/homebrew/opt/llvm/bin)

if(WRELA_LIT_EXE AND WRELA_FILECHECK_EXE)
  set(WRELA_LIT_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  set(WRELA_LIT_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")
  set(WRELA_LIT_FILECHECK_EXE "${WRELA_FILECHECK_EXE}")

  file(
    GENERATE
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py"
    CONTENT
      "import os\n\nconfig.wrela_exe = \"$<TARGET_FILE:wrela>\"\nconfig.filecheck_exe = \"${WRELA_LIT_FILECHECK_EXE}\"\nconfig.test_exec_root = \"${WRELA_LIT_BINARY_DIR}\"\n\nlit_config.load_config(config, \"${WRELA_LIT_SOURCE_DIR}/lit.cfg.py\")\n\nconfig.substitutions.append((\"%wrela\", config.wrela_exe))\nconfig.substitutions.append((\"%FileCheck\", config.filecheck_exe))\n")

  add_custom_target(
    check-wrela-lit
    COMMAND "${WRELA_LIT_EXE}" -sv "${CMAKE_CURRENT_BINARY_DIR}"
    DEPENDS wrela
    USES_TERMINAL)

  add_test(NAME wrela-lit COMMAND "${WRELA_LIT_EXE}" -sv "${CMAKE_CURRENT_BINARY_DIR}")
else()
  message(WARNING "lit/FileCheck not found; compiler fixture tests are disabled")
endif()
