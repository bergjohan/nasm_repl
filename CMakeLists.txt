cmake_minimum_required(VERSION 3.13)
project(nasm_repl)

add_library(linenoise STATIC external/linenoise/linenoise.c)

enable_language(ASM_NASM)

add_executable(nasm_repl src/nasm_repl.c src/nasm_repl.asm)
target_include_directories(nasm_repl PRIVATE external/linenoise)
target_compile_features(nasm_repl PRIVATE c_std_99)
target_compile_options(nasm_repl PRIVATE
  $<$<COMPILE_LANGUAGE:C>:
  -Werror
  -pedantic-errors
  -Wall
  -Wextra
  -Wconversion
  -Wsign-conversion
  >
)
target_link_libraries(nasm_repl PRIVATE linenoise)
