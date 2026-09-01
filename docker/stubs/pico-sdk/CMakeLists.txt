# Minimal Pico SDK project whose only job is to compile the requested
# libraries. Harvest reads the build tree (.o / .a), never ghidra_stub.elf:
# that ELF has been --gc-sections'd down to what main.c referenced.
#
# Adding stubs/zephyr/ later is another directory with the same GHIDRA_*
# cache variables; the builder does not special-case this file.

cmake_minimum_required(VERSION 3.13)

if(NOT GHIDRA_SDK_PATH)
    message(FATAL_ERROR "GHIDRA_SDK_PATH must point at a checked-out Pico SDK")
endif()

set(PICO_SDK_PATH "${GHIDRA_SDK_PATH}" CACHE PATH "Pico SDK" FORCE)
if(GHIDRA_BOARD)
    set(PICO_BOARD "${GHIDRA_BOARD}" CACHE STRING "Pico board" FORCE)
endif()

# The toolchain is NOT selected here. pico-sdk resolves its own compiler
# through pico_find_compiler, which searches PATH; the builder's packed
# prefixes are deliberately off PATH, so CMAKE_C_COMPILER alone is ignored
# and configure fails with "Compiler 'arm-none-eabi-gcc' not found".
# PICO_TOOLCHAIN_PATH / PICO_GCC_TRIPLE come in as -D cache entries from
# the toolchain_cache_vars block in stub.json, filled from the resolved
# toolchain identity.
#
# Nested ExternalProject builds of pioasm/picotool use the host compiler.
# Do not set CC/CXX in the environment. PICO_NO_PICOTOOL skips the 2.1.0
# GitHub fetch of picotool (we harvest objects, not UF2).
set(PICO_NO_PICOTOOL 1 CACHE BOOL "" FORCE)

include("${PICO_SDK_PATH}/pico_sdk_init.cmake")

project(ghidra_framework_stub C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
pico_sdk_init()

add_executable(ghidra_stub main.c)

if(NOT GHIDRA_LIBRARIES)
    message(FATAL_ERROR "GHIDRA_LIBRARIES is empty; linking nothing produces nothing")
endif()

# CMake list (semicolon-separated). Linking INTERFACE pico libraries compiles
# their sources into this target even when main.c never calls them.
target_link_libraries(ghidra_stub ${GHIDRA_LIBRARIES})
