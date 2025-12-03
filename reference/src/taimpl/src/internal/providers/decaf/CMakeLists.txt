cmake_minimum_required(VERSION 3.10)

# ed448-goldilocks (libdecaf) provider for Ed448/X448 operations
# Note: We only use decaf for curve448 (Ed448/X448), not curve25519
# Curve25519 (Ed25519/X25519) is handled by ed25519-donna and curve25519-donna
project(decaf_provider C)

# Detect architecture for optimal field implementation
set(TARGET_ARCH_DIR_P448 "arch_32")

if((${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64" OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "amd64") AND NOT MSVC)
    message(STATUS "libdecaf: Using x86_64 architecture for curve448")
    set(TARGET_ARCH_DIR_P448 "arch_x86_64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "aarch64" OR ${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm64")
    message(STATUS "libdecaf: Using 64-bit generic architecture (ARM64) for curve448")
    set(TARGET_ARCH_DIR_P448 "arch_ref64")
elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "^arm")
    message(STATUS "libdecaf: Using ARM 32-bit architecture for curve448")
    set(TARGET_ARCH_DIR_P448 "arch_arm_32")
else()
    message(STATUS "libdecaf: Using generic 32-bit architecture for curve448")
endif()

# ============================================================================
# Library: decaf_448 for Ed448/X448 only
# ============================================================================

# Source files for p448 field arithmetic
set(P448_SOURCES
    ed448-goldilocks/src/p448/${TARGET_ARCH_DIR_P448}/f_impl.c
    ed448-goldilocks/src/p448/f_arithmetic.c
    ed448-goldilocks/src/generated/p448/f_generic.c
)

# Source files for Ed448/X448 curve operations
set(ED448_SOURCES
    ed448-goldilocks/src/generated/ed448goldilocks/decaf.c
    ed448-goldilocks/src/generated/ed448goldilocks/scalar.c
    ed448-goldilocks/src/generated/ed448goldilocks/eddsa.c
    ed448-goldilocks/src/generated/ed448goldilocks/elligator.c
    ed448-goldilocks/src/decaf_tables.c
)

# Utility sources for curve448
set(UTIL_448_SOURCES
    ed448-goldilocks/src/utils.c
    ed448-goldilocks/src/shake.c
    ed448-goldilocks/src/sha512.c
    ed448-goldilocks/src/spongerng.c
)

add_library(decaf_provider STATIC ${P448_SOURCES} ${ED448_SOURCES} ${UTIL_448_SOURCES})

target_include_directories(decaf_provider
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/ed448-goldilocks/include
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/ed448-goldilocks/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}/ed448-goldilocks/src/include/${TARGET_ARCH_DIR_P448}
    ${CMAKE_CURRENT_SOURCE_DIR}/ed448-goldilocks/src/p448
    ${CMAKE_CURRENT_SOURCE_DIR}/ed448-goldilocks/src/p448/${TARGET_ARCH_DIR_P448}
    ${CMAKE_CURRENT_SOURCE_DIR}/ed448-goldilocks/src/generated/p448
    ${CMAKE_CURRENT_SOURCE_DIR}/ed448-goldilocks/src
)

target_compile_options(decaf_provider PRIVATE
    -Werror
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-unused-function
    -fno-strict-aliasing
)

# Define DECAF_448 to select curve448 definitions
target_compile_definitions(decaf_provider PRIVATE DECAF_448=1)

set_property(TARGET decaf_provider PROPERTY C_STANDARD 99)
