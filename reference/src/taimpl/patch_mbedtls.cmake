# Patch script for mbedTLS CMakeLists.txt
# This script modifies the mbedTLS CMakeLists.txt to require CMake 3.5 instead of 2.8.12

# Get the source directory from command line argument
set(MBEDTLS_SOURCE_DIR ${CMAKE_ARGV3})

if(NOT EXISTS "${MBEDTLS_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "mbedTLS CMakeLists.txt not found at ${MBEDTLS_SOURCE_DIR}/CMakeLists.txt")
endif()

message(STATUS "Patching ${MBEDTLS_SOURCE_DIR}/CMakeLists.txt")

# Read the original CMakeLists.txt
file(READ "${MBEDTLS_SOURCE_DIR}/CMakeLists.txt" MBEDTLS_CMAKELISTS)

# Replace cmake_minimum_required version from 2.6 to 3.10...3.28 range
string(REPLACE
    "cmake_minimum_required(VERSION 2.6)"
    "cmake_minimum_required(VERSION 3.10...3.28)"
    MBEDTLS_CMAKELISTS
    "${MBEDTLS_CMAKELISTS}"
)

# Also replace 2.8.12 if it exists (for other mbedTLS versions)
string(REPLACE
    "cmake_minimum_required(VERSION 2.8.12)"
    "cmake_minimum_required(VERSION 3.10...3.28)"
    MBEDTLS_CMAKELISTS
    "${MBEDTLS_CMAKELISTS}"
)

# Write the patched CMakeLists.txt
file(WRITE "${MBEDTLS_SOURCE_DIR}/CMakeLists.txt" "${MBEDTLS_CMAKELISTS}")

message(STATUS "Successfully patched mbedTLS CMakeLists.txt to require CMake 3.10...3.28")
