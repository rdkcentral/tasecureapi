#
# Copyright 2020-2025 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions andf
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)


project(taimpl)

# Option for verbose debug logging (macro VERBOSE_LOG)
option(VERBOSE_LOG "Enable verbose debug logging" OFF)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

if (DEFINED ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_COMMAND NAMES clang-tidy)
    if (CLANG_TIDY_COMMAND)
        set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY_COMMAND}; )
        set(CMAKE_C_CLANG_TIDY ${CLANG_TIDY_COMMAND}; )
        message("clang-tidy found--enabling")
    else ()
        message("clang-tidy not found")
    endif ()
else ()
    message("clang-tidy disabled")
endif ()

find_package(OpenSSL REQUIRED)

# Optional mbedTLS support for PKCS#12
option(USE_MBEDTLS "Enable mbedTLS PKCS#12 support" OFF)

if(USE_MBEDTLS)
    message(STATUS "USE_MBEDTLS is enabled for util - using mbedTLS from parent project")

    # mbedTLS variables are set in the parent CMakeLists.txt
    # Just verify they exist
    if(NOT DEFINED MBEDTLS_INCLUDE_DIR OR NOT DEFINED MBEDTLS_LIBRARIES)
        message(FATAL_ERROR "MBEDTLS_INCLUDE_DIR and MBEDTLS_LIBRARIES must be defined by parent project")
    endif()

    message(STATUS "mbedTLS configured for util")
    message(STATUS "mbedTLS include dir: ${MBEDTLS_INCLUDE_DIR}")
    message(STATUS "mbedTLS libraries: ${MBEDTLS_LIBRARIES}")

    add_definitions(-DUSE_MBEDTLS=1)
else()
    message(STATUS "USE_MBEDTLS is disabled for util")
endif()

add_library(util STATIC
        include/common.h
        include/digest_util.h
        include/log.h
        include/pkcs8.h
        include/pkcs12.h
        include/sa_rights.h
        include/test_helpers.h
        include/test_process_common_encryption.h

        src/digest_util.c
        src/log.c
        src/pkcs8.c
        src/pkcs12.c
        src/sa_rights.c
        src/test_helpers.cpp
        src/test_process_common_encryption.cpp
        )

# Add mbedTLS PKCS#12 sources if enabled
if(USE_MBEDTLS)
    target_sources(util PRIVATE
        src/pkcs12_mbedtls.c
        include/pkcs12_mbedtls.h
    )
    message(STATUS "Added mbedTLS PKCS#12 sources to util")
endif()

# Always add VERBOSE_LOG macro if requested
if(VERBOSE_LOG)
    target_compile_definitions(util PRIVATE VERBOSE_LOG)
endif()

target_include_directories(util
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
        PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        )

# Add mbedTLS include directories if enabled
if(USE_MBEDTLS)
    target_include_directories(util PRIVATE ${MBEDTLS_INCLUDE_DIR})
endif()

target_link_libraries(util
        PRIVATE
        ${OPENSSL_CRYPTO_LIBRARY}
        )

# Add mbedTLS libraries if enabled
if(USE_MBEDTLS)
    target_link_libraries(util PRIVATE ${MBEDTLS_LIBRARIES})
endif()

target_compile_options(util PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

target_clangformat_setup(util)

if (BUILD_TESTS)
    # Google test
    add_executable(utiltest
            test/pkcs12test.cpp
            )

    target_include_directories(utiltest
            PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            ${OPENSSL_INCLUDE_DIR}
            )

    # Add mbedTLS include directories to tests if enabled
    if(USE_MBEDTLS)
        target_include_directories(utiltest PRIVATE ${MBEDTLS_INCLUDE_DIR})
    endif()

    target_compile_options(utiltest PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

    target_link_libraries(utiltest
            PRIVATE
            gtest
            gmock_main
            util
            ${OPENSSL_CRYPTO_LIBRARY}
            )

    # Add mbedTLS libraries to tests if enabled
    if(USE_MBEDTLS)
        target_link_libraries(utiltest PRIVATE ${MBEDTLS_LIBRARIES})
    endif()

    target_clangformat_setup(utiltest)

    add_custom_command(
            TARGET utiltest POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/test/root_keystore.p12
            ${CMAKE_CURRENT_BINARY_DIR}/root_keystore.p12)

    gtest_discover_tests(utiltest)
endif ()

