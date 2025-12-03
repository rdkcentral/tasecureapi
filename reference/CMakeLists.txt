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
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)

project(tasecureapi)

option(BUILD_TESTS  "Builds and installs the unit tests" ON)
option(BUILD_DOC    "Build documentation" ON)
option(ENABLE_SVP  "Build SecAPI with SVP" OFF)
set(USE_MBEDTLS ON CACHE BOOL "Enable mbedTLS for all sub-projects" FORCE)

if(ENABLE_SVP)
    message(STATUS "ENABLE_SVP is ON: Building SecAPI  SVP functionality")
else()
    message(STATUS "ENABLE_SVP is OFF: Building SecAPI without SVP functionality")
endif()

if(${BUILD_TESTS})
    # Download and unpack googletest at configure time
    include(FetchContent)
    FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.13.0
    )

    FetchContent_GetProperties(googletest)
    if(NOT googletest_POPULATED)
        FetchContent_Populate(googletest)
        add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()

    set_property(GLOBAL PROPERTY CTEST_TARGETS_ADDED 1)
    include(CTest)
    include(GoogleTest)
endif()

# Setup mbedTLS before adding subdirectories so all sub-projects can use it
if(USE_MBEDTLS)
    message(STATUS "Setting up mbedTLS 2.16.10 via ExternalProject_Add")
    include(ExternalProject)

    ExternalProject_Add(
        mbedtls_external
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG mbedtls-2.16.10
        GIT_SHALLOW TRUE
        PREFIX ${CMAKE_BINARY_DIR}/mbedtls
        PATCH_COMMAND ${CMAKE_COMMAND} -E echo "Patching mbedTLS CMakeLists.txt to require CMake 3.10...3.28"
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/patch_mbedtls.cmake <SOURCE_DIR>
            COMMAND ${CMAKE_COMMAND} -E echo "Enabling mbedTLS threading support for concurrent operations"
            COMMAND sed -i.bak "s|//#define MBEDTLS_THREADING_PTHREAD|#define MBEDTLS_THREADING_PTHREAD|g" <SOURCE_DIR>/include/mbedtls/config.h
            COMMAND sed -i.bak "s|//#define MBEDTLS_THREADING_C|#define MBEDTLS_THREADING_C|g" <SOURCE_DIR>/include/mbedtls/config.h
        CMAKE_ARGS 
            -DENABLE_PROGRAMS=OFF 
            -DENABLE_TESTING=OFF 
            -DUSE_SHARED_MBEDTLS_LIBRARY=OFF 
            -DUSE_STATIC_MBEDTLS_LIBRARY=ON
            -DENABLE_ZLIB_SUPPORT=OFF
        INSTALL_COMMAND ""
    )

    # Set mbedTLS variables (will be populated after ExternalProject builds)
    set(MBEDTLS_INCLUDE_DIR ${CMAKE_BINARY_DIR}/mbedtls/src/mbedtls_external/include CACHE PATH "mbedTLS include directory")
    set(MBEDTLS_LIBRARY_DIR ${CMAKE_BINARY_DIR}/mbedtls/src/mbedtls_external-build/library CACHE PATH "mbedTLS library directory")

    # Create IMPORTED library targets for mbedTLS libraries
    add_library(mbedtls_lib STATIC IMPORTED GLOBAL)
    set_target_properties(mbedtls_lib PROPERTIES
        IMPORTED_LOCATION ${MBEDTLS_LIBRARY_DIR}/libmbedtls.a
    )
    add_dependencies(mbedtls_lib mbedtls_external)

    add_library(mbedcrypto_lib STATIC IMPORTED GLOBAL)
    set_target_properties(mbedcrypto_lib PROPERTIES
        IMPORTED_LOCATION ${MBEDTLS_LIBRARY_DIR}/libmbedcrypto.a
    )
    add_dependencies(mbedcrypto_lib mbedtls_external)

    add_library(mbedx509_lib STATIC IMPORTED GLOBAL)
    set_target_properties(mbedx509_lib PROPERTIES
        IMPORTED_LOCATION ${MBEDTLS_LIBRARY_DIR}/libmbedx509.a
    )
    add_dependencies(mbedx509_lib mbedtls_external)

    set(MBEDTLS_LIBRARIES mbedtls_lib mbedcrypto_lib mbedx509_lib CACHE STRING "mbedTLS libraries")

    message(STATUS "mbedTLS configured globally")
    message(STATUS "mbedTLS include dir: ${MBEDTLS_INCLUDE_DIR}")
    message(STATUS "mbedTLS libraries: ${MBEDTLS_LIBRARIES}")
endif()

add_subdirectory(src)
