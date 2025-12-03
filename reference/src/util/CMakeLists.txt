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

project(util)

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

# Minimal util library - no crypto library dependencies
# Contains: logging, digest utilities, and sa_rights (shared by all)
# Note: common.h is library-specific and lives in util_openssl and util_mbedtls
add_library(util STATIC
        include/digest_util.h
        include/log.h
        include/root_keystore.h
        include/sa_rights.h

        src/digest_util.c
        src/log.c
        src/sa_rights.c
        )

# Always add VERBOSE_LOG macro if requested
if(VERBOSE_LOG)
    target_compile_definitions(util PRIVATE VERBOSE_LOG)
endif()

target_include_directories(util
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
        )

# No external library dependencies - util is now standalone
target_compile_options(util PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

target_clangformat_setup(util)
