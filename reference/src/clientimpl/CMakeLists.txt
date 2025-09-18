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

project(saclientimpl)

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
else()
    message("clang-tidy disabled")
endif ()

set(CMAKE_CXX_FLAGS "-D_GNU_SOURCE -fPIC ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS "-D_GNU_SOURCE -fPIC ${CMAKE_C_FLAGS}")

if (COVERAGE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_C_FLAGS "-fprofile-arcs -ftest-coverage ${CMAKE_C_FLAGS}")
endif ()

include_directories(AFTER SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
find_package(Threads REQUIRED)

set(SACLIENTIMPL_SOURCES
        src/internal/client.c
        src/internal/client.h
        src/porting/ta_client.c
        src/porting/ta_client.h
        src/porting/sa_key_provision_impl.c
        src/sa_crypto_cipher_init.c
        src/sa_crypto_cipher_process.c
        src/sa_crypto_cipher_process_last.c
        src/sa_crypto_cipher_release.c
        src/sa_crypto_cipher_update_iv.c
        src/sa_crypto_mac_compute.c
        src/sa_crypto_mac_init.c
        src/sa_crypto_mac_process.c
        src/sa_crypto_mac_process_key.c
        src/sa_crypto_mac_release.c
        src/sa_crypto_random.c
        src/sa_crypto_sign.c
        src/sa_get_device_id.c
        src/sa_get_name.c
        src/sa_get_ta_uuid.c
        src/sa_get_version.c
        src/sa_key_derive.c
        src/sa_key_provision.c
        src/sa_key_digest.c
        src/sa_key_exchange.c
        src/sa_key_export.c
        src/sa_key_generate.c
        src/sa_key_get_public.c
        src/sa_key_header.c
        src/sa_key_import.c
        src/sa_key_release.c
        src/sa_key_unwrap.c
        src/sa_process_common_encryption.c
	src/sa_svp_supported.c
	)
if(NOT DISABLE_SVP)
    list(APPEND SACLIENTIMPL_SOURCES 
	src/porting/sa_svp_memory_alloc.c
	src/porting/sa_svp_memory_free.c
	src/sa_svp_buffer_check.c
	src/sa_svp_buffer_alloc.c
	src/sa_svp_buffer_copy.c
	src/sa_svp_buffer_free.c
	src/sa_svp_buffer_release.c
	src/sa_svp_buffer_write.c
	src/sa_svp_key_check.c
	src/sa_svp_buffer_create.c
        )
endif()

add_library(saclientimpl STATIC ${SACLIENTIMPL_SOURCES})

target_include_directories(saclientimpl
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/internal>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/porting>
        ${OPENSSL_INCLUDE_DIR}
        ${YAJL_INCLUDE_DIR}
        )

target_link_libraries(saclientimpl
        PRIVATE
        ${OPENSSL_CRYPTO_LIBRARY}
        ${CMAKE_THREAD_LIBS_INIT}
        ${YAJL_LIBRARY}
        taimpl
        util
        )

if (COVERAGE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(saclientimpl
            PRIVATE
            gcov
            )
endif ()

target_compile_options(saclientimpl PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

target_clangformat_setup(saclientimpl)
