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

project(taimpl)

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

if (DEFINED SA_LOG_LEVEL)
    set(CMAKE_CXX_FLAGS "-DSA_LOG_LEVEL=${SA_LOG_LEVEL} ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-DSA_LOG_LEVEL=${SA_LOG_LEVEL} ${CMAKE_C_FLAGS}")
endif ()

if (DEFINED DISABLE_CENC_1000000_TESTS)
    set(CMAKE_CXX_FLAGS "-DDISABLE_CENC_1000000_TESTS ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-DDISABLE_CENC_1000000_TESTS ${CMAKE_C_FLAGS}")
endif ()

find_package(OpenSSL REQUIRED)
include_directories(AFTER SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
find_package(Threads REQUIRED)
find_package(YAJL REQUIRED)

set(TAIMPL_SOURCES
        include/porting/init.h
        include/porting/memory.h
        include/porting/otp.h
        include/porting/otp_internal.h
        include/porting/overflow.h
        include/porting/rand.h
	include/porting/svp.h
        include/porting/transport.h
	include/porting/video_output.h
        src/porting/init.c
        src/porting/memory.c
        src/porting/otp.c
        src/porting/overflow.c
        src/porting/rand.c
	src/porting/svp.c
	src/porting/transport.c
	src/porting/video_output.c

        include/internal/buffer.h
        include/internal/cenc.h
        include/internal/cipher_store.h
        include/internal/client_store.h
        include/internal/cmac_context.h
        include/internal/dh.h
        include/internal/digest.h
        include/internal/ec.h
        include/internal/hmac_internal.h
        include/internal/hmac_context.h
        include/internal/json.h
        include/internal/kdf.h
        include/internal/key_store.h
        include/internal/key_type.h
        include/internal/mac_store.h
        include/internal/netflix.h
        include/internal/object_store.h
        include/internal/pad.h
        include/internal/rights.h
        include/internal/rsa.h
        include/internal/rsa_internal.h
        include/internal/saimpl.h
        include/internal/slots.h
        include/internal/soc_key_container.h
        include/internal/stored_key.h
        include/internal/stored_key_internal.h
	include/internal/svp_store.h
        include/internal/symmetric.h
        include/internal/typej.h
        include/internal/unwrap.h

	src/internal/buffer.c
	src/internal/cenc.c
        src/internal/cipher_store.c
        src/internal/client_store.c
        src/internal/cmac_context.c
        src/internal/dh.c
        src/internal/digest.c
        src/internal/ec.c
        src/internal/hmac_context.c
        src/internal/json.c
        src/internal/kdf.c
        src/internal/key_store.c
        src/internal/key_type.c
        src/internal/mac_store.c
        src/internal/netflix.c
        src/internal/object_store.c
        src/internal/pad.c
        src/internal/rights.c
        src/internal/rsa.c
        src/internal/saimpl.c
        src/internal/slots.c
        src/internal/soc_key_container.c
        src/internal/stored_key.c
	src/internal/svp_store.c
        src/internal/symmetric.c
        src/internal/ta.c
        src/internal/typej.c
        src/internal/unwrap.c

        include/ta.h
        include/ta_sa.h
        include/ta_sa_cenc.h
        include/ta_sa_crypto.h
        include/ta_sa_key.h
        include/ta_sa_svp.h
        include/ta_sa_types.h

        src/ta_sa_close.c
        src/ta_sa_crypto_cipher_init.c
	src/ta_sa_crypto_cipher_process.c
	src/ta_sa_crypto_cipher_process_last.c
        src/ta_sa_crypto_cipher_release.c
        src/ta_sa_crypto_cipher_update_iv.c
        src/ta_sa_crypto_mac_compute.c
        src/ta_sa_crypto_mac_init.c
        src/ta_sa_crypto_mac_process.c
        src/ta_sa_crypto_mac_process_key.c
        src/ta_sa_crypto_mac_release.c
        src/ta_sa_crypto_random.c
        src/ta_sa_crypto_sign.c
        src/ta_sa_get_device_id.c
        src/ta_sa_get_name.c
        src/ta_sa_get_ta_uuid.c
        src/ta_sa_get_version.c
        src/ta_sa_init.c
        src/ta_sa_key_derive.c
        src/ta_sa_key_digest.c
        src/ta_sa_key_exchange.c
        src/ta_sa_key_export.c
        src/ta_sa_key_generate.c
        src/ta_sa_key_get_public.c
        src/ta_sa_key_header.c
        src/ta_sa_key_import.c
        src/ta_sa_key_provision.c
        src/ta_sa_key_release.c
        src/ta_sa_key_unwrap.c
	src/ta_sa_process_common_encryption.c
	src/ta_sa_svp_supported.c
        )
if(ENABLE_SVP)
    list(APPEND TAIMPL_SOURCES 
	src/ta_sa_svp_buffer_check.c
	src/ta_sa_svp_buffer_copy.c
	src/ta_sa_svp_buffer_create.c
	src/ta_sa_svp_buffer_release.c
	src/ta_sa_svp_buffer_write.c
	src/ta_sa_svp_key_check.c
	)
endif()


add_library(taimpl STATIC ${TAIMPL_SOURCES})

target_include_directories(taimpl
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/internal>
        ${OPENSSL_INCLUDE_DIR}
        ${YAJL_INCLUDE_DIR}
        )

target_link_libraries(taimpl
        PRIVATE
        util
        ${OPENSSL_CRYPTO_LIBRARY}
        ${CMAKE_THREAD_LIBS_INIT}
        ${YAJL_LIBRARY}
        )

if (COVERAGE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(taimpl
            PRIVATE
            gcov
            )
endif ()

find_package(OpenSSL REQUIRED)

target_compile_options(taimpl PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

target_clangformat_setup(taimpl)

if (BUILD_TESTS)
    # Google test
    set(TAIMPLTEST_SOURCES
            test/environment.cpp
            test/ta_test_helpers.cpp
            test/json.cpp
            test/object_store.cpp
            test/rights.cpp
            test/slots.cpp
            test/ta_sa_init.cpp
	    test/ta_sa_svp_crypto.cpp
	    test/ta_sa_svp_crypto.h
        )
    if(NOT ENABLE_SVP)
        list(APPEND TAIMPLTEST_SOURCES
	    test/ta_sa_svp_key_check.cpp
	    test/ta_sa_svp_buffer_check.cpp
	    test/ta_sa_svp_buffer_copy.cpp
	    test/ta_sa_svp_buffer_write.cpp
	    test/ta_sa_svp_common.cpp
    	    )
    endif()
    add_executable(taimpltest ${TAIMPLTEST_SOURCES})

    target_include_directories(taimpltest
            PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/internal>
            ${OPENSSL_INCLUDE_DIR}
            )

    target_compile_options(taimpltest PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

    target_link_libraries(taimpltest
            PRIVATE
            gtest_main
            gmock_main
            taimpl
            util
            ${OPENSSL_CRYPTO_LIBRARY}
            )

    target_clangformat_setup(taimpltest)

    add_custom_command(
            TARGET taimpltest POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/test/root_keystore.p12
            ${CMAKE_CURRENT_BINARY_DIR}/root_keystore.p12)

    gtest_discover_tests(taimpltest)
endif ()
