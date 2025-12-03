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
        include/porting/transport.h
	include/porting/video_output.h
        src/porting/init.c
        src/porting/memory.c
        src/porting/otp.c
        src/porting/overflow.c
        src/porting/rand.c
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
        src/internal/symmetric.c
        src/internal/ta.c
        src/internal/typej.c
        src/internal/unwrap.c

        include/ta.h
        include/ta_sa.h
        include/ta_sa_cenc.h
        include/ta_sa_crypto.h
        include/ta_sa_key.h
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
        src/ta_sa_key_release.c
        src/ta_sa_key_unwrap.c
	src/ta_sa_process_common_encryption.c
        )


add_library(taimpl STATIC ${TAIMPL_SOURCES})

target_include_directories(taimpl
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util_mbedtls/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/internal/providers/edwards/ed25519-donna>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/internal/providers/decaf/ed448-goldilocks/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/internal>
        ${MBEDTLS_INCLUDE_DIR}
        ${YAJL_INCLUDE_DIR}
        )

target_link_libraries(taimpl
        PRIVATE
        util
        util_mbedtls
        ${MBEDTLS_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
        ${YAJL_LIBRARY}
        )

# ==============================================================================
# Cryptographic Provider Libraries (ED/X Curves)
# ==============================================================================
# These libraries provide Edwards and Montgomery curve cryptography support
# that is not available in mbedTLS 2.16.10:
#   - ed25519-donna: ED25519 EdDSA signatures and public key derivation
#   - curve25519-donna: X25519 ECDH and public key derivation
#   - libdecaf (ed448-goldilocks): ED448 and X448 operations
#
# Libraries are automatically downloaded and built using FetchContent.
# Custom headers for SecAPI integration are in cmake/custom_headers/
# ==============================================================================

include(FetchContent)

# ------------------------------------------------------------------------------
# 1. ed25519-donna Provider (ED25519 EdDSA)
# ------------------------------------------------------------------------------
set(EDWARDS_PROVIDER_ENABLED TRUE)
if(EDWARDS_PROVIDER_ENABLED)
    message(STATUS "Configuring ed25519-donna provider...")
    
    FetchContent_Declare(
        ed25519_donna
        GIT_REPOSITORY https://github.com/floodyberry/ed25519-donna.git
        GIT_TAG        master
        GIT_SHALLOW    TRUE
    )
    
    FetchContent_GetProperties(ed25519_donna)
    if(NOT ed25519_donna_POPULATED)
        FetchContent_Populate(ed25519_donna)
        
        # Copy custom headers for SecAPI integration
        file(COPY ${CMAKE_SOURCE_DIR}/cmake/custom_headers/ed25519-hash-custom.h
             DESTINATION ${ed25519_donna_SOURCE_DIR})
        file(COPY ${CMAKE_SOURCE_DIR}/cmake/custom_headers/ed25519-randombytes-custom.h
             DESTINATION ${ed25519_donna_SOURCE_DIR})
        
        # Create build configuration
        set(ED25519_SOURCES ${ed25519_donna_SOURCE_DIR}/ed25519.c)
        add_library(edwards_provider STATIC ${ED25519_SOURCES})
        
        target_include_directories(edwards_provider 
            PUBLIC ${ed25519_donna_SOURCE_DIR}
            PRIVATE 
                ${CMAKE_SOURCE_DIR}/src/taimpl/include
                ${MBEDTLS_INCLUDE_DIR}
        )
        
        target_compile_options(edwards_provider PRIVATE
            -Werror
            -Wall
            -Wextra
            -Wno-unused-parameter
            -Wno-unused-function
            -Wno-macro-redefined
        )
        
        # Define ED25519_CUSTOMHASH and ED25519_CUSTOMRANDOM to use our custom implementations
        target_compile_definitions(edwards_provider PRIVATE
            ED25519_CUSTOMHASH
            ED25519_CUSTOMRANDOM
        )
        
        # Ensure mbedTLS is built before edwards_provider (needed for SHA-512 headers)
        add_dependencies(edwards_provider mbedtls_external)
        
        set_property(TARGET edwards_provider PROPERTY C_STANDARD 99)
        
        message(STATUS "ed25519-donna provider configured successfully")
    endif()
    
    target_link_libraries(taimpl PUBLIC edwards_provider)
endif()

# ------------------------------------------------------------------------------
# 2. curve25519-donna Provider (X25519 ECDH)
# ------------------------------------------------------------------------------
set(CURVE25519_PROVIDER_ENABLED TRUE)
if(CURVE25519_PROVIDER_ENABLED)
    message(STATUS "Configuring curve25519-donna provider...")
    
    FetchContent_Declare(
        curve25519_donna
        GIT_REPOSITORY https://github.com/agl/curve25519-donna.git
        GIT_TAG        master
        GIT_SHALLOW    TRUE
    )
    
    FetchContent_GetProperties(curve25519_donna)
    if(NOT curve25519_donna_POPULATED)
        FetchContent_Populate(curve25519_donna)
        
        # Copy custom headers for SecAPI integration
        file(COPY ${CMAKE_SOURCE_DIR}/cmake/custom_headers/curve25519-donna.h
             DESTINATION ${curve25519_donna_SOURCE_DIR})
        file(COPY ${CMAKE_SOURCE_DIR}/cmake/custom_headers/curve25519-randombytes-custom.h
             DESTINATION ${curve25519_donna_SOURCE_DIR})
        
        # Create build configuration
        set(CURVE25519_SOURCES ${curve25519_donna_SOURCE_DIR}/curve25519-donna.c)
        add_library(curve25519_provider STATIC ${CURVE25519_SOURCES})
        
        target_include_directories(curve25519_provider 
            PUBLIC ${curve25519_donna_SOURCE_DIR}
            PRIVATE ${CMAKE_SOURCE_DIR}/src/taimpl/include
        )
        
        target_compile_options(curve25519_provider PRIVATE
            -Werror
            -Wall
            -Wextra
            -Wno-unused-parameter
            -Wno-unused-function
        )
        
        set_property(TARGET curve25519_provider PROPERTY C_STANDARD 99)
        
        message(STATUS "curve25519-donna provider configured successfully")
    endif()
    
    target_link_libraries(taimpl PUBLIC curve25519_provider)
endif()

# ------------------------------------------------------------------------------
# 3. libdecaf Provider (ED448 and X448)
# ------------------------------------------------------------------------------
set(DECAF_PROVIDER_ENABLED TRUE)
if(DECAF_PROVIDER_ENABLED)
    message(STATUS "Configuring libdecaf (ed448-goldilocks) provider...")
    
    # Use Git mirror since SourceForge SVN can be unreliable
    FetchContent_Declare(
        libdecaf
        GIT_REPOSITORY https://git.code.sf.net/p/ed448goldilocks/code
        GIT_TAG        master
        GIT_SHALLOW    TRUE
    )
    
    FetchContent_GetProperties(libdecaf)
    if(NOT libdecaf_POPULATED)
        FetchContent_Populate(libdecaf)
        
        # libdecaf has its own CMakeLists.txt build system
        # We need to configure it to build only what we need (curve448)
        # Disable building tests and other curves we don't need
        set(ENABLE_TESTS OFF CACHE BOOL "Disable libdecaf tests")
        set(ENABLE_STRICT OFF CACHE BOOL "Disable strict warnings for external library")
        
        # Add libdecaf as a subdirectory with its own build system
        add_subdirectory(${libdecaf_SOURCE_DIR} ${libdecaf_BINARY_DIR} EXCLUDE_FROM_ALL)
        
        # libdecaf builds a library called "decaf" - create an alias for our naming convention
        if(TARGET decaf)
            add_library(decaf_provider ALIAS decaf)
            message(STATUS "libdecaf provider configured successfully (using library: decaf)")
        else()
            message(FATAL_ERROR "libdecaf did not create expected 'decaf' target")
        endif()
    endif()
    
    target_link_libraries(taimpl PUBLIC decaf_provider)
endif()

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
        )
    add_executable(taimpltest ${TAIMPLTEST_SOURCES})

    target_include_directories(taimpltest
            PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util_mbedtls/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/internal>
            ${MBEDTLS_INCLUDE_DIR}
            ${OPENSSL_INCLUDE_DIR}
            )

    target_compile_options(taimpltest PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

    target_link_libraries(taimpltest
            PRIVATE
            gtest_main
            gmock_main
            taimpl
            util
            util_mbedtls
            ${MBEDTLS_LIBRARIES}
            )

    target_clangformat_setup(taimpltest)

    add_custom_command(
            TARGET taimpltest POST_BUILD
            BYPRODUCTS root_keystore.p12
            COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/test/root_keystore.p12
            ${CMAKE_CURRENT_BINARY_DIR}/root_keystore.p12)

    gtest_discover_tests(taimpltest)
endif ()
