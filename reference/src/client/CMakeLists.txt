#
# Copyright 2020-2023 Comcast Cable Communications Management, LLC
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

project(saclient)

find_program(CLANG_TIDY_COMMAND NAMES clang-tidy)

if (DEFINED ENABLE_CLANG_TIDY)
    if (CLANG_TIDY_COMMAND)
        set(CMAKE_C_CLANG_TIDY ${CLANG_TIDY_COMMAND}; )
        message("clang-tidy found--enabling")
    else ()
        message("clang-tidy not found")
    endif ()
else ()
    message("clang-tidy disabled")
endif ()

if (DEFINED ENABLE_CLANG_TIDY_TESTS)
    if (CLANG_TIDY_COMMAND)
        set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY_COMMAND}; )
        message("clang-tidy found--enabling for tests")
    endif ()
else ()
    message("clang-tidy disabled for tests")
endif ()

if (DEFINED DISABLE_CENC_1000000_TESTS)
    set(CMAKE_CXX_FLAGS "-DDISABLE_CENC_1000000_TESTS ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-DDISABLE_CENC_1000000_TESTS ${CMAKE_C_FLAGS}")
endif ()

find_package(OpenSSL REQUIRED)

add_library(saclient SHARED
        include/sa.h
        include/sa_cenc.h
        include/sa_crypto.h
        include/sa_engine.h
        include/sa_key.h
        include/sa_provider.h
        include/sa_svp.h
        include/sa_ta_types.h
        include/sa_types.h

        src/sa_engine.c
        src/sa_engine_cipher.c
        src/sa_engine_digest.c
        src/sa_engine_internal.h
        src/sa_engine_pkey.c
        src/sa_engine_pkey_asn1_method.c
        src/sa_engine_pkey_data.c
        src/sa_provider.c
        src/sa_provider_asym_cipher.c
        src/sa_provider_cipher.c
        src/sa_provider_digest.c
        src/sa_provider_internal.h
        src/sa_provider_kdf.c
        src/sa_provider_keyexch.c
        src/sa_provider_keymgt.c
        src/sa_provider_mac.c
        src/sa_provider_signature.c
        src/sa_public_key.h
        src/sa_public_key.c
        )

target_compile_options(saclient PRIVATE -Werror -Wall -Wextra -Wno-type-limits -Wno-unused-parameter
        -Wno-deprecated-declarations)

set_target_properties(saclient PROPERTIES
        LINKER_LANGUAGE C
        SO_VERSION 3.4
        VERSION 3.4.0
        )

target_include_directories(saclient
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        ${OPENSSL_INCLUDE_DIR}
        )

if (CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
    # using Clang
    target_include_directories(saclient
            PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
            )

    target_link_libraries(saclient
            PRIVATE
            -Wl,-all_load
            saclientimpl
            util
            ${OPENSSL_CRYPTO_LIBRARY}
            )
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # using GCC
    target_link_libraries(saclient
            PRIVATE
            -Wl,--whole-archive
            saclientimpl
            -Wl,--no-whole-archive
            util
            ${OPENSSL_CRYPTO_LIBRARY}
            )
endif ()

target_clangformat_setup(saclient)

if (BUILD_TESTS)
    # Google test
    set(SACLIENT_TEST_SOURCES
            test/client_test_helpers.cpp
            test/client_test_helpers.h
            test/environment.cpp
            test/sa_crypto_cipher_common.h
            test/sa_crypto_cipher_common.cpp
            test/sa_crypto_cipher_init.cpp
            test/sa_crypto_cipher_init_aes_cbc.cpp
            test/sa_crypto_cipher_init_aes_cbc_pkcs7.cpp
            test/sa_crypto_cipher_init_aes_ctr.cpp
            test/sa_crypto_cipher_init_aes_ecb.cpp
            test/sa_crypto_cipher_init_aes_ecb_pkcs7.cpp
            test/sa_crypto_cipher_init_aes_gcm.cpp
            test/sa_crypto_cipher_init_ec_elgamal.cpp
            test/sa_crypto_cipher_init_chacha20.cpp
            test/sa_crypto_cipher_init_chacha20_poly1305.cpp
            test/sa_crypto_cipher_init_rsa_oaep.cpp
            test/sa_crypto_cipher_init_rsa_pkcs1v15.cpp
            test/sa_crypto_cipher_process.cpp
            test/sa_crypto_cipher_process_aes_cbc.cpp
            test/sa_crypto_cipher_process_aes_cbc_pkcs7.cpp
            test/sa_crypto_cipher_process_aes_ctr.cpp
            test/sa_crypto_cipher_process_aes_ecb.cpp
            test/sa_crypto_cipher_process_aes_ecb_pkcs7.cpp
            test/sa_crypto_cipher_process_aes_gcm.cpp
            test/sa_crypto_cipher_process_chacha20.cpp
            test/sa_crypto_cipher_process_chacha20_poly1305.cpp
            test/sa_crypto_cipher_process_ec_elgamal.cpp
            test/sa_crypto_cipher_process_last.cpp
            test/sa_crypto_cipher_process_last_aes_cbc.cpp
            test/sa_crypto_cipher_process_last_aes_cbc_pkcs7.cpp
            test/sa_crypto_cipher_process_last_aes_ctr.cpp
            test/sa_crypto_cipher_process_last_aes_ecb.cpp
            test/sa_crypto_cipher_process_last_aes_ecb_pkcs7.cpp
            test/sa_crypto_cipher_process_last_aes_gcm.cpp
            test/sa_crypto_cipher_process_last_chacha20_poly1305.cpp
            test/sa_crypto_cipher_process_last_ec_elgamal.cpp
            test/sa_crypto_cipher_process_last_rsa_oaep.cpp
            test/sa_crypto_cipher_process_last_rsa_pkcs1v15.cpp
            test/sa_crypto_cipher_process_rsa_oaep.cpp
            test/sa_crypto_cipher_process_rsa_pkcs1v15.cpp
            test/sa_crypto_cipher_release.cpp
            test/sa_crypto_cipher_update_iv.cpp
            test/sa_crypto_cipher_update_iv_aes_cbc.cpp
            test/sa_crypto_cipher_update_iv_aes_cbc_pkcs7.cpp
            test/sa_crypto_cipher_update_iv_aes_ctr.cpp
            test/sa_crypto_cipher_update_iv_aes_ecb.cpp
            test/sa_crypto_cipher_update_iv_aes_ecb_pkcs7.cpp
            test/sa_crypto_cipher_update_iv_aes_gcm.cpp
            test/sa_crypto_cipher_update_iv_chacha20.cpp
            test/sa_crypto_cipher_update_iv_chacha20_poly1305.cpp
            test/sa_crypto_cipher_update_iv_ec_elgamal.cpp
            test/sa_crypto_cipher_update_iv_rsa_oaep.cpp
            test/sa_crypto_cipher_update_iv_rsa_pkcs1v15.cpp
            test/sa_crypto_mac_common.cpp
            test/sa_crypto_mac_common.h
            test/sa_crypto_mac_compute.cpp
            test/sa_crypto_mac_init.cpp
            test/sa_crypto_mac_process.cpp
            test/sa_crypto_mac_process_key.cpp
            test/sa_crypto_mac_release.cpp
            test/sa_crypto_random.cpp
            test/sa_crypto_sign.cpp
            test/sa_crypto_sign_common.cpp
            test/sa_crypto_sign_common.h
            test/sa_crypto_sign_ec_ecdsa.cpp
            test/sa_crypto_sign_ec_eddsa.cpp
            test/sa_crypto_sign_rsa_pkcs1v15.cpp
            test/sa_crypto_sign_rsa_pss.cpp
            test/sa_engine_cipher.cpp
            test/sa_engine_common.cpp
            test/sa_engine_common.h
            test/sa_engine_pkcs7.cpp
            test/sa_engine_pkey_decrypt.cpp
            test/sa_engine_pkey_derive.cpp
            test/sa_engine_pkey_mac.cpp
            test/sa_engine_pkey_sign.cpp
            test/sa_get_device_id.cpp
            test/sa_get_name.cpp
            test/sa_get_ta_uuid.cpp
            test/sa_get_version.cpp
            test/sa_key_common.cpp
            test/sa_key_common.h
            test/sa_key_derive.cpp
            test/sa_key_derive_ansi_x963.cpp
            test/sa_key_derive_cmac.cpp
            test/sa_key_derive_common.cpp
            test/sa_key_derive_common.h
            test/sa_key_derive_concat.cpp
            test/sa_key_derive_hkdf.cpp
            test/sa_key_derive_netflix.cpp
            test/sa_key_derive_common_root_key_ladder.cpp
            test/sa_key_derive_root_key_ladder.cpp
            test/sa_key_digest.cpp
            test/sa_key_exchange.cpp
            test/sa_key_exchange_common.cpp
            test/sa_key_exchange_common.h
            test/sa_key_exchange_dh.cpp
            test/sa_key_exchange_ecdh.cpp
            test/sa_key_exchange_netflix.cpp
            test/sa_key_export.cpp
            test/sa_key_provision_widevine.cpp
            test/sa_key_provision_playready.cpp
            test/sa_key_provision_netflix.cpp
            test/sa_key_generate.cpp
            test/sa_key_generate_dh.cpp
            test/sa_key_generate_ec.cpp
            test/sa_key_generate_rsa.cpp
            test/sa_key_generate_symmetric.cpp
            test/sa_key_get_public.cpp
            test/sa_key_get_public_dh.cpp
            test/sa_key_get_public_ec.cpp
            test/sa_key_get_public_rsa.cpp
            test/sa_key_get_public_symmetric.cpp
            test/sa_key_header.cpp
            test/sa_key_import.cpp
            test/sa_key_import_common.cpp
            test/sa_key_import_common.h
            test/sa_key_import_ec_private_bytes.cpp
            test/sa_key_import_exported.cpp
            test/sa_key_import_rsa_private_key_info.cpp
            test/sa_key_import_soc.cpp
            test/sa_key_import_symmetric_bytes.cpp
            test/sa_key_import_typej.cpp
            test/sa_key_release.cpp
            test/sa_key_unwrap.cpp
            test/sa_key_unwrap_common.cpp
            test/sa_key_unwrap_common.h
            test/sa_key_unwrap_aes_cbc.cpp
            test/sa_key_unwrap_aes_ctr.cpp
            test/sa_key_unwrap_aes_ecb.cpp
            test/sa_key_unwrap_aes_gcm.cpp
            test/sa_key_unwrap_chacha20.cpp
            test/sa_key_unwrap_chacha20_poly1305.cpp
            test/sa_key_unwrap_ec.cpp
            test/sa_key_unwrap_rsa.cpp
            test/sa_crypto_cipher_multiple_thread.cpp
            test/sa_provider_asym_cipher.cpp
            test/sa_process_common_encryption.cpp
            test/sa_process_common_encryption.h
            test/sa_provider_cipher.cpp
            test/sa_provider_common.cpp
            test/sa_provider_common.h
            test/sa_provider_kdf.cpp
            test/sa_provider_keyexch.cpp
            test/sa_provider_mac.cpp
            test/sa_provider_pkcs7.cpp
            test/sa_provider_signature.cpp
            )
    # Conditionally add files if DISABLE_SVP is NOT defined
    if(NOT DISABLE_SVP)
         list(APPEND SACLIENT_TEST_SOURCES
	    test/sa_client_thread_test.cpp
	    test/sa_svp_buffer_alloc.cpp
	    test/sa_svp_buffer_check.cpp
	    test/sa_svp_buffer_copy.cpp
	    test/sa_svp_buffer_create.cpp
	    test/sa_svp_buffer_release.cpp
	    test/sa_svp_buffer_write.cpp
	    test/sa_svp_key_check.cpp
	    test/sa_svp_common.cpp
	    test/sa_svp_common.h
            )
    endif()


    add_executable(saclienttest ${SACLIENT_TEST_SOURCES})

    target_compile_options(saclienttest PRIVATE -Werror -Wall -Wextra -Wno-type-limits -Wno-unused-parameter
            -Wno-deprecated-declarations)

    target_include_directories(saclienttest
            PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
            ${OPENSSL_INCLUDE_DIR}
            )

    if (CMAKE_CXX_COMPILER_ID MATCHES ".*Clang")
        # using Clang
        target_include_directories(saclienttest
                PRIVATE
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>
                )
    endif ()

    target_link_libraries(saclienttest
            PRIVATE
            gtest_main
            gmock_main
            saclient
            util
            ${OPENSSL_CRYPTO_LIBRARY}
            )

    if (COVERAGE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_libraries(saclienttest
                PRIVATE
                gcov
                )
    endif ()

    target_clangformat_setup(saclienttest)

    add_custom_command(
            TARGET saclienttest POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/test/root_keystore.p12
            ${CMAKE_CURRENT_BINARY_DIR}/root_keystore.p12)

    gtest_discover_tests(saclienttest)
endif ()

# Doxygen
if (BUILD_DOC)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        add_custom_target(saclientdocs ALL
                COMMAND "${CMAKE_SOURCE_DIR}/../docs/generate_docs.sh"
                WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/../docs/
                COMMENT "Generating API documentation with Doxygen"
                VERBATIM
                )
    else (DOXYGEN_FOUND)
        message("Doxygen need to be installed to generate the doxygen documentation")
    endif (DOXYGEN_FOUND)
endif (BUILD_DOC)
