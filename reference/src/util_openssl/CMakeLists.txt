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

project(util_openssl)

find_package(OpenSSL REQUIRED)

set(HEADERS
        "${CMAKE_CURRENT_SOURCE_DIR}/include/common.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/pkcs12.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/pkcs8.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/digest_mechanism.h")

set(UTIL_OPENSSL_SOURCES
        src/pkcs12.c
        src/pkcs8.c
        src/digest_mechanism.c
        src/test_helpers.cpp
        src/test_process_common_encryption.cpp
        )

add_library(util_openssl STATIC
        ${UTIL_OPENSSL_HEADERS}
        ${UTIL_OPENSSL_SOURCES}
        )

target_include_directories(util_openssl
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
        ${OPENSSL_INCLUDE_DIR}
        )

target_link_libraries(util_openssl
        PUBLIC
        ${OPENSSL_CRYPTO_LIBRARY}
        util
        )

target_compile_options(util_openssl PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

target_clangformat_setup(util_openssl)

if (BUILD_TESTS)
    # Google test
    add_executable(util_openssl_test
            test/pkcs12test_openssl.cpp
            )

    target_include_directories(util_openssl_test
            PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            ${OPENSSL_INCLUDE_DIR}
            )

    target_compile_options(util_openssl_test PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

    target_link_libraries(util_openssl_test
            PRIVATE
            gmock_main
            util_openssl
            ${OPENSSL_CRYPTO_LIBRARY}
            )

    target_clangformat_setup(util_openssl_test)

    add_custom_command(
            TARGET util_openssl_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/test/root_keystore.p12
            ${CMAKE_CURRENT_BINARY_DIR}/root_keystore.p12)

    gtest_discover_tests(util_openssl_test)
endif ()
