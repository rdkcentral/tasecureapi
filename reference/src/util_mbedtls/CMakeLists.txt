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

project(util_mbedtls)

set(UTIL_MBEDTLS_HEADERS
        include/common.h
        include/digest_util_mbedtls.h
        include/hardware_rng.h
        include/pkcs12_mbedtls.h
        include/pkcs8.h
        include/test_process_common_encryption_mbedtls.h
        )

set(UTIL_MBEDTLS_SOURCES
        src/digest_util_mbedtls.c
        src/hardware_rng.c
        src/pkcs12_mbedtls.c
        src/pkcs8.c
        src/test_helpers.cpp
        src/test_process_common_encryption.cpp
        )

add_library(util_mbedtls STATIC
        ${UTIL_MBEDTLS_HEADERS}
        ${UTIL_MBEDTLS_SOURCES}
        )

target_include_directories(util_mbedtls
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../util/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../client/include>
        ${MBEDTLS_INCLUDE_DIR}
        )

target_link_libraries(util_mbedtls
        PUBLIC
        ${MBEDTLS_LIBRARIES}
        util
        )

target_compile_options(util_mbedtls PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

target_clangformat_setup(util_mbedtls)

if (BUILD_TESTS)
    # Google test
    add_executable(util_mbedtls_test
            test/hardware_rng_test.cpp
            test/pkcs12test_mbedtls.cpp
            )

    target_include_directories(util_mbedtls_test
            PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            ${MBEDTLS_INCLUDE_DIR}
            )

    target_compile_options(util_mbedtls_test PRIVATE -Werror -Wall -Wextra -Wno-unused-parameter)

    target_link_libraries(util_mbedtls_test
            PRIVATE
            gmock_main
            util_mbedtls
            ${MBEDTLS_LIBRARIES}
            )

    target_clangformat_setup(util_mbedtls_test)

    add_custom_command(
            TARGET util_mbedtls_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/test/root_keystore.p12
            ${CMAKE_CURRENT_BINARY_DIR}/root_keystore.p12)

    gtest_discover_tests(util_mbedtls_test)
endif ()
