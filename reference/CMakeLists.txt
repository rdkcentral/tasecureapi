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
option(DISABLE_SVP  "Build SecAPI without SVP" OFF)

if(DISABLE_SVP)
    message(STATUS "DISABLE_SVP is ENABLED: Building SecAPI without SVP functionality")
else()
    message(STATUS "DISABLE_SVP is DISABLED: Building SecAPI with SVP functionality")
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

add_subdirectory(src)
