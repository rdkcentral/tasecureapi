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

project(tasecureapi-src)

set(CMAKE_CXX_STANDARD 11 CACHE STRING "C++ standard to be used")
set(CMAKE_C_STANDARD 11 CACHE STRING "C standard to be used")

set(CMAKE_CXX_FLAGS "-D_GNU_SOURCE -fPIC ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS "-D_GNU_SOURCE -fPIC ${CMAKE_C_FLAGS}")

if (COVERAGE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "-g -fprofile-arcs -ftest-coverage ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-g -fprofile-arcs -ftest-coverage ${CMAKE_C_FLAGS}")
endif ()

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/../cmake" ${CMAKE_MODULE_PATH})
message("CMAKE_MODULE_PATH=${CMAKE_MODULE_PATH}")
include(ClangFormat)

if (DEFINED ENABLE_SOC_KEY_TESTS)
    set(CMAKE_CXX_FLAGS "-DENABLE_SOC_KEY_TESTS ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-DENABLE_SOC_KEY_TESTS ${CMAKE_C_FLAGS}")
endif ()

if (DEFINED DISABLE_CENC_TIMING)
    set(CMAKE_CXX_FLAGS "-DDISABLE_CENC_TIMING ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-DDISABLE_CENC_TIMING ${CMAKE_C_FLAGS}")
endif ()

if (DISABLE_SVP)
    set(CMAKE_CXX_FLAGS "-DDISABLE_SVP ${CMAKE_CXX_FLAGS}")
    set(CMAKE_C_FLAGS "-DDISABLE_SVP ${CMAKE_C_FLAGS}")
endif ()

add_subdirectory(client)
add_subdirectory(clientimpl)
add_subdirectory(taimpl)
add_subdirectory(util)

# 'make install' to the correct locations (provided by GNUInstallDirs).
include(GNUInstallDirs)
install(TARGETS saclient EXPORT sa-client-config
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        RUNTIME DESTINATION bin
        )

install(DIRECTORY client/include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if (BUILD_TESTS)
    install(TARGETS saclienttest taimpltest utiltest
            ARCHIVE DESTINATION lib
            LIBRARY DESTINATION lib
            RUNTIME DESTINATION bin
            )
endif ()
