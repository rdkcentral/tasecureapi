#
# Copyright 2020-2021 Comcast Cable Communications Management, LLC
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
# Find libyajl

FIND_PATH(YAJL_INCLUDE_DIR yajl/yajl_common.h)

SET(YAJL_NAMES ${YAJL_NAMES} yajl libyajl)
FIND_LIBRARY(YAJL_LIBRARY NAMES ${YAJL_NAMES} PATH)

IF(YAJL_INCLUDE_DIR AND YAJL_LIBRARY)
    SET(YAJL_FOUND TRUE)
ENDIF(YAJL_INCLUDE_DIR AND YAJL_LIBRARY)

IF(YAJL_FOUND)
    IF(NOT Yajl_FIND_QUIETLY)
        MESSAGE(STATUS "Found Yajl: ${YAJL_LIBRARY}")
    ENDIF (NOT Yajl_FIND_QUIETLY)
ELSE(YAJL_FOUND)
    IF(Yajl_FIND_REQUIRED)
        MESSAGE(FATAL_ERROR "Could not find yajl")
    ENDIF(Yajl_FIND_REQUIRED)
ENDIF(YAJL_FOUND)
