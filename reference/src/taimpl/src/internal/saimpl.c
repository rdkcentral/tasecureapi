/**
 * Copyright 2019-2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "saimpl.h" // NOLINT
#include "sa.h"

#define SA_IMPLEMENTATION_NAME "Reference"
#define SA_IMPLEMENTATION_REVISION 0

static const sa_version version = {
        SA_SPECIFICATION_MAJOR,
        SA_SPECIFICATION_MINOR,
        SA_SPECIFICATION_REVISION,
        SA_IMPLEMENTATION_REVISION};

const char* get_implementation_name() {
    return SA_IMPLEMENTATION_NAME;
}

const sa_version* get_implementation_version() {
    return &version;
}
