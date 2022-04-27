/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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

#include "log.h"
#include "saimpl.h"
#include "ta_sa.h"
#include <string.h>

sa_status ta_sa_get_name(
        char* name,
        size_t* name_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (name_length == NULL) {
        ERROR("NULL name_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    const char* implementation_name = get_implementation_name();
    const size_t required_length = strlen(implementation_name) + 1;
    if (name == NULL) {
        *name_length = required_length;
        return SA_STATUS_OK;
    }

    if (*name_length < required_length) {
        ERROR("Bad name_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    memcpy(name, implementation_name, required_length);

    return SA_STATUS_OK;
}
