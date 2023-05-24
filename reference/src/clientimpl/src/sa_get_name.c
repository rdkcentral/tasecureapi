/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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

#include "client.h"
#include "log.h"
#include "sa.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_get_name(
        char* name,
        size_t* name_length) {

    if (name_length == NULL) {
        ERROR("NULL name_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_get_name_s* get_name = NULL;
    void* param1 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_get_name_s, get_name);
        get_name->api_version = API_VERSION;
        get_name->name_length = *name_length;

        size_t param1_size = 0;
        uint32_t param1_type = TA_PARAM_NULL;
        if (name != NULL) {
            CREATE_OUT_PARAM(param1, name, *name_length);
            param1_type = TA_PARAM_OUT;
            param1_size = *name_length;
        }

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{get_name, sizeof(sa_get_name_s)},
                                          {param1, param1_size},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_GET_NAME, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *name_length = get_name->name_length;
        if (name != NULL)
            COPY_OUT_PARAM(name, param1, get_name->name_length);
    } while (false);

    RELEASE_COMMAND(get_name);
    RELEASE_PARAM(param1);
    return status;
}
