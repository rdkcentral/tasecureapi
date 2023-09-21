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

sa_status sa_svp_copy(
        void* out,
        void* in,
        sa_svp_offset* offsets,
        size_t offsets_length) {

    if (offsets == NULL) {
        ERROR("NULL offsets");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_svp_copy_s* svp_copy = NULL;
    sa_svp_offset_s* offset_s = NULL;
    sa_status status;
    void* param1 = NULL;
    void* param2 = NULL;
    void* param3 = NULL;
    size_t param1_size;
    size_t param2_size;
    size_t param3_size;
    do {
        CREATE_COMMAND(sa_svp_copy_s, svp_copy);
        svp_copy->api_version = SVP_API_VERSION;

        param1_size = offsets_length * sizeof(sa_svp_offset_s);
        offset_s = malloc(param1_size);
        if (offset_s == NULL) {
            ERROR("malloc failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        for (size_t i = 0; i < offsets_length; i++) {
            offset_s[i].out_offset = offsets[i].out_offset;
            offset_s[i].in_offset = offsets[i].in_offset;
            offset_s[i].length = offsets[i].length;
        }

        CREATE_PARAM(param1, offset_s, param1_size);

        param2 = out;
        param2_size = sizeof(void*);
        param3 = in;
        param3_size = sizeof(void*);

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, TA_PARAM_IN, TA_PARAM_OUT, TA_PARAM_IN};
        ta_param params[NUM_TA_PARAMS] = {{svp_copy, sizeof(sa_svp_copy_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {param3, param3_size}};
        // clang-format on
        status = ta_invoke_command(session, SA_SVP_COPY, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
    } while (false);

    if (offset_s != NULL)
        free(offset_s);

    RELEASE_COMMAND(svp_copy);
    RELEASE_PARAM(param1);
    return status;
}
