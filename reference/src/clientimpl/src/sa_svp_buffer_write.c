/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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
#ifndef DISABLE_SVP
#include "client.h"
#include "log.h"
#include "sa.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_svp_buffer_write(
        sa_svp_buffer out,
        const void* in,
        size_t in_length,
        sa_svp_offset* offsets,
        size_t offsets_length) {

    if (in == NULL || in_length == 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (offsets == NULL) {
        ERROR("NULL offsets");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_svp_buffer_write_s* svp_buffer_write = NULL;
    sa_svp_offset_s* offset_s = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    size_t param1_size = in_length;
    size_t param2_size;
    sa_status status;
    do {
        CREATE_COMMAND(sa_svp_buffer_write_s, svp_buffer_write);
        svp_buffer_write->api_version = API_VERSION;
        svp_buffer_write->out = out;
        CREATE_PARAM(param1, (void*) in, in_length);

        param2_size = offsets_length * sizeof(sa_svp_offset_s);
        offset_s = malloc(param2_size);
        if (offset_s == NULL) {
            ERROR("malloc failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        for (size_t i = 0; i < offsets_length; i++) {
            offset_s[i].out_offset = offsets->out_offset;
            offset_s[i].in_offset = offsets->in_offset;
            offset_s[i].length = offsets->length;
        }

        CREATE_PARAM(param2, offset_s, param2_size);

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, TA_PARAM_IN, TA_PARAM_IN, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{svp_buffer_write, sizeof(sa_svp_buffer_write_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_SVP_BUFFER_WRITE, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
    } while (false);

    if (offset_s != NULL)
        free(offset_s);

    RELEASE_COMMAND(svp_buffer_write);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    return status;
}
#endif // DISABLE_SVP
