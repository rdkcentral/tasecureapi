/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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

sa_status sa_svp_buffer_copy(
        sa_svp_buffer out,
        size_t* out_offset,
        const sa_svp_buffer in,
        size_t* in_offset,
        size_t in_length) {

    if (out_offset == NULL) {
        ERROR("NULL out_offset");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_offset == NULL) {
        ERROR("NULL in_offset");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_svp_buffer_copy_s* svp_buffer_copy = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_svp_buffer_copy_s, svp_buffer_copy);
        if (svp_buffer_copy == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        svp_buffer_copy->api_version = API_VERSION;
        svp_buffer_copy->out_svp_buffer = out;
        svp_buffer_copy->out_offset = *out_offset;
        svp_buffer_copy->in_svp_buffer = in;
        svp_buffer_copy->in_offset = *in_offset;
        svp_buffer_copy->in_length = in_length;

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, TA_PARAM_NULL, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{svp_buffer_copy, sizeof(sa_svp_buffer_copy_s)},
                                          {NULL, 0},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_SVP_BUFFER_COPY, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *out_offset = svp_buffer_copy->out_offset;
        *in_offset = svp_buffer_copy->in_offset;
    } while (false);

    RELEASE_COMMAND(svp_buffer_copy);
    return status;
}
