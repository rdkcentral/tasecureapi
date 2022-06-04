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

sa_status sa_svp_buffer_write(
        sa_svp_buffer svp_buffer,
        size_t* offset,
        const void* in,
        size_t in_length) {

    if (offset == NULL) {
        ERROR("NULL offset");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_svp_buffer_write_s* svp_buffer_write = NULL;
    void* param1 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_svp_buffer_write_s, svp_buffer_write);
        if (svp_buffer_write == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        svp_buffer_write->api_version = API_VERSION;
        svp_buffer_write->svp_buffer = svp_buffer;
        svp_buffer_write->offset = *offset;

        size_t param1_size;
        ta_param_type param1_type;
        if (in != NULL) {
            CREATE_PARAM(param1, (void*) in, in_length);
            if (param1 == NULL) {
                ERROR("CREATE_PARAM failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }

            param1_size = in_length;
            param1_type = TA_PARAM_IN;
        } else {
            param1_size = 0;
            param1_type = TA_PARAM_NULL;
        }

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{svp_buffer_write, sizeof(sa_svp_buffer_write_s)},
                                          {param1, param1_size},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_SVP_BUFFER_WRITE, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *offset = svp_buffer_write->offset;
    } while (false);

    RELEASE_COMMAND(svp_buffer_write);
    RELEASE_PARAM(param1);
    return status;
}
