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

sa_status sa_svp_key_check(
        sa_key key,
        sa_buffer* in,
        size_t bytes_to_process,
        const void* expected,
        size_t expected_length) {

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (expected == NULL) {
        ERROR("NULL expected");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_svp_key_check_s* svp_key_check = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_svp_key_check_s, svp_key_check);
        svp_key_check->api_version = API_VERSION;
        svp_key_check->key = key;
        svp_key_check->in_buffer_type = in->buffer_type;
        svp_key_check->bytes_to_process = bytes_to_process;

        size_t param1_size = 0;
        uint32_t param1_type = 0;
        if (in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
            if (in->context.clear.buffer == NULL) {
                ERROR("NULL in.context.clear.buffer");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            svp_key_check->in_offset = in->context.clear.offset;
            CREATE_PARAM(param1, in->context.clear.buffer, in->context.clear.length);
            param1_size = in->context.clear.length;
            param1_type = TA_PARAM_IN;
        } else {
            svp_key_check->in_offset = in->context.svp.offset;
            CREATE_PARAM(param1, &in->context.svp.buffer, sizeof(sa_svp_buffer));
            param1_size = sizeof(sa_svp_buffer);
            param1_type = TA_PARAM_IN;
        }

        CREATE_PARAM(param2, (void*) expected, expected_length);
        size_t param2_size = expected_length;
        uint32_t param2_type = TA_PARAM_IN;

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{svp_key_check, sizeof(sa_svp_key_check_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_SVP_KEY_CHECK, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        if (in->buffer_type == SA_BUFFER_TYPE_CLEAR)
            in->context.clear.offset = svp_key_check->in_offset;
        else {
            in->context.svp.offset = svp_key_check->in_offset;
	}
    } while (false);

    RELEASE_COMMAND(svp_key_check);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    return status;
}
#endif // DISABLE_SVP
