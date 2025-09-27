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

sa_status sa_svp_buffer_check(
        sa_svp_buffer svp_buffer,
        size_t offset,
        size_t length,
        sa_digest_algorithm digest_algorithm,
        const void* hash,
        size_t hash_length) {

    if (hash == NULL) {
        ERROR("hash failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_svp_buffer_check_s* svp_buffer_check = NULL;
    void* param1 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_svp_buffer_check_s, svp_buffer_check);
        svp_buffer_check->api_version = API_VERSION;
        svp_buffer_check->svp_buffer = svp_buffer;
        svp_buffer_check->offset = offset;
        svp_buffer_check->length = length;
        svp_buffer_check->digest_algorithm = digest_algorithm;

        CREATE_PARAM(param1, (void*) hash, hash_length);
        size_t param1_size = hash_length;
        uint32_t param1_type = TA_PARAM_IN;

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_IN, param1_type, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{svp_buffer_check, sizeof(sa_svp_buffer_check_s)},
                                          {param1, param1_size},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_SVP_BUFFER_CHECK, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
    } while (false);

    RELEASE_COMMAND(svp_buffer_check);
    RELEASE_PARAM(param1);
    return status;
}
#endif // DISABLE_SVP
