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
#include "sa.h"
#include "sa_log.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_key_digest(
        void* out,
        size_t* out_length,
        sa_key key,
        sa_digest_algorithm digest_algorithm) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_key_digest_s* key_digest = NULL;
    void* param1 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_digest_s, key_digest);
        if (key_digest == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        key_digest->api_version = API_VERSION;
        key_digest->out_length = *out_length;
        key_digest->key = key;
        key_digest->digest_algorithm = digest_algorithm;

        size_t param1_size;
        ta_param_type param1_type;
        if (out != NULL) {
            CREATE_OUT_PARAM(param1, out, *out_length);
            if (param1 == NULL) {
                ERROR("CREATE_OUT_PARAM failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }

            param1_size = *out_length;
            param1_type = TA_PARAM_OUT;
        } else {
            param1_size = 0;
            param1_type = TA_PARAM_NULL;
        }

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{key_digest, sizeof(sa_key_digest_s)},
                                          {param1, param1_size},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_DIGEST, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *out_length = key_digest->out_length;
        if (out != NULL)
            COPY_OUT_PARAM(out, param1, key_digest->out_length);
    } while (false);

    RELEASE_COMMAND(key_digest);
    RELEASE_PARAM(param1);
    return status;
}
