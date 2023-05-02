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

sa_status sa_key_export(
        void* out,
        size_t* out_length,
        const void* mixin,
        size_t mixin_length,
        sa_key key) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out == NULL && *out_length > 0) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mixin == NULL && mixin_length > 0) {
        ERROR("NULL mixin");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_key_export_s* key_export = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_export_s, key_export);
        key_export->api_version = API_VERSION;
        key_export->out_length = *out_length;
        key_export->key = key;

        size_t param1_size;
        ta_param_type param1_type;
        if (out != NULL) {
            CREATE_OUT_PARAM(param1, out, *out_length);
            param1_size = *out_length;
            param1_type = TA_PARAM_OUT;
        } else {
            param1_size = 0;
            param1_type = TA_PARAM_NULL;
        }

        size_t param2_size;
        ta_param_type param2_type;
        if (mixin != NULL) {
            CREATE_PARAM(param2, (void*) mixin, mixin_length);
            param2_size = mixin_length;
            param2_type = TA_PARAM_IN;
        } else {
            param2_size = mixin_length;
            param2_type = TA_PARAM_NULL;
        }

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{key_export, sizeof(sa_key_export_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_EXPORT, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *out_length = key_export->out_length;
        if (out != NULL)
            COPY_OUT_PARAM(out, param1, key_export->out_length);
    } while (false);

    RELEASE_COMMAND(key_export);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    return status;
}
