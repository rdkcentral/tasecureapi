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

sa_status sa_key_generate(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* parameters) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_key_generate_s* key_generate = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_generate_s, key_generate);
        key_generate->api_version = API_VERSION;
        key_generate->key = *key;
        key_generate->rights = *rights;
        key_generate->key_type = key_type;

        size_t param1_length = 0;
        uint32_t param1_type = TA_PARAM_NULL;
        size_t param2_length = 0;
        uint32_t param2_type = TA_PARAM_NULL;
        switch (key_type) {
            case SA_KEY_TYPE_SYMMETRIC:
                key_generate->key_length = ((sa_generate_parameters_symmetric*) parameters)->key_length;
                break;

            case SA_KEY_TYPE_RSA:
                key_generate->key_length = ((sa_generate_parameters_rsa*) parameters)->modulus_length;
                break;

            case SA_KEY_TYPE_EC:
                key_generate->key_length = ((sa_generate_parameters_ec*) parameters)->curve;
                break;

            case SA_KEY_TYPE_DH: {
                sa_generate_parameters_dh* parameters_dh = (sa_generate_parameters_dh*) parameters;
                if (parameters_dh->p == NULL || parameters_dh->g == NULL) {
                    ERROR("NULL p or g");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param1, (void*) parameters_dh->p, parameters_dh->p_length);
                param1_length = parameters_dh->p_length;
                param1_type = TA_PARAM_IN;

                CREATE_PARAM(param2, (void*) parameters_dh->g, parameters_dh->g_length);
                param2_length = parameters_dh->g_length;
                param2_type = TA_PARAM_IN;
                key_generate->key_length = 0;
                break;
            }
            default:
                status = SA_STATUS_INVALID_PARAMETER;
                continue; // NOLINT
        }

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{key_generate, sizeof(sa_key_generate_s)},
                                          {param1, param1_length},
                                          {param2, param2_length},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_GENERATE, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *key = key_generate->key;
    } while (false);

    RELEASE_COMMAND(key_generate);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    return status;
}
