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

sa_status sa_key_exchange(
        sa_key* key,
        const sa_rights* rights,
        sa_key_exchange_algorithm key_exchange_algorithm,
        sa_key private_key,
        const void* other_public,
        size_t other_public_length,
        void* parameters) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (other_public == NULL) {
        ERROR("NULL other_public");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_key_exchange_s* key_exchange = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_exchange_s, key_exchange);
        if (key_exchange == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        key_exchange->api_version = API_VERSION;
        key_exchange->key = *key;
        key_exchange->rights = *rights;
        key_exchange->key_exchange_algorithm = key_exchange_algorithm;
        key_exchange->private_key = private_key;

        CREATE_PARAM(param1, (void*) other_public, other_public_length);
        if (param1 == NULL) {
            ERROR("CREATE_PARAM failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        size_t param1_size = other_public_length;
        ta_param_type param1_type = TA_PARAM_IN;

        size_t param2_size;
        ta_param_type param2_type;
        sa_key_exchange_parameters_netflix_authenticated_dh* netflix_authenticated_dh;
        sa_key_exchange_parameters_netflix_authenticated_dh_s* netflix_authenticated_dh_s;
        if (key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH) {
            if (parameters == NULL) {
                ERROR("NULL parameters");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            netflix_authenticated_dh = (sa_key_exchange_parameters_netflix_authenticated_dh*) parameters;
            if (netflix_authenticated_dh->out_ke == NULL) {
                ERROR("NULL out_ke");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            if (netflix_authenticated_dh->rights_ke == NULL) {
                ERROR("NULL rights_ke");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            if (netflix_authenticated_dh->out_kh == NULL) {
                ERROR("NULL out_kh");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            if (netflix_authenticated_dh->rights_kh == NULL) {
                ERROR("NULL rights_kh");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            CREATE_COMMAND(sa_key_exchange_parameters_netflix_authenticated_dh_s, param2);
            if (param2 == NULL) {
                ERROR("CREATE_COMMAND failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }

            netflix_authenticated_dh_s = (sa_key_exchange_parameters_netflix_authenticated_dh_s*) param2;
            netflix_authenticated_dh_s->in_kw = netflix_authenticated_dh->in_kw;
            netflix_authenticated_dh_s->out_ke = *netflix_authenticated_dh->out_ke;
            netflix_authenticated_dh_s->rights_ke = *netflix_authenticated_dh->rights_ke;
            netflix_authenticated_dh_s->out_kh = *netflix_authenticated_dh->out_kh;
            netflix_authenticated_dh_s->rights_kh = *netflix_authenticated_dh->rights_kh;
            param2_size = sizeof(sa_key_exchange_parameters_netflix_authenticated_dh_s);
            param2_type = TA_PARAM_INOUT;
        } else {
            netflix_authenticated_dh = NULL;
            netflix_authenticated_dh_s = NULL;
            param2_size = 0;
            param2_type = TA_PARAM_NULL;
        }

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{key_exchange, sizeof(sa_key_exchange_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_EXCHANGE, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *key = key_exchange->key;
        if (key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH) {
            *netflix_authenticated_dh->out_ke = netflix_authenticated_dh_s->out_ke;
            *netflix_authenticated_dh->out_kh = netflix_authenticated_dh_s->out_kh;
        }
    } while (false);

    RELEASE_COMMAND(key_exchange);
    RELEASE_PARAM(param1);
    RELEASE_COMMAND(param2);
    return status;
}
