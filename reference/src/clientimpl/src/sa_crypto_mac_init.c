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

sa_status sa_crypto_mac_init(
        sa_crypto_mac_context* context,
        sa_mac_algorithm mac_algorithm,
        sa_key key,
        void* parameters) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_crypto_mac_init_s* mac_init = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_crypto_mac_init_s, mac_init);
        if (mac_init == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        mac_init->api_version = API_VERSION;
        mac_init->context = *context;
        mac_init->mac_algorithm = mac_algorithm;
        mac_init->key = key;

        if (mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
            if (parameters == NULL) {
                ERROR("NULL parameters");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            sa_mac_parameters_hmac* mac_parameters_hmac = (sa_mac_parameters_hmac*) parameters;
            mac_init->digest_algorithm = mac_parameters_hmac->digest_algorithm;
        } else {
            mac_init->digest_algorithm = 0;
        }

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, TA_PARAM_NULL, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{mac_init, sizeof(sa_crypto_mac_init_s)},
                                          {NULL, 0},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_CRYPTO_MAC_INIT, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *context = mac_init->context;
    } while (false);

    RELEASE_COMMAND(mac_init);
    return status;
}
