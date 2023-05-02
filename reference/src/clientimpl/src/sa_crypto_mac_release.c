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

sa_status sa_crypto_mac_release(sa_crypto_mac_context context) {

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_crypto_mac_release_s* mac_release = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_crypto_mac_release_s, mac_release);
        mac_release->api_version = API_VERSION;
        mac_release->context = context;

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_IN, TA_PARAM_NULL, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{mac_release, sizeof(sa_crypto_mac_release_s)},
                                          {NULL, 0},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_CRYPTO_MAC_RELEASE, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
    } while (false);

    RELEASE_COMMAND(mac_release);
    return status;
}
