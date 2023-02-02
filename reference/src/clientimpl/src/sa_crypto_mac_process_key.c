/**
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

sa_status sa_crypto_mac_process_key(
        sa_crypto_mac_context context,
        sa_key key) {

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_crypto_mac_process_key_s* mac_process_key = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_crypto_mac_process_key_s, mac_process_key);
        if (mac_process_key == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        mac_process_key->api_version = API_VERSION;
        mac_process_key->mac_context = context;
        mac_process_key->key = key;

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_IN, TA_PARAM_NULL, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{mac_process_key, sizeof(sa_crypto_mac_process_key_s)},
                                          {NULL, 0},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_CRYPTO_MAC_PROCESS_KEY, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
    } while (false);

    RELEASE_COMMAND(mac_process_key);
    return status;
}
