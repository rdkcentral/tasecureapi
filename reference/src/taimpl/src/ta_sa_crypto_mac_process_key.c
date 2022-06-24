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

#include "client_store.h"
#include "log.h"
#include "mac_store.h"
#include "ta_sa.h"
#include <rights.h>

sa_status ta_sa_crypto_mac_process_key(
        sa_crypto_mac_context context,
        sa_key key,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    mac_store_t* mac_store = NULL;
    mac_t* mac = NULL;
    stored_key_t* stored_key = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        mac_store = client_get_mac_store(client);
        status = mac_store_acquire_exclusive(&mac, mac_store, context, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("mac_store_acquire_exclusive failed");
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key, key_store, key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("key type is not symmetric");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        sa_mac_algorithm mac_algorithm = mac_get_algorithm(mac);
        if (mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
            hmac_context_t* hmac_context = mac_get_hmac_context(mac);
            if (hmac_context_done(hmac_context)) {
                ERROR("hmac_context_done failed");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            if (!hmac_context_update_key(hmac_context, stored_key)) {
                ERROR("hmac_context_update_key failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (mac_algorithm == SA_MAC_ALGORITHM_CMAC) {
            cmac_context_t* cmac_context = mac_get_cmac_context(mac);
            if (cmac_context_done(cmac_context)) {
                ERROR("cmac_context_done failed");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }
            if (!cmac_context_update_key(cmac_context, stored_key)) {
                ERROR("cmac_context_update_key failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Invalid mac context");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (mac != NULL)
        mac_store_release_exclusive(mac_store, context, mac, caller_uuid);

    stored_key_free(stored_key);
    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
