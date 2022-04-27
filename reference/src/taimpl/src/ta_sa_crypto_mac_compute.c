/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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
#include "common.h"
#include "digest.h"
#include "log.h"
#include "mac_store.h"
#include "ta_sa.h"

sa_status ta_sa_crypto_mac_compute(
        void* out,
        size_t* out_length,
        sa_crypto_mac_context context,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    mac_store_t* mac_store = NULL;
    mac_t* mac = NULL;
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

        sa_mac_algorithm mac_algorithm = mac_get_algorithm(mac);
        if (mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
            hmac_context_t* hmac_context = mac_get_hmac_context(mac);
            if (hmac_context == NULL) {
                ERROR("NULL hmac_context");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }

            sa_digest_algorithm digest_algorithm = hmac_context_get_digest(hmac_context);
            size_t required_length = digest_length(digest_algorithm);
            if (out == NULL) {
                *out_length = required_length;
                status = SA_STATUS_OK;
                break;
            }

            if (hmac_context_done(hmac_context)) {
                ERROR("hmac_context_done failed");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }

            if (*out_length < required_length) {
                ERROR("Bad out_length");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }
            *out_length = required_length;

            if (!hmac_context_compute(out, out_length, hmac_context)) {
                ERROR("hmac_context_compute failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else if (mac_algorithm == SA_MAC_ALGORITHM_CMAC) {
            if (out == NULL) {
                *out_length = AES_BLOCK_SIZE;
                status = SA_STATUS_OK;
                break;
            }

            cmac_context_t* cmac_context = mac_get_cmac_context(mac);
            if (cmac_context_done(cmac_context)) {
                ERROR("cmac_context_done failed");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }

            if (*out_length < AES_BLOCK_SIZE) {
                ERROR("Bad out_length");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }
            *out_length = AES_BLOCK_SIZE;

            if (!cmac_context_compute(out, cmac_context)) {
                ERROR("cmac_context_compute failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
        } else {
            ERROR("Bad mac context");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (mac)
        mac_store_release_exclusive(mac_store, context, mac, caller_uuid);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
