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

#include "cipher_store.h"
#include "client_store.h"
#include "common.h"
#include "log.h"
#include "ta_sa.h"

sa_status ta_sa_crypto_cipher_update_iv(
        sa_crypto_cipher_context context,
        const void* iv,
        size_t iv_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    cipher_store_t* cipher_store = NULL;
    cipher_t* cipher = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        cipher_store = client_get_cipher_store(client);
        status = cipher_store_acquire_exclusive(&cipher, cipher_store, context, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_acquire_exclusive failed");
            break;
        }

        sa_cipher_algorithm cipher_algorithm = cipher_get_algorithm(cipher);

        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC || cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
            if (iv_length != AES_BLOCK_SIZE) {
                ERROR("Invalid iv_length");
                status = SA_STATUS_INVALID_PARAMETER;
                break;
            }

            const symmetric_context_t* symmetric_context = cipher_get_symmetric_context(cipher);
            if (symmetric_context == NULL) {
                ERROR("cipher_get_symmetric_context failed");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            status = symmetric_context_set_iv((symmetric_context_t*)symmetric_context, iv, iv_length);
            if (status != SA_STATUS_OK) {
                ERROR("symmetric_context_set_iv failed");
                break;
            }
        } else {
            status = SA_STATUS_INVALID_PARAMETER;
            ERROR("Invalid algorithm");
            break;
        }
    } while (false);

    if (cipher != NULL)
        cipher_store_release_exclusive(cipher_store, context, cipher, caller_uuid);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
