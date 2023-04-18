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

#include "client_store.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "mac_store.h"
#include "rights.h"
#include "ta_sa.h"

static sa_status ta_sa_crypto_mac_init_hmac(
        sa_crypto_mac_context* context,
        sa_key key,
        sa_mac_parameters_hmac* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key = NULL;
    hmac_context_t* hmac_context = NULL;
    do {
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

        if (!rights_allowed_sign(&header->rights)) {
            ERROR("rights_allowed_sign failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_hmac(header->type, header->size)) {
            ERROR("key_type_supports_hmac failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        if (parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
                parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
                parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
                parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
            ERROR("Invalid digest algorithm");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        hmac_context = hmac_context_create(parameters->digest_algorithm, stored_key);
        if (hmac_context == NULL) {
            ERROR("hmac_context_create failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        mac_store_t* mac_store = client_get_mac_store(client);
        status = mac_store_add_hmac_context(context, mac_store, hmac_context, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("mac_store_add_hmac_context failed");
            break;
        }

        // hmac_context is now owned by mac store
        hmac_context = NULL;
    } while (false);

    stored_key_free(stored_key);
    hmac_context_free(hmac_context);

    return status;
}

static sa_status ta_sa_crypto_mac_init_cmac(
        sa_crypto_mac_context* context,
        sa_key key,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }
    *context = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key = NULL;
    cmac_context_t* cmac_context = NULL;
    do {
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

        if (!rights_allowed_sign(&header->rights)) {
            ERROR("rights_allowed_sign failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_aes(header->type, header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        cmac_context = cmac_context_create(stored_key);
        if (cmac_context == NULL) {
            ERROR("cmac_context_create failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        mac_store_t* mac_store = client_get_mac_store(client);
        status = mac_store_add_cmac_context(context, mac_store, cmac_context, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("mac_store_add_cmac_context failed");
            break;
        }

        // cmac_context is now owned by mac store
        cmac_context = NULL;
    } while (false);

    stored_key_free(stored_key);
    cmac_context_free(cmac_context);

    return status;
}

sa_status ta_sa_crypto_mac_init(
        sa_crypto_mac_context* context,
        sa_mac_algorithm mac_algorithm,
        sa_key key,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        if (mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
            status = ta_sa_crypto_mac_init_hmac(context, key, (sa_mac_parameters_hmac*) parameters, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_mac_init_hmac failed");
                break;
            }
        } else if (mac_algorithm == SA_MAC_ALGORITHM_CMAC) {
            status = ta_sa_crypto_mac_init_cmac(context, key, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_crypto_mac_init_hmac failed");
                break;
            }
        } else {
            ERROR("Unknown algorithm encountered");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }
    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
