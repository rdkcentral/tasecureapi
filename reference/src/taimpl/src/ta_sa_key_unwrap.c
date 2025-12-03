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
#include "common.h"
#include "ec.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "rights.h"
#include "ta_sa.h"
#include "unwrap.h"

static sa_status ta_sa_key_unwrap_aes_ecb(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_cipher_algorithm cipher_algorithm,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length % AES_BLOCK_SIZE != 0) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_unwrapped = NULL;
    stored_key_t* stored_key_wrapping = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_aes(header->type, header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = unwrap_aes_ecb(&stored_key_unwrapped, in, in_length, rights, key_type, type_parameters,
                cipher_algorithm, stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

static sa_status ta_sa_key_unwrap_aes_cbc(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_cipher_algorithm cipher_algorithm,
        sa_unwrap_parameters_aes_cbc* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->iv_length != AES_BLOCK_SIZE) {
        ERROR("Invalid iv_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length % AES_BLOCK_SIZE != 0) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_unwrapped = NULL;
    stored_key_t* stored_key_wrapping = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_aes(header->type, header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = unwrap_aes_cbc(&stored_key_unwrapped, in, in_length, rights, key_type, type_parameters,
                cipher_algorithm, algorithm_parameters->iv, stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_cbc failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

static sa_status ta_sa_key_unwrap_aes_ctr(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_unwrap_parameters_aes_ctr* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->ctr == NULL) {
        ERROR("NULL ctr");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->ctr_length != AES_BLOCK_SIZE) {
        ERROR("Invalid ctr_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_unwrapped = NULL;
    stored_key_t* stored_key_wrapping = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_aes(header->type, header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = unwrap_aes_ctr(&stored_key_unwrapped, in, in_length, rights, key_type, type_parameters,
                algorithm_parameters->ctr, stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_ctr failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

static sa_status ta_sa_key_unwrap_aes_gcm(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_unwrap_parameters_aes_gcm* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->iv_length != GCM_IV_LENGTH) {
        ERROR("Invalid iv_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (algorithm_parameters->aad == NULL && algorithm_parameters->aad_length > 0) {
        ERROR("NULL aad");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->tag_length > AES_BLOCK_SIZE) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_unwrapped = NULL;
    stored_key_t* stored_key_wrapping = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_aes(header->type, header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = unwrap_aes_gcm(&stored_key_unwrapped, in, in_length, rights, key_type, type_parameters,
                algorithm_parameters, stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_aes_gcm failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

static sa_status ta_sa_key_unwrap_chacha20(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_unwrap_parameters_chacha20* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->counter == NULL) {
        ERROR("NULL counter");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->counter_length != CHACHA20_COUNTER_LENGTH) {
        ERROR("Invalid counter_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (algorithm_parameters->nonce == NULL) {
        ERROR("NULL nonce");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Invalid nonce_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_unwrapped = NULL;
    stored_key_t* stored_key_wrapping = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_chacha20(header->type, header->size)) {
            ERROR("key_type_supports_chacha20 failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = unwrap_chacha20(&stored_key_unwrapped, in, in_length, rights, key_type, type_parameters,
                algorithm_parameters, stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_chacha20 failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

static sa_status ta_sa_key_unwrap_chacha20_poly1305(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_unwrap_parameters_chacha20_poly1305* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->nonce == NULL) {
        ERROR("NULL nonce");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->nonce_length != CHACHA20_NONCE_LENGTH) {
        ERROR("Invalid nonce_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (algorithm_parameters->aad == NULL && algorithm_parameters->aad_length > 0) {
        ERROR("NULL aad");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->tag == NULL) {
        ERROR("NULL tag");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (algorithm_parameters->tag_length != CHACHA20_TAG_LENGTH) {
        ERROR("Invalid tag_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_unwrapped = NULL;
    stored_key_t* stored_key_wrapping = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_chacha20(header->type, header->size)) {
            ERROR("key_type_supports_chacha20 failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = unwrap_chacha20_poly1305(&stored_key_unwrapped, in, in_length, rights, key_type, type_parameters,
                algorithm_parameters, stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_chacha20_poly1305 failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

static sa_status ta_sa_key_unwrap_rsa(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        sa_cipher_algorithm cipher_algorithm,
        void* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_type != SA_KEY_TYPE_SYMMETRIC) {
        ERROR("Invalid type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_wrapping = NULL;
    stored_key_t* stored_key_unwrapped = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!key_type_supports_rsa(header->type, header->size)) {
            ERROR("key_type_supports_rsa failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (in_length != header->size) {
            ERROR("Invalid in_length");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        status = unwrap_rsa(&stored_key_unwrapped, in, in_length, rights, cipher_algorithm, algorithm_parameters,
                stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_rsa failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

static sa_status ta_sa_key_unwrap_ec(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        sa_unwrap_parameters_ec_elgamal* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_type != SA_KEY_TYPE_SYMMETRIC) {
        ERROR("Invalid type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (algorithm_parameters == NULL) {
        ERROR("NULL algorithm_parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_wrapping = NULL;
    stored_key_t* stored_key_unwrapped = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_wrapping, key_store, wrapping_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_wrapping);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_ec(header->type, header->type_parameters.curve, header->size)) {
            ERROR("key_type_supports_ec failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = unwrap_ec(&stored_key_unwrapped, in, in_length, rights, algorithm_parameters, stored_key_wrapping);
        if (status != SA_STATUS_OK) {
            ERROR("unwrap_ec failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_unwrapped, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_wrapping);
    stored_key_free(stored_key_unwrapped);

    return status;
}

sa_status ta_sa_key_unwrap(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_cipher_algorithm cipher_algorithm,
        void* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
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

        if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB || cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7) {
            status = ta_sa_key_unwrap_aes_ecb(key, rights, key_type, type_parameters, cipher_algorithm, wrapping_key,
                    in, in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_aes_ecb failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
                   cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7) {
            status = ta_sa_key_unwrap_aes_cbc(key, rights, key_type, type_parameters, cipher_algorithm,
                    (sa_unwrap_parameters_aes_cbc*) algorithm_parameters, wrapping_key, in,
                    in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_aes_cbc failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
            status = ta_sa_key_unwrap_aes_ctr(key, rights, key_type, type_parameters,
                    (sa_unwrap_parameters_aes_ctr*) algorithm_parameters, wrapping_key, in,
                    in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_aes_ctr failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM) {
            status = ta_sa_key_unwrap_aes_gcm(key, rights, key_type, type_parameters,
                    (sa_unwrap_parameters_aes_gcm*) algorithm_parameters, wrapping_key, in,
                    in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_aes_gcm failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20) {
            status = ta_sa_key_unwrap_chacha20(key, rights, key_type, type_parameters,
                    (sa_unwrap_parameters_chacha20*) algorithm_parameters, wrapping_key, in,
                    in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_chacha20 failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
            status = ta_sa_key_unwrap_chacha20_poly1305(key, rights, key_type, type_parameters,
                    (sa_unwrap_parameters_chacha20_poly1305*) algorithm_parameters, wrapping_key, in,
                    in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_chacha20_poly1305 failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_PKCS1V15 ||
                   cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) {
            status = ta_sa_key_unwrap_rsa(key, rights, key_type, cipher_algorithm, algorithm_parameters, wrapping_key,
                    in, in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_rsa failed");
                break;
            }
        } else if (cipher_algorithm == SA_CIPHER_ALGORITHM_EC_ELGAMAL) {
            status = ta_sa_key_unwrap_ec(key, rights, key_type, (sa_unwrap_parameters_ec_elgamal*) algorithm_parameters,
                    wrapping_key, in, in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_unwrap_ec failed");
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
