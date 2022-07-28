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
#include "dh.h"
#include "ec.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "netflix.h"
#include "porting/memory.h"
#include "rights.h"
#include "ta_sa.h"

static sa_status ta_sa_key_exchange_dh(
        sa_key* key,
        const sa_rights* rights,
        sa_key private_key,
        const void* other_public,
        size_t other_public_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (other_public == NULL) {
        ERROR("NULL other_public");
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
    stored_key_t* stored_key_shared_secret = NULL;
    stored_key_t* stored_key_private = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_private, key_store, private_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_private);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_exchange(&header->rights)) {
            ERROR("rights_allowed_exchange failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_dh(header->type, header->size)) {
            ERROR("key_type_supports_dh failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = dh_compute_shared_secret(&stored_key_shared_secret, rights, other_public, other_public_length,
                stored_key_private);
        if (status != SA_STATUS_OK) {
            ERROR("dh_compute failed");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_shared_secret, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_private);
    stored_key_free(stored_key_shared_secret);

    return status;
}

static sa_status ta_sa_key_exchange_ecdh(
        sa_key* key,
        const sa_rights* rights,
        sa_key private_key,
        const void* other_public,
        size_t other_public_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (other_public == NULL) {
        ERROR("NULL other_public");
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
    stored_key_t* stored_key_private = NULL;
    stored_key_t* stored_key_shared_secret = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_private, key_store, private_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_private);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_exchange(&header->rights)) {
            ERROR("rights_allowed_exchange failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_ec(header->type, header->type_parameters.curve, header->size)) {
            ERROR("key_type_supports_ec failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = ec_compute_ecdh_shared_secret(&stored_key_shared_secret, rights, other_public, other_public_length,
                stored_key_private);
        if (status != SA_STATUS_OK) {
            ERROR("ec_compute_ecdh_shared_secret failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_shared_secret, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_private);
    stored_key_free(stored_key_shared_secret);

    return status;
}

static sa_status ta_sa_key_exchange_netflix_dh(
        sa_key* key,
        const sa_rights* rights,
        sa_key private_key,
        const void* other_public,
        size_t other_public_length,
        sa_key_exchange_parameters_netflix_authenticated_dh* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (other_public == NULL) {
        ERROR("NULL other_public");
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

    if (parameters->out_ke == NULL) {
        ERROR("NULL out_ke");
        return SA_STATUS_NULL_PARAMETER;
    }

    *parameters->out_ke = INVALID_HANDLE;

    if (parameters->rights_ke == NULL) {
        ERROR("NULL rights_ke");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->out_kh == NULL) {
        ERROR("NULL out_kh");
        return SA_STATUS_NULL_PARAMETER;
    }

    *parameters->out_kh = INVALID_HANDLE;

    if (parameters->rights_kh == NULL) {
        ERROR("NULL rights_kh");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_enc = NULL;
    stored_key_t* stored_key_hmac = NULL;
    stored_key_t* stored_key_wrap = NULL;
    stored_key_t* stored_key_private = NULL;
    stored_key_t* stored_key_in = NULL;
    stored_key_t* stored_key_shared_secret = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_in, key_store, parameters->in_kw, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* in_header = stored_key_get_header(stored_key_in);
        if (in_header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_derive(&in_header->rights)) {
            ERROR("rights_allowed_derive failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (in_header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("Invalid key type");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = key_store_unwrap(&stored_key_private, key_store, private_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* private_header = stored_key_get_header(stored_key_private);
        if (private_header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_exchange(&private_header->rights)) {
            ERROR("rights_allowed_exchange failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_dh(private_header->type, private_header->size)) {
            ERROR("key_type_supports_dh failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        status = dh_compute_shared_secret(&stored_key_shared_secret, &in_header->rights, other_public,
                other_public_length, stored_key_private);
        if (status != SA_STATUS_OK) {
            ERROR("dh_compute failed");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        status = kdf_netflix_shared_secret(&stored_key_enc, parameters->rights_ke, &stored_key_hmac, parameters->rights_kh,
                stored_key_in, stored_key_shared_secret);
        if (status != SA_STATUS_OK) {
            ERROR("kdf_netflix_shared_secret failed");
            break;
        }

        status = key_store_import_stored_key(parameters->out_ke, key_store, stored_key_enc, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }

        status = key_store_import_stored_key(parameters->out_kh, key_store, stored_key_hmac, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }

        status = kdf_netflix_wrapping(&stored_key_wrap, rights, &in_header->rights, stored_key_enc, stored_key_hmac);
        if (status != SA_STATUS_OK) {
            ERROR("kdf_netflix_wrapping failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_wrap, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_shared_secret);
    stored_key_free(stored_key_private);
    stored_key_free(stored_key_in);
    stored_key_free(stored_key_enc);
    stored_key_free(stored_key_hmac);
    stored_key_free(stored_key_wrap);

    if (status != SA_STATUS_OK) {
        if (*parameters->out_ke != INVALID_HANDLE) {
            key_store_t* key_store = client_get_key_store(client);
            key_store_remove(key_store, *parameters->out_ke, caller_uuid);
        }

        if (*parameters->out_kh != INVALID_HANDLE) {
            key_store_t* key_store = client_get_key_store(client);
            key_store_remove(key_store, *parameters->out_kh, caller_uuid);
        }

        if (*key != INVALID_HANDLE) {
            key_store_t* key_store = client_get_key_store(client);
            key_store_remove(key_store, *key, caller_uuid);
        }
    }

    return status;
}

sa_status ta_sa_key_exchange(
        sa_key* key,
        const sa_rights* rights,
        sa_key_exchange_algorithm key_exchange_algorithm,
        sa_key private_key,
        const void* other_public,
        size_t other_public_length,
        void* parameters,
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

    if (other_public == NULL) {
        ERROR("NULL other_public");
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

        if (key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_DH) {
            status = ta_sa_key_exchange_dh(key, rights, private_key, other_public, other_public_length, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_exchange_dh failed");
                break;
            }
        } else if (key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_ECDH) {
            status = ta_sa_key_exchange_ecdh(key, rights, private_key, other_public, other_public_length, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_exchange_ecdh failed");
                break;
            }
        } else if (key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH) {
            if (parameters == NULL) {
                ERROR("NULL parameters");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            status = ta_sa_key_exchange_netflix_dh(key, rights, private_key, other_public, other_public_length,
                    (sa_key_exchange_parameters_netflix_authenticated_dh*) parameters,
                    client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_exchange_netflix_dh failed");
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
