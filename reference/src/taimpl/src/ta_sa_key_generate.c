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
#include "common.h"
#include "dh.h"
#include "ec.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "symmetric.h"
#include "ta_sa.h"

static sa_status ta_sa_key_generate_symmetric(
        sa_key* key,
        const sa_rights* rights,
        sa_generate_parameters_symmetric* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

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

    if (parameters->key_length < SYM_128_KEY_SIZE || parameters->key_length > SYM_MAX_KEY_SIZE) {
        ERROR("Bad key_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key = NULL;
    do {
        if (!symmetric_generate_key(&stored_key, rights, parameters)) {
            ERROR("symmetric_generate_key failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_import_stored_key(key, key_store, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key);

    return status;
}

static sa_status ta_sa_key_generate_ec(
        sa_key* key,
        const sa_rights* rights,
        sa_generate_parameters_ec* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

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
    do {
        status = ec_generate_key(&stored_key, rights, parameters);
        if (status != SA_STATUS_OK) {
            ERROR("ec_generate_key failed");
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_import_stored_key(key, key_store, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key);

    return status;
}

static sa_status ta_sa_key_generate_rsa(
        sa_key* key,
        const sa_rights* rights,
        sa_generate_parameters_rsa* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    ERROR("RSA key generation is not supported");
    return SA_STATUS_OPERATION_NOT_SUPPORTED;
}

static sa_status ta_sa_key_generate_dh(
        sa_key* key,
        const sa_rights* rights,
        sa_generate_parameters_dh* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

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

    if (parameters->p == NULL) {
        ERROR("NULL p");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (!key_type_supports_dh(SA_KEY_TYPE_DH, parameters->p_length)) {
        ERROR("Bad p_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->g == NULL) {
        ERROR("NULL g");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->g_length < 1 || parameters->g_length > parameters->p_length) {
        ERROR("Bad g_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key = NULL;
    do {
        if (!dh_generate(&stored_key, rights, parameters->p, parameters->p_length, parameters->g,
                    parameters->g_length)) {
            ERROR("dh_generate failed");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_import_stored_key(key, key_store, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key);

    return status;
}

sa_status ta_sa_key_generate(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
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

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        if (key_type == SA_KEY_TYPE_SYMMETRIC) {
            status = ta_sa_key_generate_symmetric(key, rights, (sa_generate_parameters_symmetric*) parameters, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_generate_symmetric failed");
                break;
            }
        } else if (key_type == SA_KEY_TYPE_EC) {
            status = ta_sa_key_generate_ec(key, rights, (sa_generate_parameters_ec*) parameters,
                    client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_generate_ec failed");
                break;
            }
        } else if (key_type == SA_KEY_TYPE_DH) {
            status = ta_sa_key_generate_dh(key, rights, (sa_generate_parameters_dh*) parameters,
                    client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_generate_dh failed");
                break;
            }
        } else if (key_type == SA_KEY_TYPE_RSA) {
            status = ta_sa_key_generate_rsa(key, rights, (sa_generate_parameters_rsa*) parameters,
                    client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_generate_rsa failed");
                break;
            }
        } else {
            ERROR("Unknown key type encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
