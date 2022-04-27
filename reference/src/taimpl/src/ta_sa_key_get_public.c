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
#include "log.h"
#include "rsa.h"
#include "ta_sa.h"

static sa_status ta_sa_key_get_public_ec(
        void* out,
        size_t* out_length,
        stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (header->type != SA_KEY_TYPE_EC) {
        ERROR("Bad type");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    sa_status status = ec_get_public(out, out_length, stored_key);
    if (status != SA_STATUS_OK) {
        ERROR("ec_get_public failed");
    }

    return status;
}

static sa_status ta_sa_key_get_public_dh(
        void* out,
        size_t* out_length,
        stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (header->type != SA_KEY_TYPE_DH) {
        ERROR("Bad type");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    if (out == NULL) {
        *out_length = header->size;
        return SA_STATUS_OK;
    }

    if (*out_length < header->size) {
        ERROR("Bad out_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (!dh_get_public(out, out_length, stored_key)) {
        ERROR("dh_get_public failed");
        return SA_STATUS_BAD_PARAMETER;
    }

    return SA_STATUS_OK;
}

static sa_status ta_sa_key_get_public_rsa(
        void* out,
        size_t* out_length,
        stored_key_t* stored_key) {

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return SA_STATUS_NULL_PARAMETER;
    }

    const sa_header* header = stored_key_get_header(stored_key);
    if (header == NULL) {
        ERROR("stored_key_get_header failed");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (header->type != SA_KEY_TYPE_RSA) {
        ERROR("Bad type");
        return SA_STATUS_BAD_KEY_TYPE;
    }

    sa_status status;
    do {
        if (!rsa_get_public(out, out_length, stored_key)) {
            ERROR("rsa_get_public failed");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    return status;
}

sa_status ta_sa_key_get_public(
        void* out,
        size_t* out_length,
        sa_key key,
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
    stored_key_t* stored_key = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
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

        if (header->type == SA_KEY_TYPE_EC) {
            status = ta_sa_key_get_public_ec(out, out_length, stored_key);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_get_public_ec failed");
                break;
            }
        } else if (header->type == SA_KEY_TYPE_DH) {
            status = ta_sa_key_get_public_dh(out, out_length, stored_key);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_get_public_dh failed");
                break;
            }
        } else if (header->type == SA_KEY_TYPE_RSA) {
            status = ta_sa_key_get_public_rsa(out, out_length, stored_key);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_get_public_rsa failed");
                break;
            }
        } else {
            ERROR("Unexpected key type encountered");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }
    } while (false);

    stored_key_free(stored_key);
    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
