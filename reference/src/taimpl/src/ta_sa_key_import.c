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
#include "ec.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "rights.h"
#include "rsa.h"
#include "soc_key_container.h"
#include "ta_sa.h"
#include "typej.h"

static sa_status ta_sa_key_import_symmetric_bytes(
        sa_key* key,
        const void* in,
        size_t in_length,
        sa_import_parameters_symmetric* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->rights == NULL) {
        ERROR("NULL rights");
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

    if (in_length < SYM_128_KEY_SIZE || in_length > SYM_MAX_SIZE) {
        ERROR("Bad in_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key = NULL;
    do {
        if (!stored_key_import(&stored_key, parameters->rights, SA_KEY_TYPE_SYMMETRIC, 0, in_length, in, in_length)) {
            ERROR("stored_key_import failed");
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

static sa_status ta_sa_key_import_ec_private_bytes(
        sa_key* key,
        const void* in,
        size_t in_length,
        sa_import_parameters_ec_private_bytes* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    *key = INVALID_HANDLE;

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    size_t key_size = ec_key_size_from_curve(parameters->curve);
    if (key_size == 0) {
        ERROR("Unexpected ec curve encountered");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (in_length > key_size) {
        ERROR("in_length too large");
        return SA_STATUS_BAD_PARAMETER;
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
        status = ec_validate_private(parameters->curve, in, in_length);
        if (status != SA_STATUS_OK) {
            ERROR("ec_validate_private failed");
            break;
        }

        if (!stored_key_import(&stored_key, parameters->rights, SA_KEY_TYPE_EC, parameters->curve, in_length, in,
                    in_length)) {
            ERROR("stored_key_import failed");
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

static sa_status ta_sa_key_import_rsa_private_key_info(
        sa_key* key,
        const void* in,
        size_t in_length,
        sa_import_parameters_rsa_private_key_info* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters == NULL) {
        ERROR("NULL parameters");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->rights == NULL) {
        ERROR("NULL rights");
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
        size_t key_size = rsa_validate_pkcs8(in, in_length);
        if (key_size == 0) {
            ERROR("rsa_validate_pkcs8 failed");
            status = SA_STATUS_BAD_KEY_FORMAT;
            break;
        }

        if (key_size != RSA_1024_BYTE_LENGTH && key_size != RSA_2048_BYTE_LENGTH &&
                key_size != RSA_3072_BYTE_LENGTH && key_size != RSA_4096_BYTE_LENGTH) {
            ERROR("Bad key_size");
            return SA_STATUS_BAD_PARAMETER;
        }

        if (!stored_key_import(&stored_key, parameters->rights, SA_KEY_TYPE_RSA, 0, key_size, in, in_length)) {
            ERROR("stored_key_import failed");
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

static sa_status ta_sa_key_import_exported(
        sa_key* key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (in == NULL) {
        ERROR("NULL in");
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
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_import_exported(key, key_store, in, in_length, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_exported failed");
            break;
        }
    } while (false);

    return status;
}

static sa_status ta_sa_key_import_soc(
        sa_key* key,
        const void* in,
        size_t in_length,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in_length <= 0) {
        ERROR("Bad in_length");
        return SA_STATUS_BAD_KEY_FORMAT;
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
        status = soc_kc_unwrap(&stored_key, in, in_length);
        if (status != SA_STATUS_OK) {
            ERROR("soc_kc_unwrap failed");
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

static sa_status ta_sa_key_import_typej(
        sa_key* key,
        const void* in,
        size_t in_length,
        sa_import_parameters_typej* parameters,
        client_t* client,
        const sa_uuid* caller_uuid) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }
    *key = INVALID_HANDLE;

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

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
    stored_key_t* stored_key_mac = NULL;
    stored_key_t* stored_key_encryption = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_mac, key_store, parameters->khmac, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* mac_header = stored_key_get_header(stored_key_mac);
        if (mac_header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_sign(&mac_header->rights)) {
            ERROR("rights_allowed_sign failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_hmac(mac_header->type, mac_header->size)) {
            ERROR("key_type_supports_hmac failed");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        status = key_store_unwrap(&stored_key_encryption, key_store, parameters->kcipher, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* enc_header = stored_key_get_header(stored_key_encryption);
        if (enc_header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_unwrap(&enc_header->rights)) {
            ERROR("rights_allowed_unwrap failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_aes(enc_header->type, enc_header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        status = typej_unwrap(&stored_key, in, in_length, stored_key_mac, stored_key_encryption);
        if (status != SA_STATUS_OK) {
            ERROR("typej_unwrap failed");
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key);
    stored_key_free(stored_key_encryption);
    stored_key_free(stored_key_mac);

    return status;
}

sa_status ta_sa_key_import(
        sa_key* key,
        sa_key_format key_format,
        const void* in,
        size_t in_length,
        void* parameters,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_format != SA_KEY_FORMAT_SYMMETRIC_BYTES && key_format != SA_KEY_FORMAT_EC_PRIVATE_BYTES &&
            key_format != SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO && key_format != SA_KEY_FORMAT_EXPORTED &&
            key_format != SA_KEY_FORMAT_SOC && key_format != SA_KEY_FORMAT_TYPEJ) {
        ERROR("Bad format");
        return SA_STATUS_BAD_PARAMETER;
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

        if (key_format == SA_KEY_FORMAT_SYMMETRIC_BYTES) {
            status = ta_sa_key_import_symmetric_bytes(key, in, in_length, (sa_import_parameters_symmetric*) parameters,
                    client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_import_symmetric_bytes failed");
                break;
            }
        } else if (key_format == SA_KEY_FORMAT_EC_PRIVATE_BYTES) {
            status = ta_sa_key_import_ec_private_bytes(key, in, in_length,
                    (sa_import_parameters_ec_private_bytes*) parameters, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_import_ec_private_bytes failed");
                break;
            }
        } else if (key_format == SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO) {
            status = ta_sa_key_import_rsa_private_key_info(key, in, in_length,
                    (sa_import_parameters_rsa_private_key_info*) parameters,
                    client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_import_rsa_private_key_info failed");
                break;
            }
        } else if (key_format == SA_KEY_FORMAT_EXPORTED) {
            status = ta_sa_key_import_exported(key, in, in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_import_exported failed");
                break;
            }
        } else if (key_format == SA_KEY_FORMAT_SOC) {
            status = ta_sa_key_import_soc(key, in, in_length, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_import_soc failed");
                break;
            }
        } else { // format == SA_KEY_FORMAT_TYPEJ
            status = ta_sa_key_import_typej(key, in, in_length, (sa_import_parameters_typej*) parameters, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_import_exported failed");
                break;
            }
        }
    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
