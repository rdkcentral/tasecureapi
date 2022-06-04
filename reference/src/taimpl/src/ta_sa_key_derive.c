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
#include "kdf.h"
#include "key_store.h"
#include "key_type.h"
#include "log.h"
#include "netflix.h"
#include "porting/otp.h"
#include "rights.h"
#include "ta_sa.h"

static sa_status ta_sa_key_derive_root_key_ladder(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_parameters_root_key_ladder* parameters,
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

    if (parameters->c1 == NULL) {
        ERROR("NULL c1");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->c1_length != SYM_128_KEY_SIZE) {
        ERROR("Bad c1_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->c2 == NULL) {
        ERROR("NULL c2");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->c2_length != SYM_128_KEY_SIZE) {
        ERROR("Bad c2_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->c3 == NULL) {
        ERROR("NULL c3");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->c3_length != SYM_128_KEY_SIZE) {
        ERROR("Bad c3_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->c4 == NULL) {
        ERROR("NULL c4");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->c4_length != SYM_128_KEY_SIZE) {
        ERROR("Bad c4_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_derived = NULL;
    do {
        if (!otp_root_key_ladder(&stored_key_derived, rights, parameters->c1, parameters->c2, parameters->c3,
                    parameters->c4)) {
            ERROR("otp_root_key_ladder failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_import_stored_key(key, key_store, stored_key_derived, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_derived);

    return status;
}

static sa_status ta_sa_key_derive_ansi_x963(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_parameters_ansi_x963* parameters,
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

    if (parameters->info == NULL && parameters->info_length > 0) {
        ERROR("NULL info");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->key_length > SYM_MAX_KEY_SIZE) {
        ERROR("Bad key_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
        ERROR("Bad digest");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_parent = NULL;
    stored_key_t* stored_key_derived = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_parent, key_store, parameters->parent, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_derive(&header->rights)) {
            ERROR("rights_allowed_derive failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("Wrong key type");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        if (!kdf_ansi_x963(&stored_key_derived, rights, parameters, stored_key_parent)) {
            ERROR("kdf_ansi_x963 failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_derived, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_derived);
    stored_key_free(stored_key_parent);

    return status;
}

static sa_status ta_sa_key_derive_cmac(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_parameters_cmac* parameters,
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

    if (parameters->other_data == NULL && parameters->other_data_length > 0) {
        ERROR("NULL other_data");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->counter < 1 || parameters->counter > 4) {
        ERROR("Bad counter");
        return SA_STATUS_BAD_PARAMETER;
    }

    if ((parameters->key_length % SYM_128_KEY_SIZE) != 0) {
        ERROR("Bad key_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->key_length / SYM_128_KEY_SIZE > (size_t) (5 - parameters->counter)) {
        ERROR("Bad key_length, ctr combination");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_parent = NULL;
    stored_key_t* stored_key_derived = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_parent, key_store, parameters->parent, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_derive(&header->rights)) {
            ERROR("rights_allowed_derive failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("Wrong key type");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        if (!key_type_supports_aes(header->type, header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        if (!kdf_ctr_cmac(&stored_key_derived, rights, parameters, stored_key_parent)) {
            ERROR("kdf_ctr_cmac failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_derived, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_derived);
    stored_key_free(stored_key_parent);

    return status;
}

static sa_status ta_sa_key_derive_concat(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_parameters_concat* parameters,
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

    if (parameters->info == NULL && parameters->info_length > 0) {
        ERROR("NULL info");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->key_length > SYM_MAX_KEY_SIZE) {
        ERROR("Bad key_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
        ERROR("Bad digest");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_parent = NULL;
    stored_key_t* stored_key_derived = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_parent, key_store, parameters->parent, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_derive(&header->rights)) {
            ERROR("rights_allowed_derive failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("Wrong key type");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        if (!kdf_concat_kdf(&stored_key_derived, rights, parameters, stored_key_parent)) {
            ERROR("kdf_concat_kdf failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_derived, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_derived);
    stored_key_free(stored_key_parent);

    return status;
}

static sa_status ta_sa_key_derive_hkdf(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_parameters_hkdf* parameters,
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

    if (parameters->info == NULL && parameters->info_length > 0) {
        ERROR("NULL info");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->salt == NULL && parameters->salt_length > 0) {
        ERROR("NULL salt");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (parameters->key_length > SYM_MAX_KEY_SIZE) {
        ERROR("Bad key_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA1 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA256 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA384 &&
            parameters->digest_algorithm != SA_DIGEST_ALGORITHM_SHA512) {
        ERROR("Bad digest");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    stored_key_t* stored_key_parent = NULL;
    stored_key_t* stored_key_derived = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_parent, key_store, parameters->parent, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key_parent);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_derive(&header->rights)) {
            ERROR("rights_allowed_derive failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("Wrong key type");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        if (!key_type_supports_hmac(header->type, header->size)) {
            ERROR("key_type_supports_hmac failed");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        if (!kdf_hkdf_hmac(&stored_key_derived, rights, parameters, stored_key_parent)) {
            ERROR("kdf_hkdf_hmac failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_derived, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_derived);
    stored_key_free(stored_key_parent);

    return status;
}

static sa_status ta_sa_key_derive_netflix(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_parameters_netflix* parameters,
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
    stored_key_t* stored_key_enc = NULL;
    stored_key_t* stored_key_hmac = NULL;
    stored_key_t* stored_key_derived = NULL;
    do {
        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key_enc, key_store, parameters->kenc, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* enc_header = stored_key_get_header(stored_key_enc);
        if (enc_header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_derive(&enc_header->rights)) {
            ERROR("rights_allowed_derive failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (enc_header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("Wrong key type");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        status = key_store_unwrap(&stored_key_hmac, key_store, parameters->khmac, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* hmac_header = stored_key_get_header(stored_key_hmac);
        if (hmac_header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_derive(&hmac_header->rights)) {
            ERROR("rights_allowed_derive failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (hmac_header->type != SA_KEY_TYPE_SYMMETRIC) {
            ERROR("Wrong key type");
            status = SA_STATUS_BAD_KEY_TYPE;
            break;
        }

        if (!kdf_netflix_wrapping(&stored_key_derived, rights, &enc_header->rights, stored_key_enc, stored_key_hmac)) {
            ERROR("kdf_netflix_wrapping_key failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        status = key_store_import_stored_key(key, key_store, stored_key_derived, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_import_stored_key failed");
            break;
        }
    } while (false);

    stored_key_free(stored_key_derived);
    stored_key_free(stored_key_enc);
    stored_key_free(stored_key_hmac);

    return status;
}

sa_status ta_sa_key_derive(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_algorithm kdf_algorithm,
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

    if (parameters == NULL) {
        ERROR("NULL parameters");
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

        if (kdf_algorithm == SA_KDF_ALGORITHM_ROOT_KEY_LADDER) {
            status = ta_sa_key_derive_root_key_ladder(key, rights, (sa_kdf_parameters_root_key_ladder*) parameters,
                    client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_derive_root_key_ladder failed");
                break;
            }
        } else if (kdf_algorithm == SA_KDF_ALGORITHM_HKDF) {
            status = ta_sa_key_derive_hkdf(key, rights, (sa_kdf_parameters_hkdf*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_derive_hkdf failed");
                break;
            }
        } else if (kdf_algorithm == SA_KDF_ALGORITHM_CONCAT) {
            status = ta_sa_key_derive_concat(key, rights, (sa_kdf_parameters_concat*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_derive_concat failed");
                break;
            }
        } else if (kdf_algorithm == SA_KDF_ALGORITHM_ANSI_X963) {
            status = ta_sa_key_derive_ansi_x963(key, rights, (sa_kdf_parameters_ansi_x963*) parameters, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_derive_ansi_x963 failed");
                break;
            }
        } else if (kdf_algorithm == SA_KDF_ALGORITHM_CMAC) {
            status = ta_sa_key_derive_cmac(key, rights, (sa_kdf_parameters_cmac*) parameters, client, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_derive_cmac failed");
                break;
            }
        } else if (kdf_algorithm == SA_KDF_ALGORITHM_NETFLIX) {
            status = ta_sa_key_derive_netflix(key, rights, (sa_kdf_parameters_netflix*) parameters, client,
                    caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("ta_sa_key_derive_netflix failed");
                break;
            }
        } else {
            ERROR("Bad algorithm");
            status = SA_STATUS_BAD_PARAMETER;
        }
    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
