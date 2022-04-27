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

#include "ta.h" // NOLINT
#include "log.h"
#include "ta_sa.h"
#include "transport.h"
#include <malloc.h>
#include <stdbool.h>

typedef struct {
    ta_client client;
} ta_session_context;

static sa_status ta_invoke_get_version(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_get_version_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_get_version_s* get_version = (sa_get_version_s*) params[0].mem_ref;
    return ta_sa_get_version(&get_version->version, context->client, uuid);
}

static sa_status ta_invoke_get_name(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_get_name_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_get_name_s* get_name = (sa_get_name_s*) params[0].mem_ref;
    return ta_sa_get_name((char*) params[1].mem_ref, &get_name->name_length, context->client, uuid);
}

static sa_status ta_invoke_get_device_id(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_get_device_id_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_get_device_id_s* get_device_id = (sa_get_device_id_s*) params[0].mem_ref;
    return ta_sa_get_device_id(&get_device_id->id, context->client, uuid);
}

static sa_status ta_invoke_get_ta_uuid(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_get_ta_uuid_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_get_ta_uuid_s* get_ta_uuid = (sa_get_ta_uuid_s*) params[0].mem_ref;
    return ta_sa_get_ta_uuid(&get_ta_uuid->uuid, context->client, uuid);
}

static sa_status ta_invoke_key_generate(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_generate_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_generate_s* key_generate = (sa_key_generate_s*) params[0].mem_ref;
    sa_generate_parameters_symmetric parameters_symmetric;
    sa_generate_parameters_rsa parameters_rsa;
    sa_generate_parameters_ec parameters_ec;
    sa_generate_parameters_dh parameters_dh;
    void* parameters;
    switch (key_generate->key_type) {
        case SA_KEY_TYPE_SYMMETRIC:
            parameters_symmetric.key_length = key_generate->key_length;
            parameters = &parameters_symmetric;
            break;

        case SA_KEY_TYPE_RSA:
            parameters_rsa.modulus_length = key_generate->key_length;
            parameters = &parameters_rsa;
            break;

        case SA_KEY_TYPE_EC:
            parameters_ec.curve = key_generate->key_length;
            parameters = &parameters_ec;
            break;

        case SA_KEY_TYPE_DH:
            parameters_dh.p = params[1].mem_ref;
            parameters_dh.p_length = params[1].mem_ref_size;
            parameters_dh.g = params[2].mem_ref;
            parameters_dh.g_length = params[2].mem_ref_size;
            parameters = &parameters_dh;
            break;

        default:
            parameters = NULL;
    }

    return ta_sa_key_generate(&key_generate->key, &key_generate->rights, key_generate->key_type, parameters,
            context->client, uuid);
}

static sa_status ta_invoke_key_export(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_export_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_export_s* key_export = (sa_key_export_s*) params[0].mem_ref;
    return ta_sa_key_export(params[1].mem_ref, &key_export->out_length, params[2].mem_ref, params[2].mem_ref_size,
            key_export->key, context->client, uuid);
}

static sa_status ta_invoke_key_import(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_import_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_import_s* key_import = (sa_key_import_s*) params[0].mem_ref;
    sa_import_parameters_symmetric parameters_symmetric;
    sa_import_parameters_rsa_private_key_info parameters_rsa;
    sa_import_parameters_ec_private_bytes parameters_ec;
    void* parameters = NULL;
    switch (key_import->key_format) {
        case SA_KEY_FORMAT_SYMMETRIC_BYTES:
            if (params[2].mem_ref_size != sizeof(sa_rights)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_BAD_PARAMETER;
            }

            parameters_symmetric.rights = params[2].mem_ref;
            parameters = &parameters_symmetric;
            break;

        case SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO:
            if (params[2].mem_ref_size != sizeof(sa_rights)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_BAD_PARAMETER;
            }

            parameters_rsa.rights = params[2].mem_ref;
            parameters = &parameters_rsa;
            break;

        case SA_KEY_FORMAT_EC_PRIVATE_BYTES:
            if (params[2].mem_ref_size != sizeof(sa_rights)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_BAD_PARAMETER;
            }

            parameters_ec.rights = params[2].mem_ref;
            parameters_ec.curve = key_import->curve;
            parameters = &parameters_ec;
            break;

        case SA_KEY_FORMAT_EXPORTED:
            parameters = NULL;
            break;

        case SA_KEY_FORMAT_TYPEJ:
            if (params[2].mem_ref_size != sizeof(sa_import_parameters_typej)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_BAD_PARAMETER;
            }

            parameters = params[2].mem_ref;
            break;

        case SA_KEY_FORMAT_SOC:
            parameters = params[2].mem_ref;
            break;
    }

    return ta_sa_key_import(&key_import->key, key_import->key_format, params[1].mem_ref, params[1].mem_ref_size,
            parameters, context->client, uuid);
}

static sa_status ta_invoke_key_unwrap(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_unwrap_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_unwrap_s* key_unwrap = (sa_key_unwrap_s*) params[0].mem_ref;
    void* type_parameters;
    sa_unwrap_type_parameters_ec type_parameters_ec = {key_unwrap->curve};
    if (key_unwrap->key_type == SA_KEY_TYPE_EC) {
        type_parameters = &type_parameters_ec;
    } else {
        type_parameters = NULL;
    }

    void* algorithm_parameters;
    sa_unwrap_parameters_aes_cbc parameters_aes_cbc;
    sa_unwrap_parameters_aes_ctr parameters_aes_ctr;
    sa_unwrap_parameters_aes_gcm parameters_aes_gcm;
    switch (key_unwrap->cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_aes_iv_s)) {
                ERROR("params[2].mem_ref is bad size");
                return SA_STATUS_BAD_PARAMETER;
            }

            sa_unwrap_parameters_aes_iv_s* params_cbc = (sa_unwrap_parameters_aes_iv_s*) params[2].mem_ref;
            parameters_aes_cbc.iv = &params_cbc->iv;
            parameters_aes_cbc.iv_length = sizeof(params_cbc->iv);
            algorithm_parameters = &parameters_aes_cbc;
            break;

        case SA_CIPHER_ALGORITHM_AES_CTR:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_aes_iv_s)) {
                ERROR("params[2].mem_ref is bad size");
                return SA_STATUS_BAD_PARAMETER;
            }

            sa_unwrap_parameters_aes_iv_s* params_ctr = (sa_unwrap_parameters_aes_iv_s*) params[2].mem_ref;
            parameters_aes_ctr.ctr = &params_ctr->iv;
            parameters_aes_ctr.ctr_length = sizeof(params_ctr->iv);
            algorithm_parameters = &parameters_aes_ctr;
            break;

        case SA_CIPHER_ALGORITHM_AES_GCM:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_aes_gcm_s)) {
                ERROR("params[2].mem_ref is bad size");
                return SA_STATUS_BAD_PARAMETER;
            }

            if (params[3].mem_ref == NULL) {
                ERROR("NULL params[3].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            sa_unwrap_parameters_aes_gcm_s* params_gcm = (sa_unwrap_parameters_aes_gcm_s*) params[2].mem_ref;
            parameters_aes_gcm.iv = &params_gcm->iv;
            parameters_aes_gcm.iv_length = params_gcm->iv_length;
            parameters_aes_gcm.aad = params[3].mem_ref;
            parameters_aes_gcm.aad_length = params[3].mem_ref_size;
            parameters_aes_gcm.tag = &params_gcm->tag;
            parameters_aes_gcm.tag_length = params_gcm->tag_length;
            algorithm_parameters = &parameters_aes_gcm;
            break;

        case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_ec_elgamal_s)) {
                ERROR("params[2].mem_ref is bad size");
                return SA_STATUS_BAD_PARAMETER;
            }

            algorithm_parameters = params[2].mem_ref;
            break;

        default:
            algorithm_parameters = NULL;
            break;
    }

    return ta_sa_key_unwrap(&key_unwrap->key, &key_unwrap->rights, key_unwrap->key_type, type_parameters,
            key_unwrap->cipher_algorithm, algorithm_parameters, key_unwrap->wrapping_key, params[1].mem_ref,
            params[1].mem_ref_size, context->client, uuid);
}

static sa_status ta_invoke_key_get_public(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_get_public_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_get_public_s* key_get_public = (sa_key_get_public_s*) params[0].mem_ref;
    return ta_sa_key_get_public(params[1].mem_ref, &key_get_public->out_length, key_get_public->key, context->client,
            uuid);
}

static sa_status ta_invoke_key_derive(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_derive_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (params[1].mem_ref == NULL) {
        ERROR("NULL params[1].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_key_derive_s* key_derive = (sa_key_derive_s*) params[0].mem_ref;

    void* algorithm_parameters;
    sa_kdf_parameters_root_key_ladder parameters_root_key_ladder;
    sa_kdf_parameters_hkdf parameters_hkdf;
    sa_kdf_parameters_concat parameters_concat;
    sa_kdf_parameters_ansi_x963 parameters_ansi_x963;
    sa_kdf_parameters_cmac parameters_cmac;
    switch (key_derive->kdf_algorithm) {
        case SA_KDF_ALGORITHM_ROOT_KEY_LADDER: {
            sa_kdf_parameters_root_key_ladder_s* parameters_root_key_ladder_s =
                    (sa_kdf_parameters_root_key_ladder_s*) params[1].mem_ref;
            parameters_root_key_ladder.c1 = parameters_root_key_ladder_s->c1;
            parameters_root_key_ladder.c1_length = AES_BLOCK_SIZE;
            parameters_root_key_ladder.c2 = parameters_root_key_ladder_s->c2;
            parameters_root_key_ladder.c2_length = AES_BLOCK_SIZE;
            parameters_root_key_ladder.c3 = parameters_root_key_ladder_s->c3;
            parameters_root_key_ladder.c3_length = AES_BLOCK_SIZE;
            parameters_root_key_ladder.c4 = parameters_root_key_ladder_s->c4;
            parameters_root_key_ladder.c4_length = AES_BLOCK_SIZE;
            algorithm_parameters = &parameters_root_key_ladder;
            break;
        }
        case SA_KDF_ALGORITHM_HKDF: {
            sa_kdf_parameters_hkdf_s* parameters_hkdf_s = (sa_kdf_parameters_hkdf_s*) params[1].mem_ref;
            parameters_hkdf.key_length = parameters_hkdf_s->key_length;
            parameters_hkdf.digest_algorithm = parameters_hkdf_s->digest_algorithm;
            parameters_hkdf.parent = parameters_hkdf_s->parent;
            parameters_hkdf.salt = params[3].mem_ref;
            parameters_hkdf.salt_length = params[3].mem_ref_size;
            parameters_hkdf.info = params[2].mem_ref;
            parameters_hkdf.info_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_hkdf;
            break;
        }
        case SA_KDF_ALGORITHM_CONCAT: {
            sa_kdf_parameters_concat_s* parameters_concat_s = (sa_kdf_parameters_concat_s*) params[1].mem_ref;
            parameters_concat.key_length = parameters_concat_s->key_length;
            parameters_concat.digest_algorithm = parameters_concat_s->digest_algorithm;
            parameters_concat.parent = parameters_concat_s->parent;
            parameters_concat.info = params[2].mem_ref;
            parameters_concat.info_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_concat;
            break;
        }
        case SA_KDF_ALGORITHM_ANSI_X963: {
            sa_kdf_parameters_ansi_x963_s* parameters_ansi_x963_s = (sa_kdf_parameters_ansi_x963_s*) params[1].mem_ref;
            parameters_ansi_x963.key_length = parameters_ansi_x963_s->key_length;
            parameters_ansi_x963.digest_algorithm = parameters_ansi_x963_s->digest_algorithm;
            parameters_ansi_x963.parent = parameters_ansi_x963_s->parent;
            parameters_ansi_x963.info = params[2].mem_ref;
            parameters_ansi_x963.info_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_ansi_x963;
            break;
        }
        case SA_KDF_ALGORITHM_CMAC: {
            sa_kdf_parameters_cmac_s* parameters_cmac_s = (sa_kdf_parameters_cmac_s*) params[1].mem_ref;
            parameters_cmac.key_length = parameters_cmac_s->key_length;
            parameters_cmac.counter = parameters_cmac_s->counter;
            parameters_cmac.parent = parameters_cmac_s->parent;
            parameters_cmac.other_data = params[2].mem_ref;
            parameters_cmac.other_data_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_cmac;
            break;
        }
        case SA_KDF_ALGORITHM_NETFLIX: {
            algorithm_parameters = params[1].mem_ref;
            break;
        }
        default:
            return SA_STATUS_BAD_PARAMETER;
    }

    return ta_sa_key_derive(&key_derive->key, &key_derive->rights, key_derive->kdf_algorithm, algorithm_parameters,
            context->client, uuid);
}

static sa_status ta_invoke_key_exchange(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_exchange_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_exchange_s* key_exchange = (sa_key_exchange_s*) params[0].mem_ref;
    sa_key_exchange_parameters_netflix_authenticated_dh netflix_authenticated_dh;
    void* parameters = NULL;
    if (key_exchange->key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH) {
        if (params[2].mem_ref == NULL) {
            ERROR("NULL params[1].mem_ref");
            return SA_STATUS_NULL_PARAMETER;
        }

        if (params[2].mem_ref_size != sizeof(sa_key_exchange_parameters_netflix_authenticated_dh_s)) {
            ERROR("params[0].mem_ref_size is invalid");
            return SA_STATUS_BAD_PARAMETER;
        }

        sa_key_exchange_parameters_netflix_authenticated_dh_s* netflix_authenticated_dh_s =
                (sa_key_exchange_parameters_netflix_authenticated_dh_s*) params[2].mem_ref;
        netflix_authenticated_dh.in_kw = netflix_authenticated_dh_s->in_kw;
        netflix_authenticated_dh.out_ke = &netflix_authenticated_dh_s->out_ke;
        netflix_authenticated_dh.rights_ke = &netflix_authenticated_dh_s->rights_ke;
        netflix_authenticated_dh.out_kh = &netflix_authenticated_dh_s->out_kh;
        netflix_authenticated_dh.rights_kh = &netflix_authenticated_dh_s->rights_kh;
        parameters = &netflix_authenticated_dh;
    }

    return ta_sa_key_exchange(&key_exchange->key, &key_exchange->rights, key_exchange->key_exchange_algorithm,
            key_exchange->private_key, params[1].mem_ref, params[1].mem_ref_size, parameters,
            context->client, uuid);
}

static sa_status ta_invoke_key_release(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_release_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_release_s* key_release = (sa_key_release_s*) params[0].mem_ref;
    return ta_sa_key_release(key_release->key, context->client, uuid);
}

static sa_status ta_invoke_key_header(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_header_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_header_s* key_header = (sa_key_header_s*) params[0].mem_ref;
    return ta_sa_key_header(&key_header->header, key_header->key, context->client, uuid);
}

static sa_status ta_invoke_key_digest(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_key_digest_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_key_digest_s* key_digest = (sa_key_digest_s*) params[0].mem_ref;
    return ta_sa_key_digest(params[1].mem_ref, &key_digest->out_length, key_digest->key, key_digest->digest_algorithm,
            context->client, uuid);
}

static sa_status ta_invoke_crypto_random(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    // params[0] only contains the API Version.

    if (params[1].mem_ref == NULL) {
        ERROR("NULL params[1].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    return ta_sa_crypto_random(params[1].mem_ref, params[1].mem_ref_size, context->client, uuid);
}

static sa_status ta_invoke_crypto_cipher_init(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_cipher_init_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_cipher_init_s* crypto_cipher_init = (sa_crypto_cipher_init_s*) params[0].mem_ref;
    sa_cipher_parameters_aes_cbc parameters_aes_cbc;
    sa_cipher_parameters_aes_ctr parameters_aes_ctr;
    sa_cipher_parameters_aes_gcm parameters_aes_gcm;
    sa_cipher_parameters_chacha20 parameters_chacha20;
    sa_cipher_parameters_chacha20_poly1305 parameters_chacha20_poly1305;
    void* parameters;
    switch (crypto_cipher_init->cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            parameters_aes_cbc.iv = params[1].mem_ref;
            parameters_aes_cbc.iv_length = params[1].mem_ref_size;
            parameters = &parameters_aes_cbc;
            break;

        case SA_CIPHER_ALGORITHM_AES_CTR:
            parameters_aes_ctr.ctr = params[1].mem_ref;
            parameters_aes_ctr.ctr_length = params[1].mem_ref_size;
            parameters = &parameters_aes_ctr;
            break;

        case SA_CIPHER_ALGORITHM_AES_GCM:
            parameters_aes_gcm.iv = params[1].mem_ref;
            parameters_aes_gcm.iv_length = params[1].mem_ref_size;
            parameters_aes_gcm.aad = params[2].mem_ref;
            parameters_aes_gcm.aad_length = params[2].mem_ref_size;
            parameters = &parameters_aes_gcm;
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20:
            parameters_chacha20.nonce = params[1].mem_ref;
            parameters_chacha20.nonce_length = params[1].mem_ref_size;
            parameters_chacha20.counter = params[2].mem_ref;
            parameters_chacha20.counter_length = params[2].mem_ref_size;
            parameters = &parameters_chacha20;
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            parameters_chacha20_poly1305.nonce = params[1].mem_ref;
            parameters_chacha20_poly1305.nonce_length = params[1].mem_ref_size;
            parameters_chacha20_poly1305.aad = params[2].mem_ref;
            parameters_chacha20_poly1305.aad_length = params[2].mem_ref_size;
            parameters = &parameters_chacha20_poly1305;
            break;

        default:
            parameters = NULL;
            break;
    }

    return ta_sa_crypto_cipher_init(&crypto_cipher_init->context, crypto_cipher_init->cipher_algorithm,
            crypto_cipher_init->cipher_mode, crypto_cipher_init->key, parameters, context->client,
            uuid);
}

static sa_status ta_invoke_crypto_cipher_update_iv(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_cipher_update_iv_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_cipher_update_iv_s* cipher_update_iv = (sa_crypto_cipher_update_iv_s*) params[0].mem_ref;
    return ta_sa_crypto_cipher_update_iv(cipher_update_iv->context, params[1].mem_ref, params[1].mem_ref_size,
            context->client, uuid);
}

static sa_status ta_invoke_crypto_cipher_process(
        bool last,
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_cipher_process_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_cipher_process_s* cipher_process = (sa_crypto_cipher_process_s*) params[0].mem_ref;
    sa_buffer out;
    out.buffer_type = cipher_process->out_buffer_type;
    if (cipher_process->out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        out.context.clear.buffer = params[1].mem_ref;
        out.context.clear.length = params[1].mem_ref_size;
        out.context.clear.offset = cipher_process->out_offset;
    } else {
        out.context.svp.buffer = *(sa_svp_buffer*) params[1].mem_ref;
        out.context.svp.offset = cipher_process->out_offset;
    }

    sa_buffer in;
    in.buffer_type = cipher_process->in_buffer_type;
    if (cipher_process->in_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        in.context.clear.buffer = params[2].mem_ref;
        in.context.clear.length = params[2].mem_ref_size;
        in.context.clear.offset = cipher_process->in_offset;
    } else {
        in.buffer_type = cipher_process->in_buffer_type;
        in.context.svp.buffer = *(sa_svp_buffer*) params[2].mem_ref;
        in.context.svp.offset = cipher_process->in_offset;
    }

    sa_status status;
    if (last) {
        void* parameters;
        sa_cipher_end_parameters_aes_gcm parameters_aes_gcm;
        if (params[3].mem_ref != NULL) {
            parameters_aes_gcm.tag = params[3].mem_ref;
            parameters_aes_gcm.tag_length = params[3].mem_ref_size;
            parameters = &parameters_aes_gcm;
        } else {
            parameters = NULL;
        }

        status = ta_sa_crypto_cipher_process_last(params[1].mem_ref == NULL ? NULL : &out, cipher_process->context, &in,
                &cipher_process->bytes_to_process, parameters, context->client, uuid);
    } else {
        status = ta_sa_crypto_cipher_process(params[1].mem_ref == NULL ? NULL : &out, cipher_process->context, &in,
                &cipher_process->bytes_to_process, context->client, uuid);
    }

    if (params[1].mem_ref != NULL)
        cipher_process->out_offset =
                (cipher_process->out_buffer_type == SA_BUFFER_TYPE_CLEAR) ? out.context.clear.offset : out.context.svp.offset;

    cipher_process->in_offset =
            (cipher_process->in_buffer_type == SA_BUFFER_TYPE_CLEAR) ? in.context.clear.offset : in.context.svp.offset;
    return status;
}

static sa_status ta_invoke_crypto_cipher_release(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_cipher_release_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_cipher_release_s* cipher_release = (sa_crypto_cipher_release_s*) params[0].mem_ref;
    return ta_sa_crypto_cipher_release(cipher_release->cipher_context, context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_init(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_mac_init_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_mac_init_s* mac_init = (sa_crypto_mac_init_s*) params[0].mem_ref;
    void* parameters;
    sa_mac_parameters_hmac mac_parameters_hmac;
    if (mac_init->mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
        mac_parameters_hmac.digest_algorithm = mac_init->digest_algorithm;
        parameters = &mac_parameters_hmac;
    } else {
        parameters = NULL;
    }

    return ta_sa_crypto_mac_init(&mac_init->context, mac_init->mac_algorithm, mac_init->key, parameters,
            context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_process(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_mac_process_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_mac_process_s* mac_process = (sa_crypto_mac_process_s*) params[0].mem_ref;
    return ta_sa_crypto_mac_process(mac_process->mac_context, params[1].mem_ref, params[1].mem_ref_size,
            context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_process_key(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_mac_process_key_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_mac_process_key_s* mac_process_key = (sa_crypto_mac_process_key_s*) params[0].mem_ref;
    return ta_sa_crypto_mac_process_key(mac_process_key->mac_context, mac_process_key->key, context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_compute(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_mac_compute_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_mac_compute_s* mac_compute = (sa_crypto_mac_compute_s*) params[0].mem_ref;
    return ta_sa_crypto_mac_compute(params[1].mem_ref, &mac_compute->out_length, mac_compute->context, context->client,
            uuid);
}

static sa_status ta_invoke_crypto_mac_release(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_mac_release_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_mac_release_s* mac_release = (sa_crypto_mac_release_s*) params[0].mem_ref;
    return ta_sa_crypto_mac_release(mac_release->context, context->client, uuid);
}

static sa_status ta_invoke_crypto_sign(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_crypto_sign_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_crypto_sign_s* sign = (sa_crypto_sign_s*) params[0].mem_ref;
    sa_sign_parameters_rsa_pss parameters_rsa_pss;
    sa_sign_parameters_rsa_pkcs1v15 parameters_rsa_pkcs1v15;
    sa_sign_parameters_ecdsa parameters_ecdsa;
    void* parameters;
    if (sign->signature_algorithm == SA_SIGNATURE_ALGORITHM_RSA_PSS) {
        parameters_rsa_pss.digest_algorithm = sign->digest_algorithm;
        parameters_rsa_pss.precomputed_digest = sign->precomputed_digest;
        parameters_rsa_pss.salt_length = sign->salt_length;
        parameters = &parameters_rsa_pss;
    } else if (sign->signature_algorithm == SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15) {
        parameters_rsa_pkcs1v15.digest_algorithm = sign->digest_algorithm;
        parameters_rsa_pkcs1v15.precomputed_digest = sign->precomputed_digest;
        parameters = &parameters_rsa_pkcs1v15;
    } else if (sign->signature_algorithm == SA_SIGNATURE_ALGORITHM_ECDSA) {
        parameters_ecdsa.digest_algorithm = sign->digest_algorithm;
        parameters_ecdsa.precomputed_digest = sign->precomputed_digest;
        parameters = &parameters_ecdsa;
    } else {
        parameters = NULL;
    }

    return ta_sa_crypto_sign(params[1].mem_ref, &sign->out_length, sign->signature_algorithm, sign->key,
            params[2].mem_ref, params[2].mem_ref_size, parameters, context->client, uuid);
}

static sa_status ta_invoke_svp_buffer_create(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_svp_buffer_create_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_svp_buffer_create_s* svp_buffer_create = (sa_svp_buffer_create_s*) params[0].mem_ref;
    return ta_sa_svp_buffer_create(&svp_buffer_create->svp_buffer, (void*) svp_buffer_create->svp_memory, // NOLINT
            svp_buffer_create->size, context->client, uuid);
}

static sa_status ta_invoke_svp_buffer_release(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_svp_buffer_release_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_svp_buffer_release_s* svp_buffer_release = (sa_svp_buffer_release_s*) params[0].mem_ref;
    return ta_sa_svp_buffer_release((void**) &svp_buffer_release->svp_memory, &svp_buffer_release->size,
            svp_buffer_release->svp_buffer, context->client, uuid);
}

static sa_status ta_invoke_svp_buffer_write(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_svp_buffer_write_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_svp_buffer_write_s* svp_buffer_write = (sa_svp_buffer_write_s*) params[0].mem_ref;
    return ta_sa_svp_buffer_write(svp_buffer_write->svp_buffer, &svp_buffer_write->offset, params[1].mem_ref,
            params[1].mem_ref_size, context->client, uuid);
}

static sa_status ta_invoke_svp_buffer_copy(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_svp_buffer_copy_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_svp_buffer_copy_s* svp_buffer_copy = (sa_svp_buffer_copy_s*) params[0].mem_ref;
    return ta_sa_svp_buffer_copy(svp_buffer_copy->out_svp_buffer, &svp_buffer_copy->out_offset,
            svp_buffer_copy->in_svp_buffer, &svp_buffer_copy->in_offset, svp_buffer_copy->in_length, context->client,
            uuid);
}

static sa_status ta_invoke_svp_key_check(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_svp_key_check_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_svp_key_check_s* svp_key_check = (sa_svp_key_check_s*) params[0].mem_ref;
    sa_buffer in;
    in.buffer_type = svp_key_check->in_buffer_type;
    if (svp_key_check->in_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        in.context.clear.buffer = params[1].mem_ref;
        in.context.clear.length = params[1].mem_ref_size;
        in.context.clear.offset = svp_key_check->in_offset;
    } else {
        in.buffer_type = svp_key_check->in_buffer_type;
        in.context.svp.buffer = *(sa_svp_buffer*) params[1].mem_ref;
        in.context.svp.offset = svp_key_check->in_offset;
    }

    sa_status status = ta_sa_svp_key_check(svp_key_check->key, &in, svp_key_check->bytes_to_process, params[2].mem_ref,
            params[2].mem_ref_size, context->client, uuid);
    svp_key_check->in_offset =
            (svp_key_check->in_buffer_type == SA_BUFFER_TYPE_CLEAR) ? in.context.clear.offset : in.context.svp.offset;
    return status;
}

static sa_status ta_invoke_svp_buffer_check(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_svp_buffer_check_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_svp_buffer_check_s* svp_buffer_check = (sa_svp_buffer_check_s*) params[0].mem_ref;
    return ta_sa_svp_buffer_check(svp_buffer_check->svp_buffer, svp_buffer_check->offset, svp_buffer_check->length,
            svp_buffer_check->digest_algorithm, params[1].mem_ref, params[1].mem_ref_size, context->client,
            uuid);
}

static sa_status ta_invoke_process_common_encryption(
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref_size != sizeof(sa_process_common_encryption_s)) {
        ERROR("params[0].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (params[1].mem_ref == NULL) {
        ERROR("NULL params[1].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_process_common_encryption_s* process_common_encryption = (sa_process_common_encryption_s*) params[0].mem_ref;
    if (params[1].mem_ref_size != sizeof(sa_subsample_length) * process_common_encryption->subsample_count) {
        ERROR("params[1].mem_ref_size is invalid");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_buffer out;
    out.buffer_type = process_common_encryption->out_buffer_type;
    if (process_common_encryption->out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        out.context.clear.buffer = params[2].mem_ref;
        out.context.clear.length = params[2].mem_ref_size;
        out.context.clear.offset = process_common_encryption->out_offset;
    } else {
        out.context.svp.buffer = *(sa_svp_buffer*) params[2].mem_ref;
        out.context.svp.offset = process_common_encryption->out_offset;
    }

    sa_buffer in;
    in.buffer_type = process_common_encryption->in_buffer_type;
    if (process_common_encryption->in_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        in.context.clear.buffer = params[3].mem_ref;
        in.context.clear.length = params[3].mem_ref_size;
        in.context.clear.offset = process_common_encryption->in_offset;
    } else {
        in.buffer_type = process_common_encryption->in_buffer_type;
        in.context.svp.buffer = *(sa_svp_buffer*) params[3].mem_ref;
        in.context.svp.offset = process_common_encryption->in_offset;
    }

    sa_status status;
    sa_sample sample;
    sample.iv = process_common_encryption->iv;
    sample.iv_length = AES_BLOCK_SIZE;
    sample.crypt_byte_block = process_common_encryption->crypt_byte_block;
    sample.skip_byte_block = process_common_encryption->skip_byte_block;
    sample.subsample_count = process_common_encryption->subsample_count;
    sample.subsample_lengths = (sa_subsample_length*) params[1].mem_ref;
    sample.context = process_common_encryption->context;
    sample.out = &out;
    sample.in = &in;
    status = ta_sa_process_common_encryption(1, &sample, context->client, uuid);

    process_common_encryption->out_offset =
            (out.buffer_type == SA_BUFFER_TYPE_CLEAR) ? out.context.clear.offset : out.context.svp.offset;
    process_common_encryption->in_offset =
            (in.buffer_type == SA_BUFFER_TYPE_CLEAR) ? in.context.clear.offset : in.context.svp.offset;

    return status;
}

sa_status ta_invoke_command_handler(
        void* session_context,
        SA_COMMAND_ID command_id,
        ta_param params[NUM_TA_PARAMS]) {

    if (params == NULL) {
        ERROR("NULL params");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[0].mem_ref == NULL) {
        ERROR("NULL params[0].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (((uint8_t*) params[0].mem_ref)[0] != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    do {
        if (session_context == NULL) {
            ERROR("NULL session_context");
            return SA_STATUS_NULL_PARAMETER;
        }

        sa_uuid uuid;
        status = transport_authenticate_caller(&uuid);
        if (status != SA_STATUS_OK) {
            ERROR("transport_authenticate_caller failed: %d", status);
            break;
        }

        const ta_session_context* context = session_context;
        switch (command_id) {
            case SA_GET_VERSION:
                status = ta_invoke_get_version(params, context, &uuid);
                break;

            case SA_GET_TA_UUID:
                status = ta_invoke_get_ta_uuid(params, context, &uuid);
                break;

            case SA_GET_NAME:
                status = ta_invoke_get_name(params, context, &uuid);
                break;

            case SA_GET_DEVICE_ID:
                status = ta_invoke_get_device_id(params, context, &uuid);
                break;

            case SA_KEY_GENERATE:
                status = ta_invoke_key_generate(params, context, &uuid);
                break;

            case SA_KEY_EXPORT:
                status = ta_invoke_key_export(params, context, &uuid);
                break;

            case SA_KEY_IMPORT:
                status = ta_invoke_key_import(params, context, &uuid);
                break;

            case SA_KEY_UNWRAP:
                status = ta_invoke_key_unwrap(params, context, &uuid);
                break;

            case SA_KEY_GET_PUBLIC:
                status = ta_invoke_key_get_public(params, context, &uuid);
                break;

            case SA_KEY_DERIVE:
                status = ta_invoke_key_derive(params, context, &uuid);
                break;

            case SA_KEY_EXCHANGE:
                status = ta_invoke_key_exchange(params, context, &uuid);
                break;

            case SA_KEY_RELEASE:
                status = ta_invoke_key_release(params, context, &uuid);
                break;

            case SA_KEY_HEADER:
                status = ta_invoke_key_header(params, context, &uuid);
                break;

            case SA_KEY_DIGEST:
                status = ta_invoke_key_digest(params, context, &uuid);
                break;

            case SA_CRYPTO_RANDOM:
                status = ta_invoke_crypto_random(params, context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_INIT:
                status = ta_invoke_crypto_cipher_init(params, context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_UPDATE_IV:
                status = ta_invoke_crypto_cipher_update_iv(params, context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_PROCESS:
                status = ta_invoke_crypto_cipher_process(false, params, context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_PROCESS_LAST:
                status = ta_invoke_crypto_cipher_process(true, params, context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_RELEASE:
                status = ta_invoke_crypto_cipher_release(params, context, &uuid);
                break;

            case SA_CRYPTO_MAC_INIT:
                status = ta_invoke_crypto_mac_init(params, context, &uuid);
                break;

            case SA_CRYPTO_MAC_PROCESS:
                status = ta_invoke_crypto_mac_process(params, context, &uuid);
                break;

            case SA_CRYPTO_MAC_PROCESS_KEY:
                status = ta_invoke_crypto_mac_process_key(params, context, &uuid);
                break;

            case SA_CRYPTO_MAC_COMPUTE:
                status = ta_invoke_crypto_mac_compute(params, context, &uuid);
                break;

            case SA_CRYPTO_MAC_RELEASE:
                status = ta_invoke_crypto_mac_release(params, context, &uuid);
                break;

            case SA_CRYPTO_SIGN:
                status = ta_invoke_crypto_sign(params, context, &uuid);
                break;

            case SA_SVP_SUPPORTED:
                status = ta_sa_svp_supported(context->client, &uuid);
                break;

            case SA_SVP_BUFFER_CREATE:
                status = ta_invoke_svp_buffer_create(params, context, &uuid);
                break;

            case SA_SVP_BUFFER_RELEASE:
                status = ta_invoke_svp_buffer_release(params, context, &uuid);
                break;

            case SA_SVP_BUFFER_WRITE:
                status = ta_invoke_svp_buffer_write(params, context, &uuid);
                break;

            case SA_SVP_BUFFER_COPY:
                status = ta_invoke_svp_buffer_copy(params, context, &uuid);
                break;

            case SA_SVP_KEY_CHECK:
                status = ta_invoke_svp_key_check(params, context, &uuid);
                break;

            case SA_SVP_BUFFER_CHECK:
                status = ta_invoke_svp_buffer_check(params, context, &uuid);
                break;

            case SA_PROCESS_COMMON_ENCRYPTION:
                status = ta_invoke_process_common_encryption(params, context, &uuid);
                break;

            default:
                status = SA_STATUS_OPERATION_NOT_SUPPORTED;
        }
    } while (false);

    return status;
}

sa_status ta_open_session_handler(void** session_context) {

    if (session_context == NULL) {
        return SA_STATUS_BAD_PARAMETER;
    }

    ta_session_context* context = malloc(sizeof(ta_session_context));
    if (context == NULL) {
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_uuid uuid;
    sa_status status = transport_authenticate_caller(&uuid);
    if (status != SA_STATUS_OK) {
        ERROR("transport_authenticate_caller failed: %d", status);
        free(context);
        return status;
    }

    status = ta_sa_init(&context->client, &uuid);
    if (status != SA_STATUS_OK) {
        ERROR("ta_sa_init failed");
        free(context);
        return status;
    }

    *session_context = context;
    return SA_STATUS_OK;
}

void ta_close_session_handler(void* session_context) {

    ta_session_context* context = session_context;

    do {
        sa_uuid uuid;
        sa_status status = transport_authenticate_caller(&uuid);
        if (status != SA_STATUS_OK) {
            ERROR("transport_authenticate_caller failed: %d", status);
            break;
        }

        if (ta_sa_close(context->client, &uuid) != SA_STATUS_OK) {
            ERROR("ta_sa_close failed");
        }
    } while (false);

    free(context);
}
