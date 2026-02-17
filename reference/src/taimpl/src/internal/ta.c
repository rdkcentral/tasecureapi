/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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
#include "porting/memory.h"
#include "porting/transport.h"
#include "ta_sa.h"
#include <memory.h>
#include <stdbool.h>
#include <stdlib.h>

#define CHECK_NOT_TA_PARAM_NULL(param_type, param) ((param_type) != TEEC_NONE || (param).mem_ref != NULL || \
                                                    (param).mem_ref_size != 0)
#define CHECK_TA_PARAM_NULL(param_type, param) ((param_type) == TEEC_NONE || (param).mem_ref == NULL || \
                                                (param).mem_ref_size == 0)
#define CHECK_NOT_TA_PARAM_IN(param_type) ((param_type) != TEEC_MEMREF_TEMP_INPUT && \
                                           (param_type) != TEEC_MEMREF_PARTIAL_INPUT)
#define CHECK_TA_PARAM_IN(param_type) ((param_type) == TEEC_MEMREF_TEMP_INPUT || \
                                       (param_type) == TEEC_MEMREF_PARTIAL_INPUT)
#define CHECK_NOT_TA_PARAM_OUT(param_type) ((param_type) != TEEC_MEMREF_TEMP_OUTPUT && \
                                            (param_type) != TEEC_MEMREF_PARTIAL_OUTPUT)
#define CHECK_NOT_TA_PARAM_INOUT(param_type) ((param_type) != TEEC_MEMREF_TEMP_INOUT && \
                                              (param_type) != TEEC_MEMREF_PARTIAL_INOUT)
#define CHECK_TA_PARAM_INOUT(param_type) ((param_type) == TEEC_MEMREF_TEMP_INOUT || \
                                          (param_type) == TEEC_MEMREF_PARTIAL_INOUT)

typedef struct {
    ta_client client;
} ta_session_context;

static sa_status ta_invoke_get_version(
        sa_get_version_s* get_version,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_get_version_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (get_version->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_get_version(&get_version->version, context->client, uuid);
}

static sa_status ta_invoke_get_name(
        sa_get_name_s* get_name,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_get_name_s) ||
            (CHECK_NOT_TA_PARAM_OUT(param_types[1]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) &&
            params[1].mem_ref_size != get_name->name_length) {
        ERROR("Invalid params[1].mem_ref_size");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (get_name->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    size_t name_length = get_name->name_length;
    sa_status status = ta_sa_get_name((char*) params[1].mem_ref, &name_length, context->client, uuid);
    get_name->name_length = name_length;
    return status;
}

static sa_status ta_invoke_get_device_id(
        sa_get_device_id_s* get_device_id,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_get_device_id_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (get_device_id->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_get_device_id(&get_device_id->id, context->client, uuid);
}

static sa_status ta_invoke_get_ta_uuid(
        sa_get_ta_uuid_s* get_ta_uuid,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_get_ta_uuid_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (get_ta_uuid->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_get_ta_uuid(&get_ta_uuid->uuid, context->client, uuid);
}

static sa_status ta_invoke_key_generate(
        sa_key_generate_s* key_generate,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_generate_s) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[1]) && CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) && CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_generate->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

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
            if (params[1].mem_ref == NULL ||
                    params[2].mem_ref == NULL) {
                ERROR("NULL params[x].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

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
        sa_key_export_s* key_export,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_export_s) ||
            (CHECK_NOT_TA_PARAM_OUT(param_types[1]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) &&
            params[1].mem_ref_size != key_export->out_length) {
        ERROR("Invalid params[1].mem_ref_size");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_export->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    size_t out_length = key_export->out_length;
    sa_status status = ta_sa_key_export(params[1].mem_ref, &out_length, params[2].mem_ref, params[2].mem_ref_size,
            key_export->key, context->client, uuid);
    key_export->out_length = out_length;
    return status;
}

static sa_status ta_invoke_key_import(
        sa_key_import_s* key_import,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_import_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) && CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0) {
        ERROR("NULL param[1]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_import->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_rights rights;
    sa_import_parameters_symmetric parameters_symmetric;
    sa_import_parameters_rsa_private_key_info parameters_rsa;
    sa_import_parameters_ec_private_bytes parameters_ec;
    sa_import_parameters_typej parameters_typej;
    sa_import_parameters_soc parameters_soc;
    void* parameters = NULL;
    switch (key_import->key_format) {
        case SA_KEY_FORMAT_SYMMETRIC_BYTES:
            if (CHECK_NOT_TA_PARAM_IN(param_types[2]) || params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_rights)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&rights, params[2].mem_ref, params[2].mem_ref_size);
            parameters_symmetric.rights = &rights;
            parameters = &parameters_symmetric;
            break;

        case SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO:
            if (CHECK_NOT_TA_PARAM_IN(param_types[2]) || params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_rights)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&rights, params[2].mem_ref, params[2].mem_ref_size);
            parameters_rsa.rights = &rights;
            parameters = &parameters_rsa;
            break;

        case SA_KEY_FORMAT_EC_PRIVATE_BYTES:
            if (CHECK_NOT_TA_PARAM_IN(param_types[2]) || params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_rights)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&rights, params[2].mem_ref, params[2].mem_ref_size);
            parameters_ec.rights = &rights;
            parameters_ec.curve = key_import->curve;
            parameters = &parameters_ec;
            break;

        case SA_KEY_FORMAT_EXPORTED:
            if (CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            parameters = NULL;
            break;

        case SA_KEY_FORMAT_TYPEJ:
            if (CHECK_NOT_TA_PARAM_IN(param_types[2]) || params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_import_parameters_typej)) {
                ERROR("params[2].mem_ref_size is invalid");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&parameters_typej, params[2].mem_ref, params[2].mem_ref_size);
            parameters = &parameters_typej;
            break;

        case SA_KEY_FORMAT_SOC:
            // params[2].mem_ref can be null.
            if (CHECK_TA_PARAM_IN(param_types[2])) {
                if (params[2].mem_ref == NULL || params[2].mem_ref_size == 0) {
                    ERROR("NULL params[2].mem_ref");
                    return SA_STATUS_NULL_PARAMETER;
                }

                if (params[2].mem_ref_size > sizeof(sa_import_parameters_soc)) {
                    ERROR("Invalid params[2].mem_ref_size");
                    return SA_STATUS_INVALID_PARAMETER;
                }

                memcpy(&parameters_soc, params[2].mem_ref, params[2].mem_ref_size);
                parameters = &parameters_soc;
            }

            break;

        default:
            parameters = NULL;
    }

    return ta_sa_key_import(&key_import->key, key_import->key_format, params[1].mem_ref, params[1].mem_ref_size,
            parameters, context->client, uuid);
}

static sa_status ta_invoke_key_provision(
        sa_key_provision_ta_s* key_provision_ta,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
        params[0].mem_ref_size != sizeof(sa_key_provision_ta_s) ||
        CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
        (CHECK_NOT_TA_PARAM_IN(param_types[2]) && CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
        (CHECK_NOT_TA_PARAM_IN(param_types[3]) && CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3]))) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0) {
        ERROR("NULL param[1]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_provision_ta->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_provision_ta->key_format != SA_KEY_FORMAT_PROVISION_TA) {
        ERROR("Invalid key format");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_import_parameters_soc parameters_soc;
    void* parameters = NULL;
    if (CHECK_TA_PARAM_IN(param_types[2])) {
        if (params[2].mem_ref == NULL || params[2].mem_ref_size == 0) {
            ERROR("NULL params[2].mem_ref");
            return SA_STATUS_NULL_PARAMETER;
        }

        if (params[2].mem_ref_size > sizeof(sa_import_parameters_soc)) {
            ERROR("Invalid params[2].mem_ref_size");
            return SA_STATUS_INVALID_PARAMETER;
        }

        memcpy(&parameters_soc, params[2].mem_ref, params[2].mem_ref_size);
        parameters = &parameters_soc;
    }

     sa_key_type_ta ta_key_type = (sa_key_type_ta)ULONG_MAX;
     if (CHECK_TA_PARAM_IN(param_types[3])) {
        if (params[3].mem_ref == NULL || params[3].mem_ref_size == 0) {
            ERROR("NULL params[3].mem_ref");
            return SA_STATUS_NULL_PARAMETER;
        }
        ta_key_type = *(int*)(params[3].mem_ref);
        INFO("ta_key_type: %d", ta_key_type);
     }

     const void*  ProvisioningObject = params[1].mem_ref;
     const size_t ProvisioningObjectLen = params[1].mem_ref_size;

     sa_status status = SA_STATUS_OK;
     status = ta_sa_key_provision(ta_key_type, ProvisioningObject,
         ProvisioningObjectLen, parameters, context->client, uuid);
     if (SA_STATUS_OK != status) {
         ERROR("ta_sa_key_provision failed");
	 return status;
     }

     return status;
}

static sa_status ta_invoke_key_unwrap(
        sa_key_unwrap_s* key_unwrap,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_unwrap_s) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[1]) && CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) && CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[3]) && CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3]))) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_unwrap->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    void* type_parameters;
    sa_unwrap_type_parameters_ec type_parameters_ec = {key_unwrap->curve};
    if (key_unwrap->key_type == SA_KEY_TYPE_EC) {
        type_parameters = &type_parameters_ec;
    } else {
        type_parameters = NULL;
    }

    void* algorithm_parameters;
    sa_unwrap_parameters_aes_iv_s parameters_aes_iv_s;
    sa_unwrap_parameters_aes_gcm_s parameters_aes_gcm_s;
    sa_unwrap_parameters_chacha20_s parameters_chacha_20_s;
    sa_unwrap_parameters_chacha20_poly1305_s parameters_chacha_20_poly_1305_s;
    sa_unwrap_parameters_ec_elgamal_s parameters_ec_elgamal_s;
    sa_unwrap_parameters_rsa_oaep_s parameters_rsa_oaep_s;
    sa_unwrap_parameters_aes_cbc parameters_aes_cbc;
    sa_unwrap_parameters_aes_ctr parameters_aes_ctr;
    sa_unwrap_parameters_aes_gcm parameters_aes_gcm;
    sa_unwrap_parameters_chacha20 parameters_chacha20;
    sa_unwrap_parameters_chacha20_poly1305 parameters_chacha20_poly1305;
    sa_unwrap_parameters_ec_elgamal parameters_ec_elgamal;
    sa_unwrap_parameters_rsa_oaep parameters_rsa_oaep;
    switch (key_unwrap->cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_aes_iv_s)) {
                ERROR("params[2].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&parameters_aes_iv_s, params[2].mem_ref, params[2].mem_ref_size);
            parameters_aes_cbc.iv = &parameters_aes_iv_s.iv;
            parameters_aes_cbc.iv_length = sizeof(parameters_aes_iv_s.iv);
            algorithm_parameters = &parameters_aes_cbc;
            break;

        case SA_CIPHER_ALGORITHM_AES_CTR:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_aes_iv_s)) {
                ERROR("params[2].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&parameters_aes_iv_s, params[2].mem_ref, params[2].mem_ref_size);
            parameters_aes_ctr.ctr = &parameters_aes_iv_s.iv;
            parameters_aes_ctr.ctr_length = sizeof(parameters_aes_iv_s.iv);
            algorithm_parameters = &parameters_aes_ctr;
            break;

        case SA_CIPHER_ALGORITHM_AES_GCM:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_aes_gcm_s)) {
                ERROR("params[2].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            if (params[3].mem_ref == NULL) {
                ERROR("NULL params[3].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            memcpy(&parameters_aes_gcm_s, params[2].mem_ref, params[2].mem_ref_size);
            parameters_aes_gcm.iv = &parameters_aes_gcm_s.iv;
            parameters_aes_gcm.iv_length = parameters_aes_gcm_s.iv_length;
            parameters_aes_gcm.aad = params[3].mem_ref;
            parameters_aes_gcm.aad_length = params[3].mem_ref_size;
            parameters_aes_gcm.tag = &parameters_aes_gcm_s.tag;
            parameters_aes_gcm.tag_length = parameters_aes_gcm_s.tag_length;
            algorithm_parameters = &parameters_aes_gcm;
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_chacha20_s)) {
                ERROR("params[2].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&parameters_chacha_20_s, params[2].mem_ref, params[2].mem_ref_size);
            parameters_chacha20.counter = &parameters_chacha_20_s.counter;
            parameters_chacha20.counter_length = parameters_chacha_20_s.counter_length;
            parameters_chacha20.nonce = &parameters_chacha_20_s.nonce;
            parameters_chacha20.nonce_length = parameters_chacha_20_s.nonce_length;
            algorithm_parameters = &parameters_chacha20;
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_chacha20_poly1305_s)) {
                ERROR("params[2].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            if (params[3].mem_ref == NULL) {
                ERROR("NULL params[3].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            memcpy(&parameters_chacha_20_poly_1305_s, params[2].mem_ref, params[2].mem_ref_size);
            parameters_chacha20_poly1305.nonce = &parameters_chacha_20_poly_1305_s.nonce;
            parameters_chacha20_poly1305.nonce_length = parameters_chacha_20_poly_1305_s.nonce_length;
            parameters_chacha20_poly1305.aad = params[3].mem_ref;
            parameters_chacha20_poly1305.aad_length = params[3].mem_ref_size;
            parameters_chacha20_poly1305.tag = &parameters_chacha_20_poly_1305_s.tag;
            parameters_chacha20_poly1305.tag_length = parameters_chacha_20_poly_1305_s.tag_length;
            algorithm_parameters = &parameters_chacha20_poly1305;
            break;

        case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_ec_elgamal_s)) {
                ERROR("params[2].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            // Fix for 32-bit platforms: convert uint64_t fields to size_t
            memcpy(&parameters_ec_elgamal_s, params[2].mem_ref, params[2].mem_ref_size);
            parameters_ec_elgamal.offset = (size_t)parameters_ec_elgamal_s.offset;
            parameters_ec_elgamal.key_length = (size_t)parameters_ec_elgamal_s.key_length;
            algorithm_parameters = &parameters_ec_elgamal;
            break;

        case SA_CIPHER_ALGORITHM_RSA_OAEP:
            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref_size != sizeof(sa_unwrap_parameters_rsa_oaep_s)) {
                ERROR("params[2].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&parameters_rsa_oaep_s, params[2].mem_ref, params[2].mem_ref_size);
            parameters_rsa_oaep.digest_algorithm = parameters_rsa_oaep_s.digest_algorithm;
            parameters_rsa_oaep.mgf1_digest_algorithm = parameters_rsa_oaep_s.mgf1_digest_algorithm;
            parameters_rsa_oaep.label = params[3].mem_ref;
            parameters_rsa_oaep.label_length = params[3].mem_ref_size;
            algorithm_parameters = &parameters_rsa_oaep;
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
        sa_key_get_public_s* key_get_public,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_get_public_s) ||
            (CHECK_NOT_TA_PARAM_OUT(param_types[1]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) &&
            params[1].mem_ref_size != key_get_public->out_length) {
        ERROR("Invalid params[1].mem_ref_size");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_get_public->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    size_t out_length = key_get_public->out_length;
    sa_status status = ta_sa_key_get_public(params[1].mem_ref, &out_length, key_get_public->key,
            context->client, uuid);
    key_get_public->out_length = out_length;
    return status;
}

static sa_status ta_invoke_key_derive(
        sa_key_derive_s* key_derive,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_derive_s) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[1]) && CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) && CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[3]) && CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3]))) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_derive->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    void* algorithm_parameters;
    sa_kdf_parameters_root_key_ladder_s parameters_root_key_ladder_s;
    sa_kdf_parameters_hkdf_s parameters_hkdf_s;
    sa_kdf_parameters_concat_s parameters_concat_s;
    sa_kdf_parameters_ansi_x963_s parameters_ansi_x963_s;
    sa_kdf_parameters_cmac_s parameters_cmac_s;
    sa_kdf_parameters_root_key_ladder parameters_root_key_ladder;
    sa_kdf_parameters_hkdf parameters_hkdf;
    sa_kdf_parameters_concat parameters_concat;
    sa_kdf_parameters_ansi_x963 parameters_ansi_x963;
    sa_kdf_parameters_cmac parameters_cmac;
    sa_kdf_parameters_netflix parameters_netflix;
    switch (key_derive->kdf_algorithm) {
        case SA_KDF_ALGORITHM_ROOT_KEY_LADDER:
        case SA_KDF_ALGORITHM_COMMON_ROOT_KEY_LADDER: {
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[1].mem_ref_size > sizeof(parameters_root_key_ladder_s)) {
                ERROR("Invalid params[1].mem_ref_size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&parameters_root_key_ladder_s, params[1].mem_ref, params[1].mem_ref_size);
            parameters_root_key_ladder.c1 = parameters_root_key_ladder_s.c1;
            parameters_root_key_ladder.c1_length = AES_BLOCK_SIZE;
            parameters_root_key_ladder.c2 = parameters_root_key_ladder_s.c2;
            parameters_root_key_ladder.c2_length = AES_BLOCK_SIZE;
            parameters_root_key_ladder.c3 = parameters_root_key_ladder_s.c3;
            parameters_root_key_ladder.c3_length = AES_BLOCK_SIZE;
            parameters_root_key_ladder.c4 = parameters_root_key_ladder_s.c4;
            parameters_root_key_ladder.c4_length = AES_BLOCK_SIZE;
            algorithm_parameters = &parameters_root_key_ladder;
            break;
        }
        case SA_KDF_ALGORITHM_HKDF: {
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[1].mem_ref_size > sizeof(parameters_hkdf_s)) {
                ERROR("Invalid params[1].mem_ref_size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            // params[2].mem_ref and params[3].mem_ref can be null.
            memcpy(&parameters_hkdf_s, params[1].mem_ref, params[1].mem_ref_size);
            parameters_hkdf.key_length = parameters_hkdf_s.key_length;
            parameters_hkdf.digest_algorithm = parameters_hkdf_s.digest_algorithm;
            parameters_hkdf.parent = parameters_hkdf_s.parent;
            parameters_hkdf.salt = params[3].mem_ref;
            parameters_hkdf.salt_length = params[3].mem_ref_size;
            parameters_hkdf.info = params[2].mem_ref;
            parameters_hkdf.info_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_hkdf;
            break;
        }
        case SA_KDF_ALGORITHM_CONCAT: {
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[1].mem_ref_size > sizeof(parameters_concat_s)) {
                ERROR("Invalid params[1].mem_ref_size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            // params[2].mem_ref can be null.
            memcpy(&parameters_concat_s, params[1].mem_ref, params[1].mem_ref_size);
            parameters_concat.key_length = parameters_concat_s.key_length;
            parameters_concat.digest_algorithm = parameters_concat_s.digest_algorithm;
            parameters_concat.parent = parameters_concat_s.parent;
            parameters_concat.info = params[2].mem_ref;
            parameters_concat.info_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_concat;
            break;
        }
        case SA_KDF_ALGORITHM_ANSI_X963: {
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[1].mem_ref_size > sizeof(parameters_ansi_x963_s)) {
                ERROR("Invalid params[1].mem_ref_size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            // params[2].mem_ref can be null.
            memcpy(&parameters_ansi_x963_s, params[1].mem_ref, params[1].mem_ref_size);
            parameters_ansi_x963.key_length = parameters_ansi_x963_s.key_length;
            parameters_ansi_x963.digest_algorithm = parameters_ansi_x963_s.digest_algorithm;
            parameters_ansi_x963.parent = parameters_ansi_x963_s.parent;
            parameters_ansi_x963.info = params[2].mem_ref;
            parameters_ansi_x963.info_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_ansi_x963;
            break;
        }
        case SA_KDF_ALGORITHM_CMAC: {
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[1].mem_ref_size > sizeof(parameters_cmac_s)) {
                ERROR("Invalid params[1].mem_ref_size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            // params[2].mem_ref can be null.
            memcpy(&parameters_cmac_s, params[1].mem_ref, params[1].mem_ref_size);
            parameters_cmac.key_length = parameters_cmac_s.key_length;
            parameters_cmac.counter = parameters_cmac_s.counter;
            parameters_cmac.parent = parameters_cmac_s.parent;
            parameters_cmac.other_data = params[2].mem_ref;
            parameters_cmac.other_data_length = params[2].mem_ref_size;
            algorithm_parameters = &parameters_cmac;
            break;
        }
        case SA_KDF_ALGORITHM_NETFLIX: {
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[1].mem_ref_size > sizeof(parameters_netflix)) {
                ERROR("Invalid params[1].mem_ref_size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            memcpy(&parameters_netflix, params[1].mem_ref, params[1].mem_ref_size);
            algorithm_parameters = &parameters_netflix;
            break;
        }
        default:
            return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_key_derive(&key_derive->key, &key_derive->rights, key_derive->kdf_algorithm, algorithm_parameters,
            context->client, uuid);
}

static sa_status ta_invoke_key_exchange(
        sa_key_exchange_s* key_exchange,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_exchange_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            (CHECK_NOT_TA_PARAM_INOUT(param_types[2]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0) {
        ERROR("NULL param[1]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (key_exchange->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_key_exchange_parameters_netflix_authenticated_dh_s netflix_authenticated_dh_s;
    sa_key_exchange_parameters_netflix_authenticated_dh netflix_authenticated_dh;
    void* parameters = NULL;
    if (key_exchange->key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH) {
        if (params[2].mem_ref == NULL) {
            ERROR("NULL params[2].mem_ref");
            return SA_STATUS_NULL_PARAMETER;
        }

        if (params[2].mem_ref_size != sizeof(sa_key_exchange_parameters_netflix_authenticated_dh_s)) {
            ERROR("params[2].mem_ref_size is invalid");
            return SA_STATUS_INVALID_PARAMETER;
        }

        memcpy(&netflix_authenticated_dh_s, params[2].mem_ref, params[2].mem_ref_size);
        netflix_authenticated_dh.in_kw = netflix_authenticated_dh_s.in_kw;
        netflix_authenticated_dh.out_ke = &netflix_authenticated_dh_s.out_ke;
        netflix_authenticated_dh.rights_ke = &netflix_authenticated_dh_s.rights_ke;
        netflix_authenticated_dh.out_kh = &netflix_authenticated_dh_s.out_kh;
        netflix_authenticated_dh.rights_kh = &netflix_authenticated_dh_s.rights_kh;
        parameters = &netflix_authenticated_dh;
    }

    sa_status status = ta_sa_key_exchange(&key_exchange->key, &key_exchange->rights,
            key_exchange->key_exchange_algorithm, key_exchange->private_key, params[1].mem_ref, params[1].mem_ref_size,
            parameters, context->client, uuid);
    if (key_exchange->key_exchange_algorithm == SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH)
        memcpy(params[2].mem_ref, &netflix_authenticated_dh_s, params[2].mem_ref_size);

    return status;
}

static sa_status ta_invoke_key_release(
        sa_key_release_s* key_release,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_release_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_release->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_key_release(key_release->key, context->client, uuid);
}

static sa_status ta_invoke_key_header(
        sa_key_header_s* key_header,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_header_s) ||
            CHECK_NOT_TA_PARAM_OUT(param_types[1]) || params[1].mem_ref_size != sizeof(sa_header_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_header->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_header header;
    memory_memset_unoptimizable(&header, 0, sizeof(sa_header));
    sa_status status = ta_sa_key_header(&header, key_header->key, context->client, uuid);
    sa_header_s* header_s = params[1].mem_ref;
    memory_memset_unoptimizable(header_s, 0, sizeof(sa_header_s));
    memcpy(header_s->magic, header.magic, NUM_MAGIC);
    memcpy(&header_s->rights, &header.rights, sizeof(sa_rights));
    header_s->type = header.type;
    header_s->size = header.size;
    if (header.type == SA_KEY_TYPE_EC) {
        header_s->type_parameters.curve = header.type_parameters.curve;
    } else if (header.type == SA_KEY_TYPE_DH) {
        memcpy(header_s->type_parameters.dh_parameters.p, header.type_parameters.dh_parameters.p, DH_MAX_MOD_SIZE);
        header_s->type_parameters.dh_parameters.p_length = header.type_parameters.dh_parameters.p_length;
        memcpy(header_s->type_parameters.dh_parameters.g, header.type_parameters.dh_parameters.g, DH_MAX_MOD_SIZE);
        header_s->type_parameters.dh_parameters.g_length = header.type_parameters.dh_parameters.g_length;
    }

    return status;
}

static sa_status ta_invoke_key_digest(
        sa_key_digest_s* key_digest,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_key_digest_s) ||
            (CHECK_NOT_TA_PARAM_OUT(param_types[1]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) && params[1].mem_ref_size != key_digest->out_length) {
        ERROR("Invalid params[1].mem_ref_size");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (key_digest->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    size_t out_length = key_digest->out_length;
    sa_status status = ta_sa_key_digest(params[1].mem_ref, &out_length, key_digest->key,
            key_digest->digest_algorithm, context->client, uuid);
    key_digest->out_length = out_length;
    return status;
}

static sa_status ta_invoke_crypto_random(
        sa_crypto_random_s* crypto_random,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) || params[0].mem_ref_size != sizeof(sa_crypto_random_s) ||
            CHECK_NOT_TA_PARAM_OUT(param_types[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0) {
        ERROR("NULL param[1]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[1].mem_ref == NULL) {
        ERROR("NULL params[x].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (crypto_random->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_crypto_random(params[1].mem_ref, params[1].mem_ref_size, context->client, uuid);
}

static sa_status ta_invoke_crypto_cipher_init(
        sa_crypto_cipher_init_s* crypto_cipher_init,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_cipher_init_s) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[1]) && CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) && CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[3]) && CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3]))) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_cipher_init->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_cipher_parameters_rsa_oaep_s parameters_rsa_oaep_s;
    sa_cipher_parameters_aes_cbc parameters_aes_cbc;
    sa_cipher_parameters_aes_ctr parameters_aes_ctr;
    sa_cipher_parameters_aes_gcm parameters_aes_gcm;
    sa_cipher_parameters_chacha20 parameters_chacha20;
    sa_cipher_parameters_chacha20_poly1305 parameters_chacha20_poly1305;
    sa_cipher_parameters_rsa_oaep parameters_rsa_oaep;
    void* parameters;
    switch (crypto_cipher_init->cipher_algorithm) {
        case SA_CIPHER_ALGORITHM_AES_CBC:
        case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            parameters_aes_cbc.iv = params[1].mem_ref;
            parameters_aes_cbc.iv_length = params[1].mem_ref_size;
            parameters = &parameters_aes_cbc;
            break;

        case SA_CIPHER_ALGORITHM_AES_CTR:
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            parameters_aes_ctr.ctr = params[1].mem_ref;
            parameters_aes_ctr.ctr_length = params[1].mem_ref_size;
            parameters = &parameters_aes_ctr;
            break;

        case SA_CIPHER_ALGORITHM_AES_GCM:
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            // params[2].mem_ref can be NULL
            parameters_aes_gcm.iv = params[1].mem_ref;
            parameters_aes_gcm.iv_length = params[1].mem_ref_size;
            parameters_aes_gcm.aad = params[2].mem_ref;
            parameters_aes_gcm.aad_length = params[2].mem_ref_size;
            parameters = &parameters_aes_gcm;
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20:
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[2].mem_ref == NULL) {
                ERROR("NULL params[2].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            parameters_chacha20.nonce = params[1].mem_ref;
            parameters_chacha20.nonce_length = params[1].mem_ref_size;
            parameters_chacha20.counter = params[2].mem_ref;
            parameters_chacha20.counter_length = params[2].mem_ref_size;
            parameters = &parameters_chacha20;
            break;

        case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            // params[2].mem_ref can be NULL
            parameters_chacha20_poly1305.nonce = params[1].mem_ref;
            parameters_chacha20_poly1305.nonce_length = params[1].mem_ref_size;
            parameters_chacha20_poly1305.aad = params[2].mem_ref;
            parameters_chacha20_poly1305.aad_length = params[2].mem_ref_size;
            parameters = &parameters_chacha20_poly1305;
            break;

        case SA_CIPHER_ALGORITHM_RSA_OAEP:
            if (params[1].mem_ref == NULL) {
                ERROR("NULL params[1].mem_ref");
                return SA_STATUS_NULL_PARAMETER;
            }

            if (params[1].mem_ref_size != sizeof(sa_cipher_parameters_rsa_oaep_s)) {
                ERROR("params[1].mem_ref is invalid size");
                return SA_STATUS_INVALID_PARAMETER;
            }

            // params[2].mem_ref can be NULL
            memcpy(&parameters_rsa_oaep_s, params[1].mem_ref, params[1].mem_ref_size);
            parameters_rsa_oaep.digest_algorithm = parameters_rsa_oaep_s.digest_algorithm;
            parameters_rsa_oaep.mgf1_digest_algorithm = parameters_rsa_oaep_s.mgf1_digest_algorithm;
            parameters_rsa_oaep.label = params[2].mem_ref;
            parameters_rsa_oaep.label_length = params[2].mem_ref_size;
            parameters = &parameters_rsa_oaep;
            break;

        default:
            parameters = NULL;
            break;
    }

    return ta_sa_crypto_cipher_init(&crypto_cipher_init->context, crypto_cipher_init->cipher_algorithm,
            crypto_cipher_init->cipher_mode, crypto_cipher_init->key, parameters, context->client, uuid);
}

static sa_status ta_invoke_crypto_cipher_update_iv(
        sa_crypto_cipher_update_iv_s* cipher_update_iv,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_cipher_update_iv_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0) {
        ERROR("NULL param[1]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[1].mem_ref == NULL) {
        ERROR("NULL params[x].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (cipher_update_iv->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_crypto_cipher_update_iv(cipher_update_iv->context, params[1].mem_ref, params[1].mem_ref_size,
            context->client, uuid);
}
static sa_status ta_invoke_crypto_cipher_process(
        bool last,
        sa_crypto_cipher_process_s* crypto_cipher_process,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_cipher_process_s) ||
            (CHECK_TA_PARAM_INOUT(param_types[1]) && CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            CHECK_NOT_TA_PARAM_IN(param_types[2]) ||
            (CHECK_NOT_TA_PARAM_INOUT(param_types[3]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3]))) {
        ERROR("Invalid param[0] or param[2] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    // params[2].mem_ref_size can be 0.
    if (params[2].mem_ref == NULL) {
        ERROR("NULL params[2].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (crypto_cipher_process->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_buffer out;
    out.buffer_type = crypto_cipher_process->out_buffer_type;
    if (crypto_cipher_process->out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        out.context.clear.buffer = params[1].mem_ref;
        out.context.clear.length = params[1].mem_ref_size;
        out.context.clear.offset = crypto_cipher_process->out_offset;
    } 
#ifdef ENABLE_SVP
    else if (crypto_cipher_process->out_buffer_type == SA_BUFFER_TYPE_SVP) {
        out.context.svp.buffer = *(sa_svp_buffer*) params[1].mem_ref;
        out.context.svp.offset = crypto_cipher_process->out_offset;
    }
#endif // ENABLE_SVP

    sa_buffer in;
    in.buffer_type = crypto_cipher_process->in_buffer_type;
    if (crypto_cipher_process->in_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        in.context.clear.buffer = params[2].mem_ref;
        in.context.clear.length = params[2].mem_ref_size;
        in.context.clear.offset = crypto_cipher_process->in_offset;
    } 
#ifdef ENABLE_SVP
    else if (crypto_cipher_process->in_buffer_type == SA_BUFFER_TYPE_SVP) {
        in.buffer_type = crypto_cipher_process->in_buffer_type;
        in.context.svp.buffer = *(sa_svp_buffer*) params[2].mem_ref;
        in.context.svp.offset = crypto_cipher_process->in_offset;
    }
#endif // ENABLE_SVP

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

        size_t bytes_to_process = crypto_cipher_process->bytes_to_process;
        status = ta_sa_crypto_cipher_process_last(params[1].mem_ref == NULL ? NULL : &out,
                crypto_cipher_process->context, &in, &bytes_to_process, parameters, context->client, uuid);
        crypto_cipher_process->bytes_to_process = bytes_to_process;
    } else {
        size_t bytes_to_process = crypto_cipher_process->bytes_to_process;
        status = ta_sa_crypto_cipher_process(params[1].mem_ref == NULL ? NULL : &out, crypto_cipher_process->context,
                &in, &bytes_to_process, context->client, uuid);
        crypto_cipher_process->bytes_to_process = bytes_to_process;
    }

    // clang-format off
    if (params[1].mem_ref != NULL) {
#ifdef ENABLE_SVP
        crypto_cipher_process->out_offset = (crypto_cipher_process->out_buffer_type == SA_BUFFER_TYPE_CLEAR)
                                             ? out.context.clear.offset : out.context.svp.offset;
#else
        crypto_cipher_process->out_offset = out.context.clear.offset;
#endif // ENABLE_SVP
    }

#ifdef ENABLE_SVP
    crypto_cipher_process->in_offset = (crypto_cipher_process->in_buffer_type == SA_BUFFER_TYPE_CLEAR)
                                               ? in.context.clear.offset : in.context.svp.offset;
#else
    crypto_cipher_process->in_offset = in.context.clear.offset;
#endif // ENABLE_SVP
    // clang-format on
    return status;
}

static sa_status ta_invoke_crypto_cipher_release(
        sa_crypto_cipher_release_s* crypto_cipher_release,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_cipher_release_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_cipher_release->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_crypto_cipher_release(crypto_cipher_release->cipher_context, context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_init(
        sa_crypto_mac_init_s* crypto_mac_init,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_mac_init_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_mac_init->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    void* parameters;
    sa_mac_parameters_hmac mac_parameters_hmac;
    if (crypto_mac_init->mac_algorithm == SA_MAC_ALGORITHM_HMAC) {
        mac_parameters_hmac.digest_algorithm = crypto_mac_init->digest_algorithm;
        parameters = &mac_parameters_hmac;
    } else {
        parameters = NULL;
    }

    return ta_sa_crypto_mac_init(&crypto_mac_init->context, crypto_mac_init->mac_algorithm, crypto_mac_init->key,
            parameters, context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_process(
        sa_crypto_mac_process_s* crypto_mac_process,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_mac_process_s) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[1]) && CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_mac_process->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_crypto_mac_process(crypto_mac_process->mac_context, params[1].mem_ref, params[1].mem_ref_size,
            context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_process_key(
        sa_crypto_mac_process_key_s* crypto_mac_process_key,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_mac_process_key_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_mac_process_key->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_crypto_mac_process_key(crypto_mac_process_key->mac_context, crypto_mac_process_key->key,
            context->client, uuid);
}

static sa_status ta_invoke_crypto_mac_compute(
        sa_crypto_mac_compute_s* crypto_mac_compute,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_mac_compute_s) ||
            (CHECK_NOT_TA_PARAM_OUT(param_types[1]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) &&
            params[1].mem_ref_size != crypto_mac_compute->out_length) {
        ERROR("Invalid params[1].mem_ref_size");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_mac_compute->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    size_t out_length = crypto_mac_compute->out_length;
    sa_status status = ta_sa_crypto_mac_compute(params[1].mem_ref, &out_length, crypto_mac_compute->context,
            context->client, uuid);
    crypto_mac_compute->out_length = out_length;
    return status;
}

static sa_status ta_invoke_crypto_mac_release(
        sa_crypto_mac_release_s* crypto_mac_release,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_crypto_mac_release_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_mac_release->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_crypto_mac_release(crypto_mac_release->context, context->client, uuid);
}

static sa_status ta_invoke_crypto_sign(
        sa_crypto_sign_s* crypto_sign,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_crypto_sign_s) ||
            (CHECK_NOT_TA_PARAM_OUT(param_types[1]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1])) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) &&
                    CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2])) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) &&
            params[1].mem_ref_size != crypto_sign->out_length) {
        ERROR("Invalid params[1].mem_ref_size");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (crypto_sign->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_sign_parameters_rsa_pss parameters_rsa_pss;
    sa_sign_parameters_rsa_pkcs1v15 parameters_rsa_pkcs1v15;
    sa_sign_parameters_ecdsa parameters_ecdsa;
    void* parameters;
    switch (crypto_sign->signature_algorithm) {
        case SA_SIGNATURE_ALGORITHM_RSA_PSS:
            parameters_rsa_pss.digest_algorithm = crypto_sign->digest_algorithm;
            parameters_rsa_pss.mgf1_digest_algorithm = crypto_sign->mgf1_digest_algorithm;
            parameters_rsa_pss.precomputed_digest = crypto_sign->precomputed_digest;
            parameters_rsa_pss.salt_length = crypto_sign->salt_length;
            parameters = &parameters_rsa_pss;
            break;

        case SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15:
            parameters_rsa_pkcs1v15.digest_algorithm = crypto_sign->digest_algorithm;
            parameters_rsa_pkcs1v15.precomputed_digest = crypto_sign->precomputed_digest;
            parameters = &parameters_rsa_pkcs1v15;
            break;

        case SA_SIGNATURE_ALGORITHM_ECDSA:
            parameters_ecdsa.digest_algorithm = crypto_sign->digest_algorithm;
            parameters_ecdsa.precomputed_digest = crypto_sign->precomputed_digest;
            parameters = &parameters_ecdsa;
            break;

        default:
            parameters = NULL;
    }

    size_t out_length = crypto_sign->out_length;
    sa_status status = ta_sa_crypto_sign(params[1].mem_ref, &out_length, crypto_sign->signature_algorithm,
            crypto_sign->key, params[2].mem_ref, params[2].mem_ref_size, parameters, context->client, uuid);
    crypto_sign->out_length = out_length;
    return status;
}
static sa_status ta_invoke_svp_supported(
        sa_svp_supported_s* svp_supported,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) || params[0].mem_ref_size != sizeof(sa_svp_supported_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (svp_supported->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_svp_supported(context->client, uuid);
}

#ifdef ENABLE_SVP
static sa_status ta_invoke_svp_buffer_create(
        sa_svp_buffer_create_s* svp_buffer_create,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_svp_buffer_create_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (svp_buffer_create->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_svp_buffer_create(&svp_buffer_create->svp_buffer, (void*) svp_buffer_create->svp_memory, // NOLINT
            svp_buffer_create->size, context->client, uuid);
}
static sa_status ta_invoke_svp_buffer_release(
        sa_svp_buffer_release_s* svp_buffer_release,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_svp_buffer_release_s) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[1], params[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (svp_buffer_release->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    size_t release_size = svp_buffer_release->size;
    sa_status status = ta_sa_svp_buffer_release((void**) &svp_buffer_release->svp_memory, &release_size,
            svp_buffer_release->svp_buffer, context->client, uuid);
	svp_buffer_release->size = release_size;
	return status;
}

static sa_status ta_invoke_svp_buffer_write(
        sa_svp_buffer_write_s* svp_buffer_write,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_svp_buffer_write_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            CHECK_NOT_TA_PARAM_IN(param_types[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0 ||
            params[2].mem_ref == NULL || params[2].mem_ref_size == 0) {
        ERROR("NULL param[1] or param[2]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp_buffer_write->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    sa_svp_offset* offsets;
    do {
        size_t offsets_length = params[2].mem_ref_size / sizeof(sa_svp_offset_s);
        offsets = memory_secure_alloc(offsets_length * sizeof(sa_svp_offset));
        if (offsets == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        sa_svp_offset_s* offset_s = params[2].mem_ref;
        for (size_t i = 0; i < offsets_length; i++) {
            offsets[i].out_offset = offset_s[i].out_offset;
            offsets[i].in_offset = offset_s[i].in_offset;
            offsets[i].length = offset_s[i].length;
        }

        status = ta_sa_svp_buffer_write(svp_buffer_write->out, params[1].mem_ref, params[1].mem_ref_size,
                offsets, offsets_length, context->client, uuid);
    } while (false);

    if (offsets != NULL)
        memory_secure_free(offsets);

    return status;
}

static sa_status ta_invoke_svp_buffer_copy(
        sa_svp_buffer_copy_s* svp_buffer_copy,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_svp_buffer_copy_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0) {
        ERROR("NULL param[1]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp_buffer_copy->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    sa_svp_offset* offsets;
    do {
        size_t offsets_length = params[1].mem_ref_size / sizeof(sa_svp_offset_s);
        offsets = memory_secure_alloc(offsets_length * sizeof(sa_svp_offset));
        if (offsets == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        sa_svp_offset_s* offset_s = params[1].mem_ref;
        for (size_t i = 0; i < offsets_length; i++) {
            offsets[i].out_offset = offset_s[i].out_offset;
            offsets[i].in_offset = offset_s[i].in_offset;
            offsets[i].length = offset_s[i].length;
        }

        status = ta_sa_svp_buffer_copy(svp_buffer_copy->out, svp_buffer_copy->in,
                offsets, offsets_length, context->client, uuid);
    } while (false);

    if (offsets != NULL)
        memory_secure_free(offsets);

    return status;
}
static sa_status ta_invoke_svp_key_check(
        sa_svp_key_check_s* svp_key_check,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) || params[0].mem_ref_size != sizeof(sa_svp_key_check_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            CHECK_NOT_TA_PARAM_IN(param_types[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0 ||
            params[2].mem_ref == NULL || params[2].mem_ref_size == 0) {
        ERROR("NULL param[1] or param[2]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp_key_check->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_buffer in;
    in.buffer_type = svp_key_check->in_buffer_type;
    if (svp_key_check->in_buffer_type == SA_BUFFER_TYPE_CLEAR) {
        in.context.clear.buffer = params[1].mem_ref;
        in.context.clear.length = params[1].mem_ref_size;
        in.context.clear.offset = svp_key_check->in_offset;
    } 
    else if (svp_key_check->in_buffer_type == SA_BUFFER_TYPE_SVP) {
        in.buffer_type = svp_key_check->in_buffer_type;
        in.context.svp.buffer = *(sa_svp_buffer*) params[1].mem_ref;
        in.context.svp.offset = svp_key_check->in_offset;
    }

    sa_status status = ta_sa_svp_key_check(svp_key_check->key, &in, svp_key_check->bytes_to_process, params[2].mem_ref,
            params[2].mem_ref_size, context->client, uuid);
    svp_key_check->in_offset =
            (svp_key_check->in_buffer_type == SA_BUFFER_TYPE_CLEAR) ? in.context.clear.offset : in.context.svp.offset;
    svp_key_check->in_offset = svp_key_check->in_buffer_type = in.context.clear.offset;

    return status;
}

static sa_status ta_invoke_svp_buffer_check(
        sa_svp_buffer_check_s* svp_buffer_check,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_IN(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_svp_buffer_check_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[2], params[2]) ||
            CHECK_NOT_TA_PARAM_NULL(param_types[3], params[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[1].mem_ref_size == 0) {
        ERROR("NULL param[1]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[1].mem_ref == NULL) {
        ERROR("NULL params[x].mem_ref");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp_buffer_check->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return ta_sa_svp_buffer_check(svp_buffer_check->svp_buffer, svp_buffer_check->offset, svp_buffer_check->length,
            svp_buffer_check->digest_algorithm, params[1].mem_ref, params[1].mem_ref_size, context->client,
            uuid);
}
#endif // ENABLE_SVP

static sa_status ta_invoke_process_common_encryption(
        sa_process_common_encryption_s* process_common_encryption,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS],
        const ta_session_context* context,
        const sa_uuid* uuid) {

    if (CHECK_NOT_TA_PARAM_INOUT(param_types[0]) ||
            params[0].mem_ref_size != sizeof(sa_process_common_encryption_s) ||
            CHECK_NOT_TA_PARAM_IN(param_types[1]) ||
            (CHECK_NOT_TA_PARAM_IN(param_types[2]) && CHECK_NOT_TA_PARAM_OUT(param_types[2])) ||
            CHECK_NOT_TA_PARAM_IN(param_types[3])) {
        ERROR("Invalid param[0] or param type");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (params[1].mem_ref == NULL || params[2].mem_ref == NULL || params[3].mem_ref == NULL) {
        ERROR("NULL param[1] or param[2] or param[3]");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (params[1].mem_ref_size == 0 || params[2].mem_ref_size == 0 || params[3].mem_ref_size == 0) {
        ERROR("Invalid param[1] or param[2] or param[3] size");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (process_common_encryption->api_version != API_VERSION) {
        ERROR("Invalid api_version");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    sa_sample sample;
    do {
        sample.subsample_count = process_common_encryption->subsample_count;
        // Fix for 32-bit: client sends sa_subsample_length_s (uint64_t fields)
        if (params[1].mem_ref_size != sizeof(sa_subsample_length_s) * sample.subsample_count) {
            ERROR("params[1].mem_ref_size is invalid");
            return SA_STATUS_INVALID_PARAMETER;
        }

        sample.subsample_lengths =
                memory_secure_alloc(process_common_encryption->subsample_count * sizeof(sa_subsample_length));
        if (sample.subsample_lengths == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        sa_subsample_length_s* subsample_length_s = params[1].mem_ref;
        for (size_t j = 0; j < sample.subsample_count; j++) {
            sample.subsample_lengths[j].bytes_of_clear_data = subsample_length_s[j].bytes_of_clear_data;
            sample.subsample_lengths[j].bytes_of_protected_data = subsample_length_s[j].bytes_of_protected_data;
        }

        sample.iv = &process_common_encryption->iv;
        sample.iv_length = AES_BLOCK_SIZE;
        sample.crypt_byte_block = process_common_encryption->crypt_byte_block;
        sample.skip_byte_block = process_common_encryption->skip_byte_block;
        sample.context = process_common_encryption->context;

        sa_buffer out;
        sample.out = &out;
        out.buffer_type = process_common_encryption->out_buffer_type;
        if (process_common_encryption->out_buffer_type == SA_BUFFER_TYPE_CLEAR) {
            out.context.clear.buffer = params[2].mem_ref;
            out.context.clear.length = params[2].mem_ref_size;
            out.context.clear.offset = process_common_encryption->out_offset;
        } 
#ifdef ENABLE_SVP
	else if (process_common_encryption->out_buffer_type == SA_BUFFER_TYPE_SVP) {
            out.context.svp.buffer = *(sa_svp_buffer*) params[2].mem_ref;
            out.context.svp.offset = process_common_encryption->out_offset;
        }
#else
	else if (process_common_encryption->out_buffer_type == SA_BUFFER_TYPE_SVP) {
	    ERROR("SVP is not supported when ENABLE_SVP flag is enabled");
	    return SA_STATUS_OPERATION_NOT_SUPPORTED; 
	}
#endif // ENABLE_SVP

        sa_buffer in;
        sample.in = &in;
        in.buffer_type = process_common_encryption->in_buffer_type;
        if (process_common_encryption->in_buffer_type == SA_BUFFER_TYPE_CLEAR) {
            in.context.clear.buffer = params[3].mem_ref;
            in.context.clear.length = params[3].mem_ref_size;
            in.context.clear.offset = process_common_encryption->in_offset;
        } 
#ifdef ENABLE_SVP
	else if (process_common_encryption->in_buffer_type == SA_BUFFER_TYPE_SVP) {
            in.buffer_type = process_common_encryption->in_buffer_type;
            in.context.svp.buffer = *(sa_svp_buffer*) params[3].mem_ref;
            in.context.svp.offset = process_common_encryption->in_offset;
        }
#endif

        status = ta_sa_process_common_encryption(1, &sample, context->client, uuid);

#ifdef ENABLE_SVP
        process_common_encryption->out_offset =
                (out.buffer_type == SA_BUFFER_TYPE_CLEAR) ? out.context.clear.offset : out.context.svp.offset;
#else
        process_common_encryption->out_offset = out.context.clear.offset;
#endif // ENABLE_SVP

#ifdef ENABLE_SVP
        process_common_encryption->in_offset =
                (in.buffer_type == SA_BUFFER_TYPE_CLEAR) ? in.context.clear.offset : in.context.svp.offset;
#else
        process_common_encryption->in_offset = in.context.clear.offset;
#endif // ENABLE_SVP

    } while (false);

    if (sample.subsample_lengths != NULL)
        memory_secure_free(sample.subsample_lengths);

    return status;
}

sa_status ta_invoke_command_handler(
        void* session_context,
        SA_COMMAND_ID command_id,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS]) {

    sa_status status;
    void* command_parameter = NULL;
    do {
        if (session_context == NULL) {
            ERROR("NULL session_context");
            return SA_STATUS_NULL_PARAMETER;
        }

        if (params == NULL) {
            ERROR("NULL params");
            return SA_STATUS_NULL_PARAMETER;
        }

        if (param_types == NULL) {
            ERROR("NULL param_types");
            return SA_STATUS_NULL_PARAMETER;
        }

        sa_uuid uuid = {0};
        status = transport_authenticate_caller(&uuid);
        if (status != SA_STATUS_OK) {
            ERROR("transport_authenticate_caller failed: %d", status);
            break;
        }

        if (CHECK_TA_PARAM_NULL(param_types[0], params[0])) {
            ERROR("Command parameter is NULL");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        // Verify params[0] is a valid memref input before copying the buffer.
        if (CHECK_NOT_TA_PARAM_IN(param_types[0]) && CHECK_NOT_TA_PARAM_INOUT(param_types[0])) {
            ERROR("Invalid param[0] type");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        // Cache the command parameter to prevent Time-of-use Time-of-check errors.
        command_parameter = memory_secure_alloc(params[0].mem_ref_size);
        if (command_parameter == NULL) {
            ERROR("memory_secure_alloc failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        memcpy(command_parameter, params[0].mem_ref, params[0].mem_ref_size);
        const ta_session_context* context = session_context;
        switch (command_id) {
            case SA_GET_VERSION:
                status = ta_invoke_get_version((sa_get_version_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_GET_NAME:
                status = ta_invoke_get_name((sa_get_name_s*) command_parameter, param_types, params, context, &uuid);
                break;

            case SA_GET_DEVICE_ID:
                status = ta_invoke_get_device_id((sa_get_device_id_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_GET_TA_UUID:
                status = ta_invoke_get_ta_uuid((sa_get_ta_uuid_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_GENERATE:
                status = ta_invoke_key_generate((sa_key_generate_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_EXPORT:
                status = ta_invoke_key_export((sa_key_export_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_IMPORT:
                status = ta_invoke_key_import((sa_key_import_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_PROVISION_TA:
                status = ta_invoke_key_provision((sa_key_provision_ta_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;
            case SA_KEY_UNWRAP:
                status = ta_invoke_key_unwrap((sa_key_unwrap_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_GET_PUBLIC:
                status = ta_invoke_key_get_public((sa_key_get_public_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_KEY_DERIVE:
                status = ta_invoke_key_derive((sa_key_derive_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_EXCHANGE:
                status = ta_invoke_key_exchange((sa_key_exchange_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_RELEASE:
                status = ta_invoke_key_release((sa_key_release_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_HEADER:
                status = ta_invoke_key_header((sa_key_header_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_KEY_DIGEST:
                status = ta_invoke_key_digest((sa_key_digest_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_CRYPTO_RANDOM:
                status = ta_invoke_crypto_random((sa_crypto_random_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

            case SA_CRYPTO_CIPHER_INIT:
                status = ta_invoke_crypto_cipher_init((sa_crypto_cipher_init_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_UPDATE_IV:
                status = ta_invoke_crypto_cipher_update_iv((sa_crypto_cipher_update_iv_s*) command_parameter,
                        param_types, params, context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_PROCESS:
                status = ta_invoke_crypto_cipher_process(false, (sa_crypto_cipher_process_s*) command_parameter,
                        param_types, params, context, &uuid);
                break;

            case SA_CRYPTO_CIPHER_PROCESS_LAST:
                status = ta_invoke_crypto_cipher_process(true, (sa_crypto_cipher_process_s*) command_parameter,
                        param_types, params, context, &uuid);
                break;
            case SA_CRYPTO_CIPHER_RELEASE:
                status = ta_invoke_crypto_cipher_release((sa_crypto_cipher_release_s*) command_parameter, param_types,
                        params, context, &uuid);
                break;

            case SA_CRYPTO_MAC_INIT:
                status = ta_invoke_crypto_mac_init((sa_crypto_mac_init_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_CRYPTO_MAC_PROCESS:
                status = ta_invoke_crypto_mac_process((sa_crypto_mac_process_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_CRYPTO_MAC_PROCESS_KEY:
                status = ta_invoke_crypto_mac_process_key((sa_crypto_mac_process_key_s*) command_parameter, param_types,
                        params, context, &uuid);
                break;

            case SA_CRYPTO_MAC_COMPUTE:
                status = ta_invoke_crypto_mac_compute((sa_crypto_mac_compute_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_CRYPTO_MAC_RELEASE:
                status = ta_invoke_crypto_mac_release((sa_crypto_mac_release_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_CRYPTO_SIGN:
                status = ta_invoke_crypto_sign((sa_crypto_sign_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;
            case SA_SVP_SUPPORTED:
                status = ta_invoke_svp_supported((sa_svp_supported_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

	    case SA_PROCESS_COMMON_ENCRYPTION:
                status = ta_invoke_process_common_encryption((sa_process_common_encryption_s*) command_parameter,
                        param_types, params, context, &uuid);
                break;
            
#ifdef ENABLE_SVP
            case SA_SVP_KEY_CHECK:
                status = ta_invoke_svp_key_check((sa_svp_key_check_s*) command_parameter, param_types, params, context,
                        &uuid);
                break;

	    case SA_SVP_BUFFER_CHECK:
                status = ta_invoke_svp_buffer_check((sa_svp_buffer_check_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_SVP_BUFFER_CREATE:
                status = ta_invoke_svp_buffer_create((sa_svp_buffer_create_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_SVP_BUFFER_RELEASE:
                status = ta_invoke_svp_buffer_release((sa_svp_buffer_release_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_SVP_BUFFER_WRITE:
                status = ta_invoke_svp_buffer_write((sa_svp_buffer_write_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

            case SA_SVP_BUFFER_COPY:
                status = ta_invoke_svp_buffer_copy((sa_svp_buffer_copy_s*) command_parameter, param_types, params,
                        context, &uuid);
                break;

#endif // ENABLE_SVP
            default:
                status = SA_STATUS_OPERATION_NOT_SUPPORTED;
        }

        // Release the cached command parameter.
        if (CHECK_TA_PARAM_INOUT(param_types[0]))
            memcpy(params[0].mem_ref, command_parameter, params[0].mem_ref_size);
    } while (false);

    if (command_parameter != NULL)
        memory_secure_free(command_parameter);

    return status;
}

sa_status ta_open_session_handler(void** session_context) {

    if (session_context == NULL) {
        return SA_STATUS_INVALID_PARAMETER;
    }

    ta_session_context* context = memory_secure_alloc(sizeof(ta_session_context));
    if (context == NULL) {
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_uuid uuid = {0};
    sa_status status = transport_authenticate_caller(&uuid);
    if (status != SA_STATUS_OK) {
        ERROR("transport_authenticate_caller failed: %d", status);
        memory_secure_free(context);
        return status;
    }

    status = ta_sa_init(&context->client, &uuid);
    if (status != SA_STATUS_OK) {
        ERROR("ta_sa_init failed");
        memory_secure_free(context);
        return status;
    }

    *session_context = context;
    return SA_STATUS_OK;
}

void ta_close_session_handler(void* session_context) {

    ta_session_context* context = session_context;

    do {
        sa_uuid uuid = {0};
        sa_status status = transport_authenticate_caller(&uuid);
        if (status != SA_STATUS_OK) {
            ERROR("transport_authenticate_caller failed: %d", status);
            break;
        }

        if (ta_sa_close(context->client, &uuid) != SA_STATUS_OK) {
            ERROR("ta_sa_close failed");
        }
    } while (false);

    memory_secure_free(context);
}
