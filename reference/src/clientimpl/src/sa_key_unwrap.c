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

#include "client.h"
#include "sa.h"
#include "sa_log.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_key_unwrap(
        sa_key* key,
        const sa_rights* rights,
        sa_key_type key_type,
        void* type_parameters,
        sa_cipher_algorithm cipher_algorithm,
        void* algorithm_parameters,
        sa_key wrapping_key,
        const void* in,
        size_t in_length) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (in == NULL && in_length > 0) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_key_unwrap_s* key_unwrap = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    void* param3 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_unwrap_s, key_unwrap);
        if (key_unwrap == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        key_unwrap->api_version = API_VERSION;
        key_unwrap->key = *key;
        key_unwrap->rights = *rights;
        key_unwrap->key_type = key_type;
        key_unwrap->cipher_algorithm = cipher_algorithm;
        key_unwrap->wrapping_key = wrapping_key;
        if (key_type == SA_KEY_TYPE_EC) {
            if (type_parameters == NULL) {
                ERROR("NULL type_parameters");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            sa_unwrap_type_parameters_ec* parameters_ec = (sa_unwrap_type_parameters_ec*) type_parameters;
            key_unwrap->curve = parameters_ec->curve;
        } else {
            key_unwrap->curve = 0;
        }

        size_t param1_size;
        ta_param_type param1_type;
        if (in != NULL) {
            CREATE_PARAM(param1, (void*) in, in_length);
            if (param1 == NULL) {
                ERROR("CREATE_PARAM failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }
            param1_size = in_length;
            param1_type = TA_PARAM_IN;
        } else {
            param1_size = 0;
            param1_type = TA_PARAM_NULL;
        }

        size_t param2_size;
        ta_param_type param2_type;
        size_t param3_size;
        ta_param_type param3_type;
        switch (cipher_algorithm) {
            case SA_CIPHER_ALGORITHM_AES_CBC:
            case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
                if (algorithm_parameters == NULL) {
                    ERROR("NULL algorithm_parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_aes_cbc* parameters_aes_cbc = (sa_unwrap_parameters_aes_cbc*) algorithm_parameters;
                if (parameters_aes_cbc->iv == NULL) {
                    ERROR("NULL iv");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_aes_cbc->iv_length != AES_BLOCK_SIZE) {
                    ERROR("iv_length is not 16");
                    status = SA_STATUS_BAD_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_unwrap_parameters_aes_iv_s, param2);
                if (param2 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_aes_iv_s* parameters_aes_cbc_s = (sa_unwrap_parameters_aes_iv_s*) param2;
                memcpy(parameters_aes_cbc_s->iv, parameters_aes_cbc->iv, parameters_aes_cbc->iv_length);

                param2_size = sizeof(sa_unwrap_parameters_aes_iv_s);
                param2_type = TA_PARAM_IN;
                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            case SA_CIPHER_ALGORITHM_AES_CTR:
                if (algorithm_parameters == NULL) {
                    ERROR("NULL algorithm_parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_aes_ctr* parameters_aes_ctr = (sa_unwrap_parameters_aes_ctr*) algorithm_parameters;
                if (parameters_aes_ctr->ctr == NULL) {
                    ERROR("NULL ctr");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_aes_ctr->ctr_length != AES_BLOCK_SIZE) {
                    ERROR("iv_length is not 16");
                    status = SA_STATUS_BAD_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_unwrap_parameters_aes_iv_s, param2);
                if (param2 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_aes_iv_s* parameters_aes_ctr_s = (sa_unwrap_parameters_aes_iv_s*) param2;
                memcpy(parameters_aes_ctr_s->iv, parameters_aes_ctr->ctr, parameters_aes_ctr->ctr_length);

                param2_size = sizeof(sa_unwrap_parameters_aes_iv_s);
                param2_type = TA_PARAM_IN;
                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            case SA_CIPHER_ALGORITHM_AES_GCM:
                if (algorithm_parameters == NULL) {
                    ERROR("NULL algorithm_parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_aes_gcm* parameters_aes_gcm = (sa_unwrap_parameters_aes_gcm*) algorithm_parameters;
                if (parameters_aes_gcm->iv == NULL) {
                    ERROR("NULL iv");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_aes_gcm->iv_length != GCM_IV_LENGTH) {
                    ERROR("iv_length is not 12");
                    status = SA_STATUS_BAD_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_aes_gcm->tag == NULL) {
                    ERROR("NULL tag");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_aes_gcm->tag_length > AES_BLOCK_SIZE) {
                    ERROR("tag_length is too large");
                    status = SA_STATUS_BAD_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_aes_gcm->aad == NULL && parameters_aes_gcm->aad_length > 0) {
                    ERROR("NULL aad");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_unwrap_parameters_aes_gcm_s, param2);
                if (param2 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_aes_gcm_s* parameters_aes_gcm_s = (sa_unwrap_parameters_aes_gcm_s*) param2;
                memcpy(parameters_aes_gcm_s->iv, parameters_aes_gcm->iv, parameters_aes_gcm->iv_length);
                parameters_aes_gcm_s->iv_length = parameters_aes_gcm->iv_length;
                memcpy(parameters_aes_gcm_s->tag, parameters_aes_gcm->tag, parameters_aes_gcm->tag_length);
                parameters_aes_gcm_s->tag_length = parameters_aes_gcm->tag_length;
                param2_size = sizeof(sa_unwrap_parameters_aes_gcm_s);
                param2_type = TA_PARAM_IN;

                if (parameters_aes_gcm->aad != NULL) {
                    CREATE_PARAM(param3, (void*) parameters_aes_gcm->aad, parameters_aes_gcm->aad_length);
                    if (param3 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param3_size = parameters_aes_gcm->aad_length;
                    param3_type = TA_PARAM_IN;
                } else {
                    param3_size = 0;
                    param3_type = TA_PARAM_NULL;
                }
                break;

            case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
                if (algorithm_parameters == NULL) {
                    ERROR("NULL algorithm_parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_ec_elgamal* parameters_ec_elgamal =
                        (sa_unwrap_parameters_ec_elgamal*) algorithm_parameters;
                CREATE_COMMAND(sa_unwrap_parameters_ec_elgamal_s, param2);
                if (param2 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_unwrap_parameters_ec_elgamal_s* unwrap_parameters_ec_elgamal =
                        (sa_unwrap_parameters_ec_elgamal_s*) param2;
                unwrap_parameters_ec_elgamal->key_length = parameters_ec_elgamal->key_length;
                unwrap_parameters_ec_elgamal->offset = parameters_ec_elgamal->offset;
                param2_size = sizeof(sa_unwrap_parameters_ec_elgamal_s);
                param2_type = TA_PARAM_IN;
                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            case SA_CIPHER_ALGORITHM_AES_ECB:
            case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            case SA_CIPHER_ALGORITHM_RSA_PKCS1V15:
            case SA_CIPHER_ALGORITHM_RSA_OAEP:
                param2_size = 0;
                param2_type = TA_PARAM_NULL;
                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            default:
                status = SA_STATUS_BAD_PARAMETER;
                continue; // NOLINT
        }

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, param3_type};
        ta_param params[NUM_TA_PARAMS] = {{key_unwrap, sizeof(sa_key_unwrap_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {param3, param3_size}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_UNWRAP, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *key = key_unwrap->key;
    } while (false);

    RELEASE_COMMAND(key_unwrap);
    RELEASE_PARAM(param1);
    RELEASE_COMMAND(param2);
    RELEASE_PARAM(param3);
    return status;
}
