/**
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

#include "client.h"
#include "log.h"
#include "sa.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_crypto_cipher_init(
        sa_crypto_cipher_context* context,
        sa_cipher_algorithm cipher_algorithm,
        sa_cipher_mode cipher_mode,
        sa_key key,
        void* parameters) {

    if (context == NULL) {
        ERROR("NULL context");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_crypto_cipher_init_s* cipher_init = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_crypto_cipher_init_s, cipher_init);
        if (cipher_init == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        cipher_init->api_version = API_VERSION;
        cipher_init->context = *context;
        cipher_init->cipher_algorithm = cipher_algorithm;
        cipher_init->cipher_mode = cipher_mode;
        cipher_init->key = key;

        size_t param1_size;
        uint32_t param1_type;
        size_t param2_size;
        uint32_t param2_type;
        switch (cipher_algorithm) {
            case SA_CIPHER_ALGORITHM_AES_ECB:
            case SA_CIPHER_ALGORITHM_AES_ECB_PKCS7:
            case SA_CIPHER_ALGORITHM_EC_ELGAMAL:
            case SA_CIPHER_ALGORITHM_RSA_PKCS1V15:
                param1_size = 0;
                param1_type = TA_PARAM_NULL;
                param2_size = 0;
                param2_type = TA_PARAM_NULL;
                break;

            case SA_CIPHER_ALGORITHM_AES_CBC:
            case SA_CIPHER_ALGORITHM_AES_CBC_PKCS7:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_cipher_parameters_aes_cbc* parameters_aes_cbc = (sa_cipher_parameters_aes_cbc*) parameters;
                if (parameters_aes_cbc->iv == NULL) {
                    ERROR("NULL iv");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param1, (void*) parameters_aes_cbc->iv, parameters_aes_cbc->iv_length);
                if (param1 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param1_size = parameters_aes_cbc->iv_length;
                param1_type = TA_PARAM_IN;
                param2_size = 0;
                param2_type = TA_PARAM_NULL;
                break;

            case SA_CIPHER_ALGORITHM_AES_CTR:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_cipher_parameters_aes_ctr* parameters_aes_ctr = (sa_cipher_parameters_aes_ctr*) parameters;
                if (parameters_aes_ctr->ctr == NULL) {
                    ERROR("NULL ctr");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param1, (void*) parameters_aes_ctr->ctr, parameters_aes_ctr->ctr_length);
                if (param1 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param1_size = parameters_aes_ctr->ctr_length;
                param1_type = TA_PARAM_IN;
                param2_size = 0;
                param2_type = TA_PARAM_NULL;
                break;

            case SA_CIPHER_ALGORITHM_AES_GCM:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_cipher_parameters_aes_gcm* parameters_aes_gcm = (sa_cipher_parameters_aes_gcm*) parameters;
                if (parameters_aes_gcm->iv == NULL) {
                    ERROR("NULL iv");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_aes_gcm->aad == NULL && parameters_aes_gcm->aad_length > 0) {
                    ERROR("NULL aad");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param1, (void*) parameters_aes_gcm->iv, parameters_aes_gcm->iv_length);
                if (param1 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param1_size = parameters_aes_gcm->iv_length;
                param1_type = TA_PARAM_IN;

                if (parameters_aes_gcm->aad != NULL) {
                    CREATE_PARAM(param2, (void*) parameters_aes_gcm->aad, parameters_aes_gcm->aad_length);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_size = parameters_aes_gcm->aad_length;
                    param2_type = TA_PARAM_IN;
                } else {
                    param2_size = 0;
                    param2_type = TA_PARAM_NULL;
                }
                break;

            case SA_CIPHER_ALGORITHM_CHACHA20:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_cipher_parameters_chacha20* parameters_chacha20 = (sa_cipher_parameters_chacha20*) parameters;
                if (parameters_chacha20->counter == NULL) {
                    ERROR("NULL counter");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_chacha20->nonce == NULL) {
                    ERROR("NULL nonce");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param1, (void*) parameters_chacha20->nonce, parameters_chacha20->nonce_length);
                if (param1 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param1_size = parameters_chacha20->nonce_length;
                param1_type = TA_PARAM_IN;

                CREATE_PARAM(param2, (void*) parameters_chacha20->counter, parameters_chacha20->counter_length);
                if (param2 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param2_size = parameters_chacha20->counter_length;
                param2_type = TA_PARAM_IN;
                break;

            case SA_CIPHER_ALGORITHM_CHACHA20_POLY1305:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_cipher_parameters_chacha20_poly1305* parameters_chacha20_poly1305 =
                        (sa_cipher_parameters_chacha20_poly1305*) parameters;
                if (parameters_chacha20_poly1305->nonce == NULL) {
                    ERROR("NULL nonce");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_chacha20_poly1305->aad == NULL && parameters_chacha20_poly1305->aad_length > 0) {
                    ERROR("NULL aad");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param1, (void*) parameters_chacha20_poly1305->nonce,
                        parameters_chacha20_poly1305->nonce_length);
                if (param1 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param1_size = parameters_chacha20_poly1305->nonce_length;
                param1_type = TA_PARAM_IN;

                if (parameters_chacha20_poly1305->aad != NULL) {
                    CREATE_PARAM(param2, (void*) parameters_chacha20_poly1305->aad,
                            parameters_chacha20_poly1305->aad_length);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_size = parameters_chacha20_poly1305->aad_length;
                    param2_type = TA_PARAM_IN;
                } else {
                    param2_size = 0;
                    param2_type = TA_PARAM_NULL;
                }
                break;

            case SA_CIPHER_ALGORITHM_RSA_OAEP:
                if (parameters == NULL) {
                    ERROR("NULL algorithm_parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_cipher_parameters_rsa_oaep* parameters_rsa_oaep = (sa_cipher_parameters_rsa_oaep*) parameters;
                if (parameters_rsa_oaep->label == NULL && parameters_rsa_oaep->label_length != 0) {
                    ERROR("NULL label");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_cipher_parameters_rsa_oaep_s, param1);
                if (param1 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_cipher_parameters_rsa_oaep_s* parameters_rsa_oaep_s = (sa_cipher_parameters_rsa_oaep_s*) param1;
                parameters_rsa_oaep_s->digest_algorithm = parameters_rsa_oaep->digest_algorithm;
                parameters_rsa_oaep_s->mgf1_digest_algorithm = parameters_rsa_oaep->mgf1_digest_algorithm;

                param1_size = sizeof(sa_cipher_parameters_rsa_oaep_s);
                param1_type = TA_PARAM_IN;
                if (parameters_rsa_oaep->label != NULL) {
                    CREATE_PARAM(param2, (void*) parameters_rsa_oaep->label, parameters_rsa_oaep->label_length);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_size = parameters_rsa_oaep->label_length;
                    param2_type = TA_PARAM_IN;
                } else {
                    param2_size = 0;
                    param2_type = TA_PARAM_NULL;
                }

                break;

            default:
                status = SA_STATUS_INVALID_PARAMETER;
                continue; // NOLINT
        }

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{cipher_init, sizeof(sa_crypto_cipher_init_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_CRYPTO_CIPHER_INIT, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *context = cipher_init->context;
    } while (false);

    RELEASE_COMMAND(cipher_init);
    if (cipher_algorithm == SA_CIPHER_ALGORITHM_RSA_OAEP) { // NOLINT
        RELEASE_COMMAND(param1);
    } else {
        RELEASE_PARAM(param1);
    }

    RELEASE_PARAM(param2);
    return status;
}
