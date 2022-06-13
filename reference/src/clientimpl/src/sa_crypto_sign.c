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

sa_status sa_crypto_sign(
        void* out,
        size_t* out_length,
        sa_signature_algorithm signature_algorithm,
        sa_key key,
        const void* in,
        size_t in_length,
        const void* parameters) {

    if (out_length == NULL) {
        ERROR("NULL out_length");
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

    sa_crypto_sign_s* sign = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_crypto_sign_s, sign);
        if (sign == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        sign->api_version = API_VERSION;
        sign->out_length = *out_length;
        sign->signature_algorithm = signature_algorithm;
        sign->key = key;

        if (signature_algorithm == SA_SIGNATURE_ALGORITHM_RSA_PSS) {
            if (parameters == NULL) {
                ERROR("NULL parameters");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            sa_sign_parameters_rsa_pss* parameters_rsa_pss = (sa_sign_parameters_rsa_pss*) parameters;
            sign->salt_length = parameters_rsa_pss->salt_length;
            sign->digest_algorithm = parameters_rsa_pss->digest_algorithm;
            sign->precomputed_digest = parameters_rsa_pss->precomputed_digest;
        } else if (signature_algorithm == SA_SIGNATURE_ALGORITHM_RSA_PKCS1V15) {
            if (parameters == NULL) {
                ERROR("NULL parameters");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            sa_sign_parameters_rsa_pkcs1v15* parameters_rsa_pkcs1v15 = (sa_sign_parameters_rsa_pkcs1v15*) parameters;
            sign->digest_algorithm = parameters_rsa_pkcs1v15->digest_algorithm;
            sign->precomputed_digest = parameters_rsa_pkcs1v15->precomputed_digest;
        } else if (signature_algorithm == SA_SIGNATURE_ALGORITHM_ECDSA) {
            if (parameters == NULL) {
                ERROR("NULL parameters");
                status = SA_STATUS_NULL_PARAMETER;
                break;
            }

            sa_sign_parameters_ecdsa* parameters_ecdsa = (sa_sign_parameters_ecdsa*) parameters;
            sign->digest_algorithm = parameters_ecdsa->digest_algorithm;
            sign->precomputed_digest = parameters_ecdsa->precomputed_digest;
        } else {
            sign->salt_length = 0;
            sign->digest_algorithm = 0;
            sign->precomputed_digest = false;
        }

        size_t param1_size;
        ta_param_type param1_type;
        if (out != NULL) {
            CREATE_OUT_PARAM(param1, out, *out_length);
            if (param1 == NULL) {
                ERROR("CREATE_OUT_PARAM failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }

            param1_size = *out_length;
            param1_type = TA_PARAM_OUT;
        } else {
            param1_size = 0;
            param1_type = TA_PARAM_NULL;
        }

        size_t param2_size;
        ta_param_type param2_type;
        if (in != NULL) {
            CREATE_PARAM(param2, (void*) in, in_length);
            if (param2 == NULL) {
                ERROR("CREATE_PARAM failed");
                status = SA_STATUS_INTERNAL_ERROR;
                break;
            }

            param2_size = in_length;
            param2_type = TA_PARAM_IN;
        } else {
            param2_size = 0;
            param2_type = TA_PARAM_NULL;
        }

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{sign, sizeof(sa_crypto_sign_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_CRYPTO_SIGN, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *out_length = sign->out_length;
        if (out != NULL)
            COPY_OUT_PARAM(out, param1, sign->out_length);
    } while (false);

    RELEASE_COMMAND(sign);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    return status;
}
