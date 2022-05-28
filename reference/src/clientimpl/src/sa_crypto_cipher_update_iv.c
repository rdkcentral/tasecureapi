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

sa_status sa_crypto_cipher_update_iv(
        sa_crypto_cipher_context context,
        const void* iv,
        size_t iv_length) {

    if (iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_crypto_cipher_update_iv_s* cipher_update_iv = NULL;
    void* param1 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_crypto_cipher_update_iv_s, cipher_update_iv);
        if (cipher_update_iv == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        cipher_update_iv->api_version = API_VERSION;
        cipher_update_iv->context = context;

        CREATE_PARAM(param1, (void*) iv, iv_length);
        if (param1 == NULL) {
            ERROR("CREATE_PARAM failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        size_t param1_size = iv_length;
        ta_param_type param1_type = TA_PARAM_IN;

        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_IN, param1_type, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{cipher_update_iv, sizeof(sa_crypto_cipher_update_iv_s)},
                                          {param1, param1_size},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_CRYPTO_CIPHER_UPDATE_IV, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
    } while (false);

    RELEASE_COMMAND(cipher_update_iv);
    RELEASE_PARAM(param1);
    return status;
}
