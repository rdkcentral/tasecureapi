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

sa_status sa_key_derive(
        sa_key* key,
        const sa_rights* rights,
        sa_kdf_algorithm kdf_algorithm,
        void* parameters) {

    if (key == NULL) {
        ERROR("NULL key");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (rights == NULL) {
        ERROR("NULL rights");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_key_derive_s* key_derive = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    void* param3 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_derive_s, key_derive);
        if (key_derive == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        key_derive->api_version = API_VERSION;
        key_derive->key = *key;
        key_derive->rights = *rights;
        key_derive->kdf_algorithm = kdf_algorithm;

        size_t param1_size;
        uint32_t param1_type;
        size_t param2_size;
        uint32_t param2_type;
        size_t param3_size;
        uint32_t param3_type;
        switch (kdf_algorithm) {
            case SA_KDF_ALGORITHM_ROOT_KEY_LADDER:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_kdf_parameters_root_key_ladder* parameters_root_key_ladder =
                        (sa_kdf_parameters_root_key_ladder*) parameters;
                if (parameters_root_key_ladder->c1 == NULL) {
                    ERROR("NULL c1");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_root_key_ladder->c1_length != AES_BLOCK_SIZE) {
                    ERROR("c1 invalid length");
                    status = SA_STATUS_INVALID_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_root_key_ladder->c2 == NULL) {
                    ERROR("NULL c2");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_root_key_ladder->c2_length != AES_BLOCK_SIZE) {
                    ERROR("c2 invalid length");
                    status = SA_STATUS_INVALID_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_root_key_ladder->c3 == NULL) {
                    ERROR("NULL c3");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_root_key_ladder->c3_length != AES_BLOCK_SIZE) {
                    ERROR("c3 invalid length");
                    status = SA_STATUS_INVALID_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_root_key_ladder->c4 == NULL) {
                    ERROR("NULL c4");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_root_key_ladder->c4_length != AES_BLOCK_SIZE) {
                    ERROR("c4 invalid length");
                    status = SA_STATUS_INVALID_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_kdf_parameters_root_key_ladder_s, param1);
                if (param1 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_kdf_parameters_root_key_ladder_s* parameters_root_key_ladder_s =
                        (sa_kdf_parameters_root_key_ladder_s*) param1;
                memcpy(parameters_root_key_ladder_s->c1, parameters_root_key_ladder->c1, AES_BLOCK_SIZE);
                memcpy(parameters_root_key_ladder_s->c2, parameters_root_key_ladder->c2, AES_BLOCK_SIZE);
                memcpy(parameters_root_key_ladder_s->c3, parameters_root_key_ladder->c3, AES_BLOCK_SIZE);
                memcpy(parameters_root_key_ladder_s->c4, parameters_root_key_ladder->c4, AES_BLOCK_SIZE);
                param1_size = sizeof(sa_kdf_parameters_root_key_ladder_s);
                param1_type = TA_PARAM_IN;
                param2_size = 0;
                param2_type = TA_PARAM_NULL;
                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            case SA_KDF_ALGORITHM_HKDF:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_kdf_parameters_hkdf* parameters_hkdf = (sa_kdf_parameters_hkdf*) parameters;
                if (parameters_hkdf->info == NULL && parameters_hkdf->info_length > 0) {
                    ERROR("NULL info");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                if (parameters_hkdf->salt == NULL && parameters_hkdf->salt_length > 0) {
                    ERROR("NULL salt");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_kdf_parameters_hkdf_s, param1);
                if (param1 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_kdf_parameters_hkdf_s* parameters_hkdf_s = (sa_kdf_parameters_hkdf_s*) param1;
                parameters_hkdf_s->key_length = parameters_hkdf->key_length;
                parameters_hkdf_s->digest_algorithm = parameters_hkdf->digest_algorithm;
                parameters_hkdf_s->parent = parameters_hkdf->parent;
                param1_size = sizeof(sa_kdf_parameters_hkdf_s);
                param1_type = TA_PARAM_IN;

                if (parameters_hkdf->info != NULL) {
                    CREATE_PARAM(param2, (void*) parameters_hkdf->info, parameters_hkdf->info_length);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_size = parameters_hkdf->info_length;
                    param2_type = TA_PARAM_IN;
                } else {
                    param2_size = 0;
                    param2_type = TA_PARAM_NULL;
                }

                if (parameters_hkdf->salt != NULL) {
                    CREATE_PARAM(param3, (void*) parameters_hkdf->salt, parameters_hkdf->salt_length);
                    if (param3 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param3_size = parameters_hkdf->salt_length;
                    param3_type = TA_PARAM_IN;
                } else {
                    param3_size = 0;
                    param3_type = TA_PARAM_NULL;
                }

                break;

            case SA_KDF_ALGORITHM_CONCAT:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_kdf_parameters_concat* parameters_concat = (sa_kdf_parameters_concat*) parameters;
                if (parameters_concat->info == NULL && parameters_concat->info_length > 0) {
                    ERROR("NULL info");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_kdf_parameters_concat_s, param1);
                if (param1 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_kdf_parameters_concat_s* parameters_concat_s = (sa_kdf_parameters_concat_s*) param1;
                parameters_concat_s->key_length = parameters_concat->key_length;
                parameters_concat_s->digest_algorithm = parameters_concat->digest_algorithm;
                parameters_concat_s->parent = parameters_concat->parent;
                param1_size = sizeof(sa_kdf_parameters_concat_s);
                param1_type = TA_PARAM_IN;

                if (parameters_concat->info != NULL) {
                    CREATE_PARAM(param2, (void*) parameters_concat->info, parameters_concat->info_length);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_size = parameters_concat->info_length;
                    param2_type = TA_PARAM_IN;
                } else {
                    param2_size = 0;
                    param2_type = TA_PARAM_NULL;
                }

                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            case SA_KDF_ALGORITHM_ANSI_X963:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_kdf_parameters_ansi_x963* parameters_ansi_x_963 = (sa_kdf_parameters_ansi_x963*) parameters;
                if (parameters_ansi_x_963->info == NULL && parameters_ansi_x_963->info_length > 0) {
                    ERROR("NULL info");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_kdf_parameters_ansi_x963_s, param1);
                if (param1 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_kdf_parameters_ansi_x963_s* parameters_ansi_x_963_s = (sa_kdf_parameters_ansi_x963_s*) param1;
                parameters_ansi_x_963_s->key_length = parameters_ansi_x_963->key_length;
                parameters_ansi_x_963_s->digest_algorithm = parameters_ansi_x_963->digest_algorithm;
                parameters_ansi_x_963_s->parent = parameters_ansi_x_963->parent;
                param1_size = sizeof(sa_kdf_parameters_ansi_x963_s);
                param1_type = TA_PARAM_IN;

                if (parameters_ansi_x_963->info != NULL) {
                    CREATE_PARAM(param2, (void*) parameters_ansi_x_963->info, parameters_ansi_x_963->info_length);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_size = parameters_ansi_x_963->info_length;
                    param2_type = TA_PARAM_IN;
                } else {
                    param2_size = 0;
                    param2_type = TA_PARAM_NULL;
                }

                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            case SA_KDF_ALGORITHM_CMAC:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_kdf_parameters_cmac* parameters_cmac = (sa_kdf_parameters_cmac*) parameters;
                if (parameters_cmac->other_data == NULL && parameters_cmac->other_data_length > 0) {
                    ERROR("NULL other_data");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_COMMAND(sa_kdf_parameters_cmac_s, param1);
                if (param1 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_kdf_parameters_cmac_s* parameters_cmac_s = (sa_kdf_parameters_cmac_s*) param1;
                parameters_cmac_s->key_length = parameters_cmac->key_length;
                parameters_cmac_s->parent = parameters_cmac->parent;
                parameters_cmac_s->counter = parameters_cmac->counter;
                param1_size = sizeof(sa_kdf_parameters_cmac_s);
                param1_type = TA_PARAM_IN;

                if (parameters_cmac->other_data != NULL) {
                    CREATE_PARAM(param2, (void*) parameters_cmac->other_data, parameters_cmac->other_data_length);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_size = parameters_cmac->other_data_length;
                    param2_type = TA_PARAM_IN;
                } else {
                    param2_size = 0;
                    param2_type = TA_PARAM_NULL;
                }

                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            case SA_KDF_ALGORITHM_NETFLIX:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_kdf_parameters_netflix* parameters_netflix = (sa_kdf_parameters_netflix*) parameters;
                CREATE_COMMAND(sa_kdf_parameters_netflix, param1);
                if (param1 == NULL) {
                    ERROR("CREATE_COMMAND failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                sa_kdf_parameters_netflix_s* parameters_netflix_s = (sa_kdf_parameters_netflix_s*) param1;
                parameters_netflix_s->kenc = parameters_netflix->kenc;
                parameters_netflix_s->khmac = parameters_netflix->khmac;

                param1_size = sizeof(sa_kdf_parameters_netflix);
                param1_type = TA_PARAM_IN;
                param2_size = 0;
                param2_type = TA_PARAM_NULL;
                param3_size = 0;
                param3_type = TA_PARAM_NULL;
                break;

            default:
                status = SA_STATUS_INVALID_PARAMETER;
                continue; // NOLINT
        }

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, param1_type, param2_type, param3_type};
        ta_param params[NUM_TA_PARAMS] = {{key_derive, sizeof(sa_key_derive_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {param3, param3_size}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_DERIVE, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *key = key_derive->key;
    } while (false);

    RELEASE_COMMAND(key_derive);
    RELEASE_COMMAND(param1);
    RELEASE_PARAM(param2);
    RELEASE_PARAM(param3);
    return status;
}
