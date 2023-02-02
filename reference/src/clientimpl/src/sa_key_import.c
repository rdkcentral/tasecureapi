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

sa_status sa_key_import(
        sa_key* key,
        sa_key_format key_format,
        const void* in,
        size_t in_length,
        void* parameters) {

    if (key == NULL) {
        ERROR("NULL key");
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

    sa_key_import_s* key_import = NULL;
    void* param1 = NULL;
    void* param2 = NULL;
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_import_s, key_import);
        if (key_import == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        key_import->api_version = API_VERSION;
        key_import->key = *key;
        key_import->key_format = key_format;
        key_import->curve = 0;

        size_t param1_size;
        uint32_t param1_type;
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
        uint32_t param2_type;
        switch (key_format) {
            case SA_KEY_FORMAT_SYMMETRIC_BYTES:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_import_parameters_symmetric* parameters_symmetric = (sa_import_parameters_symmetric*) parameters;
                if (parameters_symmetric->rights == NULL) {
                    ERROR("NULL rights");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param2, (void*) parameters_symmetric->rights, sizeof(sa_rights));
                if (param2 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param2_size = sizeof(sa_rights);
                param2_type = TA_PARAM_IN;
                break;

            case SA_KEY_FORMAT_RSA_PRIVATE_KEY_INFO:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_import_parameters_rsa_private_key_info* parameters_rsa =
                        (sa_import_parameters_rsa_private_key_info*) parameters;
                if (parameters_rsa->rights == NULL) {
                    ERROR("NULL rights");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param2, (void*) parameters_rsa->rights, sizeof(sa_rights));
                if (param2 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param2_size = sizeof(sa_rights);
                param2_type = TA_PARAM_IN;
                break;

            case SA_KEY_FORMAT_EC_PRIVATE_BYTES:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                sa_import_parameters_ec_private_bytes* parameters_ec =
                        (sa_import_parameters_ec_private_bytes*) parameters;
                if (parameters_ec->rights == NULL) {
                    ERROR("NULL rights");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param2, (void*) parameters_ec->rights, sizeof(sa_rights));
                if (param2 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param2_size = sizeof(sa_rights);
                param2_type = TA_PARAM_IN;
                key_import->curve = parameters_ec->curve;
                break;

            case SA_KEY_FORMAT_EXPORTED:
                param2 = NULL;
                param2_size = 0;
                param2_type = TA_PARAM_NULL;
                break;

            case SA_KEY_FORMAT_TYPEJ:
                if (parameters == NULL) {
                    ERROR("NULL parameters");
                    status = SA_STATUS_NULL_PARAMETER;
                    continue; // NOLINT
                }

                CREATE_PARAM(param2, parameters, sizeof(sa_import_parameters_typej));
                if (param2 == NULL) {
                    ERROR("CREATE_PARAM failed");
                    status = SA_STATUS_INTERNAL_ERROR;
                    continue; // NOLINT
                }

                param2_size = sizeof(sa_import_parameters_typej);
                param2_type = TA_PARAM_IN;
                break;

            case SA_KEY_FORMAT_SOC:
                if (parameters != NULL) {
                    param2_size = ((size_t) ((uint8_t*) parameters)[0] << 8) + (size_t) ((uint8_t*) parameters)[1];
                    CREATE_PARAM(param2, parameters, param2_size);
                    if (param2 == NULL) {
                        ERROR("CREATE_PARAM failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        continue; // NOLINT
                    }

                    param2_type = TA_PARAM_IN;
                } else {
                    param2 = NULL;
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
        ta_param params[NUM_TA_PARAMS] = {{key_import, sizeof(sa_key_import_s)},
                                          {param1, param1_size},
                                          {param2, param2_size},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_IMPORT, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        *key = key_import->key;
    } while (false);

    RELEASE_COMMAND(key_import);
    RELEASE_PARAM(param1);
    RELEASE_PARAM(param2);
    return status;
}
