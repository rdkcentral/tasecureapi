/*
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

sa_status sa_key_header(
        sa_header* header,
        sa_key key) {

    if (header == NULL) {
        ERROR("NULL header");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_key_header_s* key_header = NULL;
    sa_header_s header_s;
    void* param1 = NULL;
    size_t param1_size = sizeof(sa_header_s);
    sa_status status;
    do {
        CREATE_COMMAND(sa_key_header_s, key_header);
        key_header->api_version = API_VERSION;
        key_header->key = key;

        CREATE_OUT_PARAM(param1, &header_s, sizeof(sa_header_s));

        // clang-format off
        uint32_t param_types[NUM_TA_PARAMS] = {TA_PARAM_INOUT, TA_PARAM_OUT, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{key_header, sizeof(sa_key_header_s)},
                                          {param1, param1_size},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_KEY_HEADER, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }

        COPY_OUT_PARAM(header_s, param1, sizeof(sa_header_s));
        memset(header, 0, sizeof(sa_header));
        memcpy(header->magic, header_s.magic, NUM_MAGIC);
        memcpy(&header->rights, &header_s.rights, sizeof(sa_rights));
        header->type = header_s.type;
        header->size = header_s.size;
        if (header_s.type == SA_KEY_TYPE_EC) {
            header->type_parameters.curve = header_s.type_parameters.curve;
        } else if (header_s.type == SA_KEY_TYPE_DH) {
            memcpy(header->type_parameters.dh_parameters.p, header_s.type_parameters.dh_parameters.p, DH_MAX_MOD_SIZE);
            header->type_parameters.dh_parameters.p_length = header_s.type_parameters.dh_parameters.p_length;
            memcpy(header->type_parameters.dh_parameters.g, header_s.type_parameters.dh_parameters.g, DH_MAX_MOD_SIZE);
            header->type_parameters.dh_parameters.g_length = header_s.type_parameters.dh_parameters.g_length;
        }
    } while (false);

    RELEASE_COMMAND(key_header);
    return status;
}
