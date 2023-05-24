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

/**
 * @section Description
 * @file ta_client.c
 * This file implements the TA client interfaces. This file should be replaced with code that implements client to
 * TA communication on the SoC platform.
 */

#include "ta_client.h" // NOLINT
#include "ta.h"

#ifdef TA_CLIENT_TEST
#include "log.h"
#endif

sa_status ta_open_session(void** session_context) {
    return ta_open_session_handler(session_context);
}

void ta_close_session(void* session_context) {
    ta_close_session_handler(session_context);
}

sa_status ta_invoke_command(
        void* session_context,
        SA_COMMAND_ID command_id,
        const uint32_t param_types[NUM_TA_PARAMS],
        ta_param params[NUM_TA_PARAMS]) {

#ifdef TA_CLIENT_TEST
    uint8_t checksums[NUM_TA_PARAMS];

    // This is for testing purposes to check for implementation errors.
    for (size_t i = 0; i < NUM_TA_PARAMS; i++) {
        if ((params[i].mem_ref == NULL && param_types[i] != TA_PARAM_NULL) ||
                (params[i].mem_ref != NULL && param_types[i] == TA_PARAM_NULL)) {
            ERROR("param_type[%d] was set to the wrong value", i);
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (params[i].mem_ref == NULL && params[i].mem_ref_size != 0) {
            ERROR("mem_ref_size[%d] was set to the wrong value", i);
            return SA_STATUS_INVALID_PARAMETER;
        }

        checksums[i] = 0;
        if (param_types[i] == TA_PARAM_IN) {
            for (size_t j = 0; j < params[i].mem_ref_size; j++)
                checksums[i] ^= ((uint8_t*) params[i].mem_ref)[j];
        }
    }
#endif

    sa_status status = ta_invoke_command_handler(session_context, command_id, param_types, params);

#ifdef TA_CLIENT_TEST
    // This is for testing purposes to check for implementation errors.
    for (size_t i = 0; i < NUM_TA_PARAMS; i++) {
        if (param_types[i] == TA_PARAM_IN) {
            uint8_t checksum = 0;
            for (size_t j = 0; j < params[i].mem_ref_size; j++)
                checksum ^= ((uint8_t*) params[i].mem_ref)[j];

            if (checksum != checksums[i]) {
                ERROR("param_type[%d] was set to the wrong value", i);
                return SA_STATUS_INVALID_PARAMETER;
            }
        }
    }
#endif

    return status;
}

void* ta_alloc_shared_memory(size_t size) {
    return malloc(size);
}

void ta_free_shared_memory(void* buffer) {
    if (buffer != NULL)
        free(buffer);
}
