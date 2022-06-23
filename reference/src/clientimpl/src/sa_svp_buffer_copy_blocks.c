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
#include "log.h"
#include "sa.h"
#include "ta_client.h"
#include <stdbool.h>

sa_status sa_svp_buffer_copy_blocks(
        sa_svp_buffer out,
        const sa_svp_buffer in,
        sa_svp_block* blocks,
        size_t blocks_length) {

    if (blocks == NULL) {
        ERROR("NULL blocks");
        return SA_STATUS_NULL_PARAMETER;
    }

    void* session = client_session();
    if (session == NULL) {
        ERROR("client_session failed");
        return SA_STATUS_INTERNAL_ERROR;
    }

    sa_svp_buffer_copy_block_s* svp_buffer_copy_blocks = NULL;
    void* param1 = NULL;
    size_t param1_size;
    ta_param_type param1_type;
    sa_status status;
    do {
        CREATE_COMMAND(sa_svp_buffer_copy_block_s, svp_buffer_copy_blocks);
        if (svp_buffer_copy_blocks == NULL) {
            ERROR("CREATE_COMMAND failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        svp_buffer_copy_blocks->api_version = API_VERSION;
        svp_buffer_copy_blocks->out_svp_buffer = out;
        svp_buffer_copy_blocks->in_svp_buffer = in;
        svp_buffer_copy_blocks->blocks_length = blocks_length;

        CREATE_PARAM(param1, blocks, sizeof(sa_svp_block) * blocks_length);
        param1_size = sizeof(sa_svp_block) * blocks_length;
        param1_type = TA_PARAM_IN;
        
        // clang-format off
        ta_param_type param_types[NUM_TA_PARAMS] = {TA_PARAM_IN, param1_type, TA_PARAM_NULL, TA_PARAM_NULL};
        ta_param params[NUM_TA_PARAMS] = {{svp_buffer_copy_blocks, sizeof(sa_svp_buffer_copy_block_s)},
                                          {param1, param1_size},
                                          {NULL, 0},
                                          {NULL, 0}};
        // clang-format on
        status = ta_invoke_command(session, SA_SVP_BUFFER_COPY_BLOCKS, param_types, params);
        if (status != SA_STATUS_OK) {
            ERROR("ta_invoke_command failed: %d", status);
            break;
        }
    } while (false);

    RELEASE_COMMAND(svp_buffer_copy_blocks);
    RELEASE_PARAM(param1);
    return status;
}
