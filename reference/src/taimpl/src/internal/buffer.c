/**
 * Copyright 2019-2022 Comcast Cable Communications Management, LLC
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

#include "buffer.h"
#include "client_store.h"
#include "log.h"

sa_status convert_buffer(
        uint8_t** bytes,
        svp_t** svp,
        const sa_buffer* buffer,
        size_t bytes_to_process,
        const client_t* client,
        const sa_uuid* caller_uuid) {

    if (bytes == NULL) {
        ERROR("NULL bytes");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp == NULL) {
        ERROR("NULL svp");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (buffer == NULL) {
        ERROR("NULL buffer");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (client == NULL) {
        ERROR("NULL client");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (buffer->buffer_type == SA_BUFFER_TYPE_SVP) {
        svp_store_t* svp_store = client_get_svp_store(client);
        sa_status status = svp_store_acquire_exclusive(svp, svp_store, buffer->context.svp.buffer, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("svp_store_acquire_exclusive failed");
            return status;
        }

        if (buffer->context.svp.offset + bytes_to_process < bytes_to_process) {
            ERROR("Integer overflow");
            return SA_STATUS_INVALID_PARAMETER;
        }

        svp_buffer_t* svp_buffer = svp_get_buffer(*svp);
        size_t length = svp_get_size(svp_buffer);
        if (buffer->context.svp.offset + bytes_to_process > length) {
            ERROR("buffer not large enough");
            return SA_STATUS_INVALID_PARAMETER;
        }

        *bytes = (uint8_t*) svp_get_svp_memory(svp_buffer) + buffer->context.svp.offset;

        // TODO: SoC vendor must verify that memory address is within SVP space.
    } else {
        if (buffer->context.clear.buffer == NULL) {
            ERROR("NULL buffer");
            return SA_STATUS_NULL_PARAMETER;
        }

        if (buffer->context.clear.offset + bytes_to_process < bytes_to_process) {
            ERROR("Integer overflow");
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (buffer->context.clear.offset + bytes_to_process > buffer->context.clear.length) {
            ERROR("buffer not large enough");
            return SA_STATUS_INVALID_PARAMETER;
        }

        *bytes = (uint8_t*) buffer->context.clear.buffer + buffer->context.clear.offset;

        // TODO: SoC vendor must verify that memory address is within SVP space.
    }

    return SA_STATUS_OK;
}
