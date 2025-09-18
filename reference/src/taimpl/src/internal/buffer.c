/*
 * Copyright 2019-2025 Comcast Cable Communications Management, LLC
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
#include "porting/memory.h"
#include "porting/overflow.h"

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

    if (buffer->buffer_type == SA_BUFFER_TYPE_CLEAR) {
        if (buffer->context.clear.buffer == NULL) {
            ERROR("NULL buffer");
            return SA_STATUS_NULL_PARAMETER;
        }

        size_t memory_range;
        if (add_overflow(buffer->context.clear.offset, bytes_to_process, &memory_range)) {
            ERROR("Integer overflow");
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (memory_range > buffer->context.clear.length) {
            ERROR("buffer not large enough");
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (!memory_is_valid_clear(buffer->context.clear.buffer, buffer->context.clear.length)) {
            ERROR("memory range is not within clear memory");
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (add_overflow((unsigned long) buffer->context.clear.buffer, buffer->context.clear.offset,
                    (unsigned long*) bytes)) {
            ERROR("Integer overflow");
            return SA_STATUS_INVALID_PARAMETER;
        }
    }
#ifndef DISABLE_SVP
    else if (buffer->buffer_type == SA_BUFFER_TYPE_SVP) {
        svp_store_t* svp_store = client_get_svp_store(client);
        sa_status status = svp_store_acquire_exclusive(svp, svp_store, buffer->context.svp.buffer, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("svp_store_acquire_exclusive failed");
            return status;
        }

        size_t memory_range;
        if (add_overflow(buffer->context.svp.offset, bytes_to_process, &memory_range)) {
            ERROR("Integer overflow");
            return SA_STATUS_INVALID_PARAMETER;
        }

        svp_buffer_t* svp_buffer = svp_get_buffer(*svp);

        // This call validates that SVP buffer is contained entirely within SVP memory.
        void* memory_location = svp_get_svp_memory(svp_buffer);
        if (memory_location == NULL) {
            ERROR("memory range is not within SVP memory");
            return SA_STATUS_INVALID_PARAMETER;
        }

        size_t memory_size = svp_get_size(svp_buffer);
        if (memory_range > memory_size) {
            ERROR("buffer not large enough");
            return SA_STATUS_INVALID_PARAMETER;
        }

        if (add_overflow((unsigned long) memory_location, buffer->context.svp.offset, (unsigned long*) bytes)) {
            ERROR("Integer overflow");
            return SA_STATUS_INVALID_PARAMETER;
        }

    }
#endif // DISABLE_SVP

    return SA_STATUS_OK;
}
