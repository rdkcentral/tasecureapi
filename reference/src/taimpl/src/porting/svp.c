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
#ifndef DISABLE_SVP
#include "porting/svp.h" // NOLINT
#include "digest.h"
#include "log.h"
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "porting/overflow.h"
#include "stored_key_internal.h"
#include <memory.h>

// An SVP buffer contains a pointer to the SVP memory region and its size.
struct svp_buffer_s {
    void* svp_memory;
    size_t size;
};

static bool svp_validate_buffer(const svp_buffer_t* svp_buffer) {
    if (svp_buffer == NULL) {
        ERROR("NULL svp_buffer");
        return false;
    }

    if (!memory_is_valid_svp(svp_buffer->svp_memory, svp_buffer->size)) {
        ERROR("memory range is not within SVP memory");
        return SA_STATUS_INVALID_PARAMETER;
    }

    return true;
}

bool svp_create_buffer(
        svp_buffer_t** svp_buffer,
        void* svp_memory,
        size_t size) {

    if (svp_buffer == NULL) {
        ERROR("NULL svp_buffer");
        return false;
    }

    if (svp_memory == NULL) {
        ERROR("NULL svp_memory");
        return false;
    }

    if (!memory_is_valid_svp(svp_memory, size)) {
        ERROR("memory range is not within SVP memory");
        return SA_STATUS_INVALID_PARAMETER;
    }

    *svp_buffer = memory_internal_alloc(sizeof(svp_buffer_t));
    if (!*svp_buffer) {
        ERROR("memory_internal_alloc failed");
        return false;
    }

    memory_memset_unoptimizable(*svp_buffer, 0, sizeof(svp_buffer_t));

    (*svp_buffer)->svp_memory = svp_memory;
    (*svp_buffer)->size = size;
    return true;
}

bool svp_release_buffer(
        void** svp_memory,
        size_t* size,
        svp_buffer_t* svp_buffer) {

    if (svp_memory == NULL) {
        ERROR("NULL svp_memory");
        return false;
    }

    if (size == NULL) {
        ERROR("NULL size");
        return false;
    }

    if (svp_buffer == NULL) {
        ERROR("NULL svp_buffer");
        return false;
    }

    *svp_memory = svp_buffer->svp_memory;
    *size = svp_buffer->size;
    svp_buffer->svp_memory = NULL;
    svp_buffer->size = 0;
    memory_internal_free(svp_buffer);
    return true;
}

bool svp_write(
        svp_buffer_t* out_svp_buffer,
        const void* in,
        size_t in_length,
        sa_svp_offset* offsets,
        size_t offsets_length) {

    if (out_svp_buffer == NULL) {
        ERROR("NULL out_svp_buffer");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in");
        return false;
    }

    if (offsets == NULL) {
        ERROR("NULL offsets");
        return false;
    }

    if (!svp_validate_buffer(out_svp_buffer)) {
        ERROR("svp_validate_buffer failed");
        return false;
    }

    for (size_t i = 0; i < offsets_length; i++) {
        size_t range;
        if (add_overflow(offsets[i].out_offset, offsets[i].length, &range)) {
            ERROR("Integer overflow");
            return false;
        }

        if (range > out_svp_buffer->size) {
            ERROR("attempting to write outside the bounds of output secure buffer");
            return false;
        }

        if (add_overflow(offsets[i].in_offset, offsets[i].length, &range)) {
            ERROR("Integer overflow");
            return false;
        }

        if (range > in_length) {
            ERROR("attempting to read outside the bounds of input buffer");
            return false;
        }
    }

    uint8_t* out_bytes = (uint8_t*) out_svp_buffer->svp_memory;
    for (size_t i = 0; i < offsets_length; i++)
        memcpy(out_bytes + offsets[i].out_offset, in + offsets[i].in_offset, offsets[i].length);

    return true;
}

bool svp_copy(
        svp_buffer_t* out_svp_buffer,
        const svp_buffer_t* in_svp_buffer,
        sa_svp_offset* offsets,
        size_t offsets_length) {

    if (out_svp_buffer == NULL) {
        ERROR("NULL out_svp_buffer");
        return false;
    }

    if (in_svp_buffer == NULL) {
        ERROR("NULL in_svp_buffer");
        return false;
    }

    if (offsets == NULL) {
        ERROR("NULL offsets");
        return false;
    }

    if (!svp_validate_buffer(out_svp_buffer)) {
        ERROR("svp_validate_buffer failed");
        return false;
    }

    if (!svp_validate_buffer(in_svp_buffer)) {
        ERROR("svp_validate_buffer failed");
        return false;
    }

    for (size_t i = 0; i < offsets_length; i++) {
        size_t range;
        if (add_overflow(offsets[i].out_offset, offsets[i].length, &range)) {
            ERROR("Integer overflow");
            return false;
        }

        if (range > out_svp_buffer->size) {
            ERROR("attempting to write outside the bounds of output secure buffer");
            return false;
        }

        if (add_overflow(offsets[i].in_offset, offsets[i].length, &range)) {
            ERROR("Integer overflow");
            return false;
        }

        if (range > in_svp_buffer->size) {
            ERROR("attempting to read outside the bounds of input secure buffer");
            return false;
        }
    }

    for (size_t i = 0; i < offsets_length; i++) {
        unsigned long out_position;
        if (add_overflow((unsigned long) out_svp_buffer->svp_memory, offsets[i].out_offset, &out_position)) {
            ERROR("Integer overflow");
            return false;
        }

        unsigned long in_position;
        if (add_overflow((unsigned long) in_svp_buffer->svp_memory, offsets[i].in_offset, &in_position)) {
            ERROR("Integer overflow");
            return false;
        }

        memcpy((void*) out_position, (void*) in_position, offsets[i].length); // NOLINT
    }
    return true;
}
bool svp_key_check(
        uint8_t* in_bytes,
        size_t bytes_to_process,
        const void* expected,
        stored_key_t* stored_key) {

    if (in_bytes == NULL) {
        ERROR("NULL in_bytes");
        return false;
    }

    if (expected == NULL) {
        ERROR("NULL expected");
        return false;
    }

    if (stored_key == NULL) {
        ERROR("NULL stored_key");
        return false;
    }

    bool status = false;
    uint8_t* decrypted = NULL;
    do {
        decrypted = memory_internal_alloc(bytes_to_process);
        if (decrypted == NULL) {
            ERROR("memory_internal_alloc failed");
            break;
        }

        const void* key = stored_key_get_key(stored_key);
        if (key == NULL) {
            ERROR("NULL key");
            break;
        }

        size_t key_length = stored_key_get_length(stored_key);
        if (unwrap_aes_ecb_internal(decrypted, in_bytes, bytes_to_process, key, key_length) != SA_STATUS_OK) {
            ERROR("unwrap_aes_ecb_internal failed");
            break;
        }

        if (memory_memcmp_constant(decrypted, expected, bytes_to_process) != 0) {
            ERROR("decrypted value does not match the expected one");
            break;
        }

        status = true;
    } while (false);

    if (decrypted != NULL) {
        memory_memset_unoptimizable(decrypted, 0, bytes_to_process);
        memory_internal_free(decrypted);
    }

    return status;
}
bool svp_digest(
        void* out,
        size_t* out_length,
        sa_digest_algorithm digest_algorithm,
        const svp_buffer_t* svp_buffer,
        size_t offset,
        size_t length) {

    size_t range;
    if (add_overflow(offset, length, &range)) {
        ERROR("Integer overflow");
        return false;
    }

    if (range > svp_buffer->size) {
        ERROR("attempting to write outside the bounds of output secure buffer");
        return false;
    }

    if (!svp_validate_buffer(svp_buffer)) {
        ERROR("svp_validate_buffer failed");
        return false;
    }

    unsigned long position;
    if (add_overflow((unsigned long) svp_buffer->svp_memory, offset, &position)) {
        ERROR("Integer overflow");
        return false;
    }

    if (digest_sha(out, out_length, digest_algorithm, (uint8_t*) position, length, NULL, 0, NULL, 0) != SA_STATUS_OK) { // NOLINT
        ERROR("digest_sha failed");
        return false;
    }

    return true;
}

void* svp_get_svp_memory(const svp_buffer_t* svp_buffer) {
    if (svp_buffer == NULL)
        return NULL;

    if (!svp_validate_buffer(svp_buffer)) {
        ERROR("svp_validate_buffer failed");
        return NULL;
    }

    return svp_buffer->svp_memory;
}

size_t svp_get_size(const svp_buffer_t* svp_buffer) {
    if (svp_buffer == NULL)
        return 0;

    return svp_buffer->size;
}
#endif // DISABLE_SVP
