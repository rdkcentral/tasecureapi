/*
 * Copyright 2019-2023 Comcast Cable Communications Management, LLC
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

#include "digest.h"
#include "log.h"
#include "porting/memory.h"
#include "porting/otp_internal.h"
#include "porting/overflow.h"
#include "porting/svp_internal.h"
#include "stored_key_internal.h"
#include <memory.h>

// This is sample code for example purposes only and matches the definition in svp.h.
typedef struct {
    size_t svp_memory_size;
    uint8_t* svp_memory;
} svp_memory_s;

sa_status svp_supported() {
    return SA_STATUS_OK;
}

bool svp_write(
        void* out,
        const void* in,
        size_t in_length,
        sa_svp_offset* offsets,
        size_t offsets_length) {

    if (out == NULL) {
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

    size_t size = svp_get_size(out);
    for (size_t i = 0; i < offsets_length; i++) {
        size_t range;
        if (add_overflow(offsets[i].out_offset, offsets[i].length, &range)) {
            ERROR("Integer overflow");
            return false;
        }

        if (range > size) {
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

    uint8_t* out_bytes = svp_get_svp_memory(out);
    for (size_t i = 0; i < offsets_length; i++)
        memcpy(out_bytes + offsets[i].out_offset, in + offsets[i].in_offset, offsets[i].length);

    return true;
}

bool svp_copy(
        void* out,
        void* in,
        sa_svp_offset* offsets,
        size_t offsets_length) {

    if (out == NULL) {
        ERROR("NULL out_svp_buffer");
        return false;
    }

    if (in == NULL) {
        ERROR("NULL in_svp_buffer");
        return false;
    }

    if (offsets == NULL) {
        ERROR("NULL offsets");
        return false;
    }

    size_t out_size = svp_get_size(out);
    size_t in_size = svp_get_size(in);
    for (size_t i = 0; i < offsets_length; i++) {
        size_t range;
        if (add_overflow(offsets[i].out_offset, offsets[i].length, &range)) {
            ERROR("Integer overflow");
            return false;
        }

        if (range > out_size) {
            ERROR("attempting to write outside the bounds of output secure buffer");
            return false;
        }

        if (add_overflow(offsets[i].in_offset, offsets[i].length, &range)) {
            ERROR("Integer overflow");
            return false;
        }

        if (range > in_size) {
            ERROR("attempting to read outside the bounds of input secure buffer");
            return false;
        }
    }

    uint8_t* out_bytes = svp_get_svp_memory(out);
    uint8_t* in_bytes = svp_get_svp_memory(in);
    for (size_t i = 0; i < offsets_length; i++) {
        unsigned long out_position;
        if (add_overflow((unsigned long) out_bytes, offsets[i].out_offset, &out_position)) {
            ERROR("Integer overflow");
            return false;
        }

        unsigned long in_position;
        if (add_overflow((unsigned long) in_bytes, offsets[i].in_offset, &in_position)) {
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
        void* svp_buffer,
        size_t offset,
        size_t length) {

    size_t range;
    if (add_overflow(offset, length, &range)) {
        ERROR("Integer overflow");
        return false;
    }

    size_t size = svp_get_size(svp_buffer);
    if (range > size) {
        ERROR("attempting to read outside the bounds of input secure buffer");
        return false;
    }

    unsigned long position;
    if (add_overflow((unsigned long) svp_get_svp_memory(svp_buffer), offset, &position)) {
        ERROR("Integer overflow");
        return false;
    }

    if (digest_sha(out, out_length, digest_algorithm, (uint8_t*) position, length, NULL, 0, NULL, 0) != SA_STATUS_OK) { // NOLINT
        ERROR("digest_sha failed");
        return false;
    }

    return true;
}

void* svp_get_svp_memory(void* svp_memory) {
    if (svp_memory == NULL)
        return NULL;

    svp_memory_s* svp = (svp_memory_s*) svp_memory;
    if (!memory_is_valid_svp(svp->svp_memory, svp->svp_memory_size)) {
        ERROR("memory range is not within SVP memory");
        return NULL;
    }

    return svp->svp_memory;
}

size_t svp_get_size(const void* svp_memory) {
    if (svp_memory == NULL)
        return 0;

    return ((svp_memory_s*) svp_memory)->svp_memory_size;
}
