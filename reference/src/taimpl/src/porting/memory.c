/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
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

#include "porting/memory.h" // NOLINT
#include "log.h"
#include "porting/overflow.h"
#include <stdlib.h>

void* memory_secure_alloc(size_t size) {
    return memory_internal_alloc(size);
}

void* memory_secure_realloc(void* buffer, size_t new_size) {
    return memory_internal_realloc(buffer, new_size);
}

void memory_secure_free(void* buffer) {
    memory_internal_free(buffer);
}

void* memory_internal_alloc(size_t size) {
    return malloc(size);
}

void* memory_internal_realloc(void* buffer, size_t new_size) {
    return realloc(buffer, new_size);
}

void memory_internal_free(void* buffer) {
    free(buffer);
}

int memory_memcmp_constant(const void* in1, const void* in2, size_t length) {
    uint8_t* a = (uint8_t*) in1;
    uint8_t* b = (uint8_t*) in2;

    int result = 0;
    for (size_t i = 0; i < length; ++i) {
        result |= a[i] ^ b[i];
    }

    return result;
}

void* memory_memset_unoptimizable(void* destination, uint8_t value, size_t size) {
    volatile uint8_t* pointer = (uint8_t*) destination;
    if (size == 0)
        return destination;

    while (size--)
        *pointer++ = value;
    return destination;
}

#ifndef DISABLE_SVP
bool memory_is_valid_svp(
        void* memory_location,
        size_t size) {

    if (memory_location == NULL) {
        ERROR("Invalid memory");
        return false;
    }

    size_t temp;
    if (add_overflow((unsigned long) memory_location, size, &temp)) {
        ERROR("Integer overflow");
        return false;
    }

    // TODO: SoC vendor must verify that all bytes between memory_location and memory_location+size are within SVP
    // space.
    return true;
}
#endif // DISABLE_SVP

bool memory_is_valid_clear(
        void* memory_location,
        size_t size) {

    if (memory_location == NULL) {
        ERROR("Invalid memory");
        return false;
    }

    size_t temp;
    if (add_overflow((unsigned long) memory_location, size, &temp)) {
        ERROR("Integer overflow");
        return false;
    }

    // TODO: SoC vendor must verify that all bytes between memory_location and memory_location+size are not within SVP
    // space.
    return true;
}
