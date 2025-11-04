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

#include "porting/init.h"
#include "porting/memory.h"
#include "log.h"

#ifdef MBEDTLS_PLATFORM_MEMORY
#include "pkcs12_mbedtls.h"

static void* mbedtls_secure_calloc(size_t nmemb, size_t size) {
    size_t total_size = nmemb * size;
    void* buffer = memory_secure_alloc(total_size);

    if (buffer != NULL) {
        memory_memset_unoptimizable(buffer, 0, total_size);
    }

    DEBUG("[MBEDTLS_ALLOCATOR] mbedtls_secure_calloc: allocated %zu bytes at %p\n", total_size, buffer);
    return buffer;
}

static void mbedtls_secure_free(void* buffer) {
    if (buffer == NULL) {
        return;
    }
    DEBUG("[MBEDTLS_ALLOCATOR] mbedtls_secure_free: freeing memory at %p\n", buffer);
    memory_secure_free(buffer);
}
#endif

void init_mbedtls_allocator() {
#ifdef MBEDTLS_PLATFORM_MEMORY
    // Configure mbedTLS to use secure heap for all crypto memory allocations
    // This requires mbedTLS to be built with MBEDTLS_PLATFORM_MEMORY defined
    DEBUG("[MBEDTLS_ALLOCATOR] Configuring mbedTLS to use custom secure memory allocators\n");
    mbedtls_platform_set_calloc_free(mbedtls_secure_calloc, mbedtls_secure_free);
    DEBUG("[MBEDTLS_ALLOCATOR] mbedTLS custom allocators configured successfully\n");
#else
    // mbedTLS not built with MBEDTLS_PLATFORM_MEMORY support
    // Using standard library allocators (calloc/free)
    DEBUG("[MBEDTLS_ALLOCATOR] WARNING: MBEDTLS_PLATFORM_MEMORY not defined - using standard library allocators\n");
#endif
}
