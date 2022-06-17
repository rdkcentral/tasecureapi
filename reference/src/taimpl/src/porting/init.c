/**
 * Copyright 2020-2021 Comcast Cable Communications Management, LLC
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
#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void* openssl_secure_malloc(size_t size) {
#else

static void* openssl_secure_malloc(size_t size, const char* file, int line) {
#endif
    void* buffer = memory_secure_alloc(size);

    if (buffer != NULL) {
        memory_memset_unoptimizable(buffer, 0, size);
    }

    return buffer;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void* openssl_secure_realloc(void* buffer, size_t size) {
#else

static void* openssl_secure_realloc(void* buffer, size_t size, const char* file, int line) {
#endif
    return memory_secure_realloc(buffer, size);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static void openssl_secure_free(void* buffer) {
#else

static void openssl_secure_free(void* buffer, const char* file, int line) {
#endif
    memory_secure_free(buffer);
}

void init_openssl_allocator() {
    // use secure heap for OpenSSL memory allocations
    CRYPTO_set_mem_functions(openssl_secure_malloc, openssl_secure_realloc, openssl_secure_free);
}
