/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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

#ifndef SA_PROVIDER_INTERNAL_H
#define SA_PROVIDER_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "sa_provider.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include "sa.h"
#include <openssl/core_dispatch.h>
#include <stdatomic.h>

typedef struct {
    const OSSL_CORE_HANDLE* handle;
    OSSL_LIB_CTX* lib_ctx;
} sa_provider_context;

typedef struct {
    atomic_int reference_count;
    sa_provider_context* provider_context;
    int type;
    const char* name;
    sa_key private_key;
    sa_header private_key_header;
    EVP_PKEY* public_key;
    bool delete_key;
} sa_provider_key_data;

/**
 * Duplicates a sa_provider_key_data object.
 *
 * @param key_data the sa_provider_key_data object to duplicate.
 * @return the duplicated sa_provider_key_data object.
 */
sa_provider_key_data* sa_provider_key_data_dup(sa_provider_key_data* key_data);

/**
 * Frees a sa_provider_key_data object.
 *
 * @param key_data the sa_provider_key_data object to free.
 * @return the duplicate sa_provider_key_data object.
 */
void sa_provider_key_data_free(sa_provider_key_data* key_data);

#endif

#ifdef __cplusplus
}
#endif

#endif //SA_PROVIDER_INTERNAL_H
