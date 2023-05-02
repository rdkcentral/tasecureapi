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

/** @section Description
 * @file key_store.h
 *
 * This file contains the functions and structures implementing storage for loaded key objects.
 * Keys are stored and retrieved using the value indicating the slot at which they are
 * stored. This mechanism allows applications to reference MAC context objects stored in a TA
 * without having explicit pointers to them.
 *
 * Keys are encrypted in the storage, and are only decrypted during the operations that use them.
 * This adds additional level of protection for the key material while not in use.
 */

#ifndef KEY_STORE_H
#define KEY_STORE_H

#include "object_store.h"
#include "sa_types.h"
#include "stored_key.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef object_store_t key_store_t;

/**
 * Create and initialize a new keystore.
 *
 * @param[in] size number of key slots in the keystore.
 * @return key store instance.
 */
key_store_t* key_store_init(size_t size);

/**
 * Release a keystore. If any keys are still contained in it, they will be released.
 *
 * @param[in] store key store.
 */
void key_store_shutdown(key_store_t* store);

/**
 * Import a clear key into the store.
 *
 * @param[out] key key slot of the exported key.
 * @param[in] store keystore.
 * @param[in] stored_key key to wrap.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status key_store_import_stored_key(
        sa_key* key,
        key_store_t* store,
        stored_key_t* stored_key,
        const sa_uuid* caller_uuid);

/**
 * Import exported key into the key store.
 *
 * @param[out] key key slot of the imported key.
 * @param[in] store key store.
 * @param[in] exported exported buffer.
 * @param[in] exported_length exported buffer length.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status key_store_import_exported(
        sa_key* key,
        key_store_t* store,
        const void* exported,
        size_t exported_length,
        const sa_uuid* caller_uuid);

/**
 * Export the keystore key.
 *
 * @param[out] out output buffer.
 * @param[in,out] out_length output buffer length.
 * @param[in] store key store.
 * @param[in] key key slot to export.
 * @param[in] mixin mixin value. If NULL, default 0x00000000000000000000000000000000 is used.
 * @param[in] mixin_length mixin length. Has to be 16 if mixin is not NULL.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status key_store_export(
        void* out,
        size_t* out_length,
        key_store_t* store,
        sa_key key,
        const void* mixin,
        size_t mixin_length,
        const sa_uuid* caller_uuid);

/**
 * Unwrap a keystore key. The returned key should be short lived (only during the request servicing
 * lifetime), and released as soon as possible.
 *
 * @param[out] stored_key clear key output pointer.
 * @param[in] store key store.
 * @param[in] key key slot.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status key_store_unwrap(
        stored_key_t** stored_key,
        key_store_t* store,
        sa_key key,
        const sa_uuid* caller_uuid);

/**
 * Retrieves the header of a keystore key.
 *
 * @param[out] header the header in which to copy the information.
 * @param[in] store key store.
 * @param[in] key key slot.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status key_store_get_header(
        sa_header* header,
        key_store_t* store,
        sa_key key,
        const sa_uuid* caller_uuid);

/**
 * Release the key in the key slot.
 *
 * @param[in] store key store.
 * @param[in] key key slot.
 * @param[in] caller_uuid caller UUID.
 */
sa_status key_store_remove(
        key_store_t* store,
        sa_key key,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // KEY_STORE_H
