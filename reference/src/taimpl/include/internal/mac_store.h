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

/** @section Description
 * @file mac_store.h
 *
 * This file contains the functions and structures implementing storage for MAC context objects.
 * The context object is stored and retrieved using the value indicating the slot at which it
 * is stored. This mechanism allows applications to reference MAC context objects stored in a TA
 * without having explicit pointers to them.
 */

#ifndef MAC_STORE_H
#define MAC_STORE_H

#include "cmac_context.h"
#include "hmac_context.h"
#include "object_store.h"
#include "sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mac_s mac_t;

/**
 * Get algorithm.
 *
 * @param[in] mac mac.
 * @return algorithm.
 */
sa_mac_algorithm mac_get_algorithm(const mac_t* mac);

/**
 * Get HMAC context.
 *
 * @param[in] mac mac.
 * @return HMAC context.
 */
hmac_context_t* mac_get_hmac_context(const mac_t* mac);

/**
 * Get CMAC context.
 *
 * @param[in] mac mac.
 * @return CMAC context.
 */
cmac_context_t* mac_get_cmac_context(const mac_t* mac);

typedef object_store_t mac_store_t;

/**
 * Create and initialize a new mac store.
 *
 * @param[in] size number of mac slots in the store.
 * @return store instance.
 */
mac_store_t* mac_store_init(size_t size);

/**
 * Release a store. If any macs are still contained in it, they will be released.
 *
 * @param[in] store store instance
 */
void mac_store_shutdown(mac_store_t* store);

/**
 * Add an HMAC to the store.
 *
 * @param[out] context slot at which the mac is stored
 * @param[in] store store
 * @param[in] hmac_context HMAC context
 * @param[in] caller_uuid caller UUID
 * @return status of the operation
 */
sa_status mac_store_add_hmac_context(
        sa_crypto_mac_context* context,
        mac_store_t* store,
        hmac_context_t* hmac_context,
        const sa_uuid* caller_uuid);

/**
 * Add an CMAC to the store.
 *
 * @param[out] context slot at which the mac is stored
 * @param[in] store store
 * @param[in] cmac_context CMAC context
 * @param[in] caller_uuid caller UUID
 * @return status of the operation
 */
sa_status mac_store_add_cmac_context(
        sa_crypto_mac_context* context,
        mac_store_t* store,
        cmac_context_t* cmac_context,
        const sa_uuid* caller_uuid);

/**
 * Remove a mac from the store.
 *
 * @param[in] store store
 * @param[in] context slot of the cipher to remove
 * @param[in] caller_uuid caller UUID
 * @return status of the operation
 */
sa_status mac_store_remove(
        mac_store_t* store,
        sa_crypto_mac_context context,
        const sa_uuid* caller_uuid);

/**
 * Obtain the mac at the specified index and increase reference count. All other attempts to
 * acquire the same mac will block until the mac is released. Mac with reference count greater then
 * 0 is guaranteed not to be deleted.
 *
 * @param[out] mac output mac pointer
 * @param[in] store store
 * @param[in] slot slot
 * @param[in] caller_uuid caller UUID
 * @return status of the operation
 */
sa_status mac_store_acquire_exclusive(
        mac_t** mac,
        mac_store_t* store,
        size_t slot,
        const sa_uuid* caller_uuid);

/**
 * Release the mac at the specified slot. Unlock the mutex on the mac.
 *
 * @param[in] store store
 * @param[in] context slot
 * @param[in] mac mac to release
 * @param[in] caller_uuid caller UUID
 * @return status of the operation
 */
sa_status mac_store_release_exclusive(
        mac_store_t* store,
        sa_crypto_mac_context context,
        mac_t* mac,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // MAC_STORE_H
