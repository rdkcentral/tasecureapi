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

/** @section Description
 * @file client_store.h
 *
 * This file contains the functions and structures implementing storage for client objects.
 * The client object is stored and retrieved using the ta_client value indicating the slot at which
 * it is stored.
 */

#ifndef CLIENT_STORE_H
#define CLIENT_STORE_H

#include "cipher_store.h"
#include "key_store.h"
#include "mac_store.h"
#include "object_store.h"
#include "sa_types.h"
#ifndef DISABLE_SVP
#include "svp_store.h"
#endif // DISABLE_SVP 
#include "ta_sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct client_s client_t;

/**
 * Get the key store.
 *
 * @param[in] client client.
 * @return key store.
 */
key_store_t* client_get_key_store(const client_t* client);

/**
 * Get the cipher store.
 *
 * @param[in] client client.
 * @return cipher store.
 */
cipher_store_t* client_get_cipher_store(const client_t* client);

/**
 * Get the mac store.
 *
 * @param[in] client client.
 * @return mac store.
 */
mac_store_t* client_get_mac_store(const client_t* client);

#ifndef DISABLE_SVP
/**
 * Get the svp store.
 *
 * @param[in] client client.
 * @return svp store.
 */
svp_store_t* client_get_svp_store(const client_t* client);
#endif //DISABLE_SVP

typedef object_store_t client_store_t;

/**
 * Obtain global client store instance. There will be only one instance of this store in the SecApi
 * TA.
 *
 * @return client store
 */
client_store_t* client_store_global();

/**
 * Add a new client to the client store.
 *
 * @param[out] client_slot slot at which the client was stored.
 * @param[in] store store.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation
 */
sa_status client_store_add(
        ta_client* client_slot,
        client_store_t* store,
        const sa_uuid* caller_uuid);

/**
 * Remove the client from the store. This call will block until the client at the specified slot
 * has reference count of 0.
 *
 * @param[in] store store.
 * @param[in] client_slot client to remove.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status client_store_remove(
        client_store_t* store,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Obtain the client at the specified index and increment reference count. Client with reference
 * count greater then 0 is guaranteed not to be deleted.
 *
 * @param[out] client client.
 * @param[in] store store.
 * @param[in] client_slot client slot.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status client_store_acquire(
        client_t** client,
        client_store_t* store,
        ta_client client_slot,
        const sa_uuid* caller_uuid);

/**
 * Decrement the reference count for the client at the specified slot.
 *
 * @param[in] store store.
 * @param[in] client_slot client slot.
 * @param[in] client client.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status client_store_release(
        client_store_t* store,
        ta_client client_slot,
        client_t* client,
        const sa_uuid* caller_uuid);

#ifdef __cplusplus
}
#endif

#endif // CLIENT_STORE_H
