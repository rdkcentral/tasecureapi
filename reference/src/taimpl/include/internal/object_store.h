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
 * @file object_store.h
 *
 * This file contains the functions and structures implementing an object store. Object store
 * stores the objects and provides a slot identifier for referencing them.
 *
 * Object store ensures that only the owner of a specific object can access it. Additionally, it
 * provides a mechanism for ensuring that the contained objects are not deleted while in use.
 */

#ifndef OBJECT_STORE_H
#define OBJECT_STORE_H

#include "sa_types.h"
#include "slots.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct object_store_s object_store_t;

typedef void (*object_free_function)(void*);

/**
 * Create an object store.
 *
 * @param[in] object_free function to be used for freeing contained objects.
 * @param[in] count size of the object store.
 * @return create store instance.
 */
object_store_t* object_store_init(
        object_free_function object_free,
        size_t count);

/**
 * Shutdown object store. Releases any remaining objects.
 *
 * @param[in] store store instance.
 */
void object_store_shutdown(object_store_t* store);

/**
 * Add an object to the store.
 *
 * @param[out] slot slot at which the object was stored.
 * @param[in] store store.
 * @param[in] object object to store.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status object_store_add(
        slot_t* slot,
        object_store_t* store,
        void* object,
        const sa_uuid* caller_uuid);

/**
 * Remove the object at the specified slot from the store. Caller UUID is checked before removing
 * the object. It has to match the caller UUID that was used when adding the object.
 *
 * @param[in] store store.
 * @param[in] slot object slot.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status object_store_remove(
        object_store_t* store,
        slot_t slot,
        const sa_uuid* caller_uuid);

/**
 * Acquire an object in the specified slot. The reference count on the object will be incremented
 * to prevent the deletion of the object while in use. object_store_release must be called once the
 * object is no longer being used to decrement the reference count. Caller UUID is checked
 * before retrieving the object. Object is retrieved only if the caller UUID matches the caller
 * UUID used when adding the object to the store.
 *
 * @param[out] object retrieved object.
 * @param[in] store store.
 * @param[in] slot object slot.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status object_store_acquire(
        void** object,
        object_store_t* store,
        slot_t slot,
        const sa_uuid* caller_uuid);

/**
 * Decrement the reference count on the acquired object. Caller UUID is checked before decrementing
 * the reference count.
 *
 * @param[in] store store.
 * @param[in] slot object slot.
 * @param[in] object object
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status object_store_release(
        object_store_t* store,
        slot_t slot,
        void* object,
        const sa_uuid* caller_uuid);

/**
 * Obtain the size of the store.
 *
 * @param[in] store store.
 * @return number of slots in the store.
 */
size_t object_store_size(object_store_t* store);

#ifdef __cplusplus
}
#endif

#endif // OBJECT_STORE_H
