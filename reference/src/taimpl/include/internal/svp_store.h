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
 * @file svp_store.h
 *
 * This file contains the functions and structures implementing storage for SVP buffer objects.
 * The buffer object is stored and retrieved using the value indicating the slot at which it
 * is stored. This mechanism allows applications to reference SVP buffer objects stored in a TA
 * without having explicit pointers to them.
 */
#ifndef SVP_STORE_H
#define SVP_STORE_H

#include "object_store.h"
#include "porting/svp.h"
#include "sa_types.h"
#include "ta_sa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct svp_s svp_t;
/**
 * Identifies if SVP is supported.
 *
 * @return SA_STATUS_OK if supported. SA_STATUS_OPERATION_NOT_SUPPORTED if not supported.
 */
sa_status svp_supported();

#ifndef DISABLE_SVP
typedef object_store_t svp_store_t;

/**
 * Get SVP buffer.
 *
 * @param[in] svp the SVP structure to retrieve the buffer from.
 * @return the SVP buffer.
 */
svp_buffer_t* svp_get_buffer(const svp_t* svp);

/**
 * Create and initialize a new svp store.
 *
 * @param[in] size number of svp slots in the store.
 * @return store instance.
 */
svp_store_t* svp_store_init(size_t size);

/**
 * Release a store. If any svps are still contained in it, they will be released.
 *
 * @param[in] store store instance
 */
void svp_store_shutdown(svp_store_t* store);


/**
 * Takes a previously allocated SVP region and adds it to the SVP store.
 *
 * @param[out] svp_buffer slot at which the svp is stored.
 * @param[in] store the SVP store instance.
 * @param[out] svp_memory a reference to the SVP memory region.
 * @param[out] size the length of the SVP memory region.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status svp_store_create(
        sa_svp_buffer* svp_buffer,
        svp_store_t* store,
        void* svp_memory,
        size_t size,
        const sa_uuid* caller_uuid);

/**
 * Remove an svp from the store and return the SVP buffer to the caller. out must be free'd by the caller.
 *
 * @param[out] svp_memory a reference to the SVP memory region.
 * @param[out] size the size of the SVP memory region.
 * @param[in] store the SVP store instance.
 * @param[in] svp_buffer slot of the SVP buffer to remove.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation
 */
sa_status svp_store_release(
        void** svp_memory,
        size_t* size,
        svp_store_t* store,
        sa_svp_buffer svp_buffer,
        const sa_uuid* caller_uuid);

/**
 * Obtain the svp at the specified index and increase reference count. All other attempts to
 * acquire the same svp will block until the svp is released. svp with reference count greater then
 * 0 is guaranteed not to be deleted.
 *
 * @param[out] svp output svp buffer.
 * @param[in] store the SVP store instance.
 * @param[in] svp_buffer slot of the SVP buffer.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status svp_store_acquire_exclusive(
        svp_t** svp,
        svp_store_t* store,
        sa_svp_buffer svp_buffer,
        const sa_uuid* caller_uuid);

/**
 * Release the svp at the specified slot. Unlock the mutex on the svp.
 *
 * @param[in] store the SVP store instance.
 * @param[in] svp_buffer the slot to release.
 * @param[in] svp svp instance to release.
 * @param[in] caller_uuid caller UUID.
 * @return status of the operation.
 */
sa_status svp_store_release_exclusive(
        svp_store_t* store,
        sa_svp_buffer svp_buffer,
        svp_t* svp,
        const sa_uuid* caller_uuid);

#endif // DISABLE_SVP
#ifdef __cplusplus
}
#endif

#endif // SVP_STORE_H
