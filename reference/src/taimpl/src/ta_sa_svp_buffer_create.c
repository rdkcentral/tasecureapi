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
#ifndef DISABLE_SVP

#include "client_store.h"
#include "log.h"
#include "svp_store.h"
#include "ta_sa.h"

sa_status ta_sa_svp_buffer_create(
        sa_svp_buffer* svp_buffer,
        void* buffer,
        size_t size,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (svp_buffer == NULL) {
        ERROR("NULL svp_buffer");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        svp_store_t* svp_store = client_get_svp_store(client);
        status = svp_store_create(svp_buffer, svp_store, buffer, size, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("svp_store_alloc failed");
            break;
        }
    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
#endif
