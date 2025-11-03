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

#include "client_store.h"
#include "log.h"
#include "porting/init.h"
#include "ta_sa.h"

sa_status ta_sa_init(
        ta_client* client_slot,
        const sa_uuid* caller_uuid) {

    static bool mbedtls_allocator_inited = false;
    if (!mbedtls_allocator_inited) {
        mbedtls_allocator_inited = true;
        init_mbedtls_allocator();
    }

    if (client_slot == NULL) {
        ERROR("NULL client_slot");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    client_store_t* client_store = client_store_global();
    sa_status status = client_store_add(client_slot, client_store, caller_uuid);
    if (status != SA_STATUS_OK) {
        ERROR("client_store_add failed");
        return status;
    }

    return SA_STATUS_OK;
}
