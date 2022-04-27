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

#include "client_store.h"
#include "common.h"
#include "key_store.h"
#include "log.h"
#include "ta_sa.h"

sa_status ta_sa_key_export(
        void* out,
        size_t* out_length,
        const void* mixin,
        size_t mixin_length,
        sa_key key,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_INTERNAL_ERROR;
    }

    if (out_length == NULL) {
        ERROR("NULL out_length");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (mixin && mixin_length != SYM_128_KEY_SIZE) {
        ERROR("Bad mixin_length");
        return SA_STATUS_BAD_PARAMETER;
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

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_export(out, out_length, key_store, key, mixin, mixin_length, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_export failed");
            break;
        }
    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
