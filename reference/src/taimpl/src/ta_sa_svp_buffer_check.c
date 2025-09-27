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
#include "digest_util.h"
#include "log.h"
#include "porting/memory.h"
#include "porting/transport.h"
#include "ta_sa.h"

sa_status ta_sa_svp_buffer_check(
        sa_svp_buffer svp_buffer,
        size_t offset,
        size_t length,
        sa_digest_algorithm digest_algorithm,
        const void* hash,
        size_t hash_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (hash == NULL) {
        ERROR("NULL hash");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (is_ree(caller_uuid)) {
        ERROR("ta_sa_svp_buffer_check can only be called by a TA");
        return SA_STATUS_OPERATION_NOT_ALLOWED;
    }

    size_t required_length = digest_length(digest_algorithm);

    if (hash_length != required_length) {
        ERROR("Invalid hash_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    svp_store_t* svp_store = NULL;
    svp_t* svp = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        svp_store = client_get_svp_store(client);
        status = svp_store_acquire_exclusive(&svp, svp_store, svp_buffer, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("svp_store_acquire_exclusive failed");
            break;
        }

        svp_buffer_t* svp_buf = svp_get_buffer(svp);
        size_t buffer_digest_length = required_length;
        uint8_t buffer_digest[required_length];
        if (!svp_digest(buffer_digest, &buffer_digest_length, digest_algorithm, svp_buf, offset, length)) {
            ERROR("digest_sha failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (buffer_digest_length != hash_length || memory_memcmp_constant(buffer_digest, hash, hash_length) != 0) {
            ERROR("hashes don't match");
            status = SA_STATUS_VERIFICATION_FAILED;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);

    if (svp != NULL)
        svp_store_release_exclusive(svp_store, svp_buffer, svp, caller_uuid);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
#endif // DISABLE_SVP
