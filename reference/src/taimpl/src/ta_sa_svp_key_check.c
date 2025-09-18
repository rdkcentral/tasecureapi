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
#include "buffer.h"
#include "client_store.h"
#include "common.h"
#include "key_type.h"
#include "log.h"
#include "porting/transport.h"
#include "rights.h"
#include "ta_sa.h"
#include "unwrap.h"

sa_status ta_sa_svp_key_check(
        sa_key key,
        sa_buffer* in,
        size_t bytes_to_process,
        const void* expected,
        size_t expected_length,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (bytes_to_process % AES_BLOCK_SIZE != 0) {
        ERROR("Invalid in_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (expected == NULL) {
        ERROR("NULL expected");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (expected_length != bytes_to_process) {
        ERROR("Invalid expected_length");
        return SA_STATUS_INVALID_PARAMETER;
    }

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    stored_key_t* stored_key = NULL;
    svp_t* in_svp = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        key_store_t* key_store = client_get_key_store(client);
        status = key_store_unwrap(&stored_key, key_store, key, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("key_store_unwrap failed");
            break;
        }

        const sa_header* header = stored_key_get_header(stored_key);
        if (header == NULL) {
            ERROR("stored_key_get_header failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        if (!rights_allowed_decrypt(&header->rights, header->type)) {
            ERROR("rights_allowed_decrypt failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (in->buffer_type == SA_BUFFER_TYPE_CLEAR && !rights_allowed_clear(&header->rights)) {
            ERROR("rights_allowed_clear failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (in->buffer_type == SA_BUFFER_TYPE_SVP && is_ree(caller_uuid)) {
            ERROR("ta_sa_svp_buffer_check can only be called by a TA when buffer type is SVP");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (!key_type_supports_aes(header->type, header->size)) {
            ERROR("key_type_supports_aes failed");
            status = SA_STATUS_INVALID_KEY_TYPE;
            break;
        }

        uint8_t* in_bytes = NULL;
        status = convert_buffer(&in_bytes, &in_svp, in, bytes_to_process, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("convert_buffer failed");
            break;
        }

        if (!svp_key_check(in_bytes, bytes_to_process, expected, stored_key)) {
            ERROR("decrypted value does not match the expected one");
            status = SA_STATUS_VERIFICATION_FAILED;
            break;
        }

        status = SA_STATUS_OK;
    } while (false);
    if (in_svp != NULL)
        svp_store_release_exclusive(client_get_svp_store(client), in->context.svp.buffer, in_svp, caller_uuid);
    stored_key_free(stored_key);
    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
#endif // DISABLE_SVP
