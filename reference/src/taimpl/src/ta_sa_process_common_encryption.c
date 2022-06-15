/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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

#include "buffer.h"
#include "cenc.h"
#include "common.h"
#include "log.h"
#include "rights.h"

static sa_status verify_sample(
        sa_sample* sample,
        client_t* client,
        cipher_store_t* cipher_store,
        const sa_uuid* caller_uuid) {

    if (sample->iv == NULL) {
        ERROR("NULL iv");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (sample->iv_length != AES_BLOCK_SIZE) {
        ERROR("Invalid iv_length");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (sample->subsample_lengths == NULL) {
        ERROR("NULL subsample_lengths");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (sample->subsample_count < 1) {
        ERROR("Invalid subsample_count");
        return SA_STATUS_BAD_PARAMETER;
    }

    if (sample->out == NULL) {
        ERROR("NULL out");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (sample->in == NULL) {
        ERROR("NULL in");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (sample->crypt_byte_block == 0 && sample->skip_byte_block != 0) {
        ERROR("Invalid skip_byte_block");
        return SA_STATUS_BAD_PARAMETER;
    }

    sa_status status;
    cipher_t* cipher = NULL;
    svp_t* out_svp = NULL;
    svp_t* in_svp = NULL;
    do {
        status = cipher_store_acquire_exclusive(&cipher, cipher_store, sample->context, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_acquire_exclusive failed");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        sa_cipher_mode cipher_mode = cipher_get_mode(cipher);
        if (cipher_mode != SA_CIPHER_MODE_DECRYPT) {
            ERROR("cipher mode not decrypt");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        const sa_rights* rights = cipher_get_key_rights(cipher);
        if (rights == NULL) {
            ERROR("cipher_get_key_rights failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        if (!rights_allowed_decrypt(rights, SA_KEY_TYPE_SYMMETRIC)) {
            ERROR("rights_allowed_decrypt failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        if (sample->out->buffer_type != SA_BUFFER_TYPE_CLEAR && sample->out->buffer_type != SA_BUFFER_TYPE_SVP) {
            ERROR("Invalid out buffer type");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        if (sample->in->buffer_type != SA_BUFFER_TYPE_CLEAR && sample->in->buffer_type != SA_BUFFER_TYPE_SVP) {
            ERROR("Invalid in buffer type");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        sa_cipher_algorithm cipher_algorithm = cipher_get_algorithm(cipher);
        if (cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR && cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CBC) {
            ERROR("Bad algorithm");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        if (sample->out->buffer_type == SA_BUFFER_TYPE_CLEAR && sample->in->buffer_type != sample->out->buffer_type) {
            ERROR("buffer_type mismatch");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }

        if (sample->out->buffer_type == SA_BUFFER_TYPE_CLEAR && !rights_allowed_clear(rights)) {
            ERROR("rights_allowed_clear failed");
            status = SA_STATUS_OPERATION_NOT_ALLOWED;
            break;
        }

        // Check out buffer length.
        size_t required_length = cenc_get_required_length(sample->subsample_lengths, sample->subsample_count);
        uint8_t* out_bytes = NULL;
        status = convert_buffer(&out_bytes, &out_svp, sample->out, required_length, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("convert_buffer failed");
            break;
        }

        // Check in buffer length.
        uint8_t* in_bytes = NULL;
        status = convert_buffer(&in_bytes, &in_svp, sample->in, required_length, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("convert_buffer failed");
            break;
        }

        // Check if the buffers overlap.
        if (sample->out->buffer_type == SA_BUFFER_TYPE_CLEAR && sample->in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
            uint8_t* out = (uint8_t*) sample->out->context.clear.buffer;
            uint8_t* out_end = (uint8_t*) sample->out->context.clear.buffer + sample->out->context.clear.offset;
            uint8_t* in = (uint8_t*) sample->in->context.clear.buffer;
            uint8_t* in_end = (uint8_t*) sample->in->context.clear.buffer + sample->in->context.clear.offset;
            if ((out >= in && out <= in_end) || (out_end >= in && out_end <= in_end) || (in >= out && in <= out_end) ||
                    (in_end >= out && in_end <= out_end)) {
                ERROR("Overlapping in and out buffers");
                status = SA_STATUS_BAD_PARAMETER;
                break;
            }
        } else if (sample->out->buffer_type == SA_BUFFER_TYPE_SVP && sample->in->buffer_type == SA_BUFFER_TYPE_SVP &&
                   sample->out->context.svp.buffer == sample->in->context.svp.buffer) {
            ERROR("Overlapping in and out buffers");
            status = SA_STATUS_BAD_PARAMETER;
            break;
        }
    } while (false);

    if (in_svp != NULL)
        svp_store_release_exclusive(client_get_svp_store(client), sample->in->context.svp.buffer, in_svp, caller_uuid);

    if (out_svp != NULL)
        svp_store_release_exclusive(client_get_svp_store(client), sample->out->context.svp.buffer, out_svp,
                caller_uuid);

    if (cipher != NULL)
        cipher_store_release_exclusive(cipher_store, sample->context, cipher, caller_uuid);

    return status;
}

sa_status ta_sa_process_common_encryption(
        size_t samples_length,
        sa_sample* samples,
        ta_client client_slot,
        const sa_uuid* caller_uuid) {

    if (caller_uuid == NULL) {
        ERROR("NULL caller_uuid");
        return SA_STATUS_NULL_PARAMETER;
    }

    if (samples == NULL) {
        ERROR("NULL samples");
        return SA_STATUS_NULL_PARAMETER;
    }

    sa_status status;
    client_store_t* client_store = client_store_global();
    client_t* client = NULL;
    cipher_store_t* cipher_store = NULL;
    do {
        status = client_store_acquire(&client, client_store, client_slot, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("client_store_acquire failed");
            break;
        }

        cipher_store = client_get_cipher_store(client);

        for (size_t i = 0; status == SA_STATUS_OK && i < samples_length; i++) {
            status = verify_sample(&samples[i], client, cipher_store, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("verify_sample failed");
            }
        }

        for (size_t i = 0; status == SA_STATUS_OK && i < samples_length; i++) {
            status = cenc_process_sample(&samples[i], client, cipher_store, caller_uuid);
            if (status != SA_STATUS_OK) {
                ERROR("cenc_process_sample failed");
            }
        }
    } while (false);

    client_store_release(client_store, client_slot, client, caller_uuid);

    return status;
}
