/**
* Copyright 2022 Comcast Cable Communications Management, LLC
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

#include "cenc.h" // NOLINT
#include "buffer.h"
#include "common.h"
#include "log.h"
#include "sa_cenc.h"
#include "sa_types.h"
#include "symmetric.h"
#include <arpa/inet.h>
#include <memory.h>

#ifdef __APPLE__
#define htobe64(x) htonll(x)
#define be64toh(x) ntohll(x)
#endif

#define MIN(A, B) ((A) <= (B) ? (A) : (B))

static bool decrypt(
        uint8_t* out_bytes,
        uint8_t* in_bytes,
        size_t bytes_to_process,
        size_t* enc_byte_count,
        uint8_t* iv,
        sa_cipher_algorithm cipher_algorithm,
        const symmetric_context_t* symmetric_context) {

    // For AES-CTR mode, IV is an 8 byte nonce followed by an 8 byte counter. Openssl as well as other implementations
    // treat all 16 bytes as a counter. This code accounts for the rollover condition.

    // Determine if the iv will rollover. If not, decrypt the whole block.
    uint64_t* counterBuffer = (uint64_t*) (iv + 8);
    size_t initial_block_size = AES_BLOCK_SIZE - *enc_byte_count % AES_BLOCK_SIZE;
    size_t number_of_blocks = (bytes_to_process - initial_block_size) / AES_BLOCK_SIZE +
                              (initial_block_size == AES_BLOCK_SIZE ? 1 : 0);
    bool counter_rollover = (*counterBuffer + number_of_blocks) < *counterBuffer;

    bool first_block = true;
    for (size_t bytes_encrypted = 0; bytes_to_process > bytes_encrypted;) {
        if (!counter_rollover && cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
            // This is an AES-CTR cipher and the counter portion of the IV is going to rollover, so encrypt each block
            // individually and manually increment the IV between each block.

            // The very first block can be a partial block which is a continuation of the previous partial block from
            // the previous sub-sample. The last block can also be a partial block. All of the blocks in between are
            // 16 bytes.
            size_t remaining_in_block = MIN(AES_BLOCK_SIZE - *enc_byte_count % AES_BLOCK_SIZE,
                    bytes_to_process - bytes_encrypted);

            // Only update the IV on the first block if it is not a partial continuation block. Update it for all
            // subsequent blocks.
            if (!first_block || remaining_in_block == AES_BLOCK_SIZE) {
                if (!symmetric_context_set_iv(symmetric_context, iv, AES_BLOCK_SIZE)) {
                    ERROR("symmetric_context_set_iv failed");
                    return false;
                }
            }

            if (!symmetric_context_decrypt(symmetric_context, out_bytes + bytes_encrypted, in_bytes + bytes_encrypted,
                        remaining_in_block)) {
                ERROR("symmetric_context_decrypt failed");
                return false;
            }

            // Increment the IV after every full block.
            if ((*enc_byte_count + remaining_in_block) % AES_BLOCK_SIZE == 0) {
                (*counterBuffer) = htobe64(be64toh(*counterBuffer) + 1);
            }

            bytes_encrypted += remaining_in_block;
            *enc_byte_count += remaining_in_block;
        } else {
            // The IV counter is not going to rollover or this is an AES-CBC CIPHER. Openssl and other implementations
            // handle this automatically.
            if (!symmetric_context_decrypt(symmetric_context, out_bytes + bytes_encrypted, in_bytes + bytes_encrypted,
                        bytes_to_process)) {
                ERROR("symmetric_context_decrypt failed");
                return false;
            }

            (*counterBuffer) = htobe64(be64toh(*counterBuffer) + number_of_blocks);
            bytes_encrypted += bytes_to_process;
            *enc_byte_count += bytes_to_process;
        }

        first_block = false;
    }

    return true;
}

size_t cenc_get_required_length(
        sa_subsample_length* subsample_lengths,
        size_t subsample_count) {

    size_t required_length = 0;
    for (size_t i = 0; i < subsample_count; i++) {
        required_length += subsample_lengths[i].bytes_of_clear_data + subsample_lengths[i].bytes_of_protected_data;
    }

    return required_length;
}

sa_status cenc_process_sample(
        sa_sample* sample,
        client_t* client,
        cipher_store_t* cipher_store,
        const sa_uuid* caller_uuid) {

    sa_status status;
    cipher_t* cipher = NULL;
    svp_t* out_svp = NULL;
    svp_t* in_svp = NULL;
    do {
        status = cipher_store_acquire_exclusive(&cipher, cipher_store, sample->context, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("cipher_store_acquire_exclusive failed");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

        size_t required_length = cenc_get_required_length(sample->subsample_lengths, sample->subsample_count);
        uint8_t* out_bytes = NULL;
        status = convert_buffer(&out_bytes, &out_svp, sample->out, required_length, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("convert_buffer failed");
            break;
        }

        uint8_t* in_bytes = NULL;
        status = convert_buffer(&in_bytes, &in_svp, sample->in, required_length, client, caller_uuid);
        if (status != SA_STATUS_OK) {
            ERROR("convert_buffer failed");
            break;
        }

        sa_cipher_algorithm cipher_algorithm = cipher_get_algorithm(cipher);
        const symmetric_context_t* symmetric_context = cipher_get_symmetric_context(cipher);
        if (symmetric_context == NULL) {
            ERROR("cipher_get_symmetric_context failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        uint8_t iv[AES_BLOCK_SIZE];
        memcpy(iv, sample->iv, sample->iv_length);
        if (!symmetric_context_set_iv(symmetric_context, iv, AES_BLOCK_SIZE)) {
            ERROR("symmetric_context_set_iv failed");
            status = SA_STATUS_INTERNAL_ERROR;
            break;
        }

        // Note that the following may not be the most optimal solution to decrypt samples. It is up to the TA vendor
        // to optimize this solution to decrypt samples in the fastest way possible.
        size_t offset = 0;
        size_t enc_byte_count = 0;
        for (size_t i = 0; i < sample->subsample_count; i++) {
            // Copy the bytes of clear data over to the output buffer.
            if (sample->subsample_lengths[i].bytes_of_clear_data > 0) {
                memcpy(out_bytes + offset, in_bytes + offset, sample->subsample_lengths[i].bytes_of_clear_data);
                offset += sample->subsample_lengths[i].bytes_of_clear_data;
            }

            // Decrypt the protected data into the output buffer.
            if (sample->subsample_lengths[i].bytes_of_protected_data > 0) {
                if (sample->crypt_byte_block == 0) {
                    // CENC or CBC1 mode

                    // For CBC, figure out if there is a remainder block because it is in the clear.
                    size_t remainder;
                    size_t block;
                    if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC) {
                        remainder = sample->subsample_lengths[i].bytes_of_protected_data % AES_BLOCK_SIZE;
                        block = sample->subsample_lengths[i].bytes_of_protected_data - remainder;
                    } else {
                        remainder = 0;
                        block = sample->subsample_lengths[i].bytes_of_protected_data;
                    }

                    // Decrypt the protected data into the output buffer.
                    if (!decrypt(out_bytes + offset, in_bytes + offset, block, &enc_byte_count, iv, cipher_algorithm,
                                symmetric_context)) {
                        ERROR("decrypt failed");
                        status = SA_STATUS_INTERNAL_ERROR;
                        break;
                    }

                    // Copy the clear remainder block into the output buffer.
                    offset += block;
                    if (remainder > 0) {
                        memcpy(out_bytes + offset, in_bytes + offset, remainder);
                        offset += remainder;
                    }
                } else {
                    // CENS or CBCS mode

                    // CBCS mode resets IV on each subsample.
                    if (cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC) {
                        memcpy(iv, sample->iv, sample->iv_length);
                        if (!symmetric_context_set_iv(symmetric_context, iv, AES_BLOCK_SIZE)) {
                            ERROR("symmetric_context_set_iv failed");
                            status = SA_STATUS_INTERNAL_ERROR;
                            break;
                        }
                    }

                    size_t bytes_left = sample->subsample_lengths[i].bytes_of_protected_data;
                    while (bytes_left >= AES_BLOCK_SIZE) {
                        // Calculate the number of bytes in the encrypted pattern stripe and decrypt them into the
                        // output buffer. Account for any remainder partial block at the end of the protected data.
                        size_t block = MIN(sample->crypt_byte_block * AES_BLOCK_SIZE,
                                (bytes_left / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
                        if (block > 0) {
                            if (!decrypt(out_bytes + offset, in_bytes + offset, block, &enc_byte_count, iv,
                                        cipher_algorithm, symmetric_context)) {
                                ERROR("decrypt failed");
                                status = SA_STATUS_INTERNAL_ERROR;
                                break;
                            }

                            offset += block;
                            bytes_left -= block;
                        }

                        // Calculate the number of bytes in the skipped pattern stripe and copy them into the output
                        // buffer. Account for any remainder partial block at the end of the protected data.
                        if (sample->skip_byte_block > 0) {
                            block = MIN(sample->skip_byte_block * AES_BLOCK_SIZE,
                                    (bytes_left / AES_BLOCK_SIZE) * AES_BLOCK_SIZE);
                            if (block > 0) {
                                memcpy(out_bytes + offset, in_bytes + offset, block);
                                offset += block;
                                bytes_left -= block;
                            }
                        }
                    }

                    // Copy the clear remainder partial block into the output buffer.
                    if (bytes_left > 0) {
                        memcpy(out_bytes + offset, in_bytes + offset, bytes_left);
                        offset += bytes_left;
                    }
                }
            }
        }

        if (status == SA_STATUS_OK) {
            if (sample->in->buffer_type == SA_BUFFER_TYPE_SVP)
                sample->in->context.svp.offset += offset;
            else
                sample->in->context.clear.offset += offset;

            if (sample->out->buffer_type == SA_BUFFER_TYPE_SVP)
                sample->out->context.svp.offset += offset;
            else
                sample->out->context.clear.offset += offset;
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
