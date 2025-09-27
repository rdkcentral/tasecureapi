/*
 * Copyright 2022-2025 Comcast Cable Communications Management, LLC
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
#include "porting/overflow.h"
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

static sa_status decrypt(
        uint8_t* out_bytes,
        uint8_t* in_bytes,
        size_t bytes_to_process,
        size_t* enc_byte_count,
        uint8_t* iv,
        sa_cipher_algorithm cipher_algorithm,
        symmetric_context_t* symmetric_context) {

    // For AES-CTR mode, IV is an 8 byte nonce followed by an 8 byte counter. Openssl as well as other implementations
    // treat all 16 bytes as a counter. This code accounts for the rollover condition.

    // Determine if the iv will rollover. If not, decrypt the whole block.
    size_t leading_partial_block_size =
            *enc_byte_count % AES_BLOCK_SIZE == 0 ? 0 : AES_BLOCK_SIZE - *enc_byte_count % AES_BLOCK_SIZE;
    size_t number_of_full_blocks = (bytes_to_process - leading_partial_block_size) / AES_BLOCK_SIZE;
    uint64_t* counter_buffer = (uint64_t*) (iv + 8);
    size_t num_blocks_before_rollover = UINT64_MAX - be64toh(*counter_buffer) + 1;
    bool counter_rollover =
            num_blocks_before_rollover <= (number_of_full_blocks + (leading_partial_block_size > 0 ? 1 : 0));

    for (size_t bytes_encrypted = 0; bytes_to_process > bytes_encrypted;) {
        if (counter_rollover && cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR) {
            // This is an AES-CTR cipher and the counter portion of the IV is going to rollover, so encrypt all blocks
            // up to the rollover block and manually increment the IV.
            if (leading_partial_block_size > 0) {
                size_t length = leading_partial_block_size;
                sa_status status = symmetric_context_decrypt(symmetric_context, out_bytes + bytes_encrypted,
                        &length, in_bytes + bytes_encrypted, leading_partial_block_size);
                if (status != SA_STATUS_OK) {
                    ERROR("symmetric_context_decrypt failed");
                    return status;
                }

                // Increment the IV by the number of full blocks just decrypted.
                (*counter_buffer) = htobe64(be64toh(*counter_buffer) + 1);
                status = symmetric_context_set_iv(symmetric_context, iv, AES_BLOCK_SIZE);
                if (status != SA_STATUS_OK) {
                    ERROR("symmetric_context_set_iv failed");
                    return status;
                }

                *enc_byte_count += length;
                bytes_encrypted += length;
                leading_partial_block_size = 0;
            }

            size_t full_blocks_to_encrypt = MIN(num_blocks_before_rollover, number_of_full_blocks);
            if (full_blocks_to_encrypt > 0) {
                size_t length = full_blocks_to_encrypt * AES_BLOCK_SIZE;
                sa_status status = symmetric_context_decrypt(symmetric_context, out_bytes + bytes_encrypted,
                        &length, in_bytes + bytes_encrypted, full_blocks_to_encrypt * AES_BLOCK_SIZE);
                if (status != SA_STATUS_OK) {
                    ERROR("symmetric_context_decrypt failed");
                    return status;
                }

                // Increment the IV by the number of full blocks just decrypted.
                (*counter_buffer) = htobe64(be64toh(*counter_buffer) + full_blocks_to_encrypt);
                status = symmetric_context_set_iv(symmetric_context, iv, AES_BLOCK_SIZE);
                if (status != SA_STATUS_OK) {
                    ERROR("symmetric_context_set_iv failed");
                    return status;
                }

                *enc_byte_count += length;
                bytes_encrypted += length;
                number_of_full_blocks -= full_blocks_to_encrypt;
                num_blocks_before_rollover = 0;
            }

            counter_rollover = false;
        } else {
            // The IV counter is not going to rollover or this is an AES-CBC CIPHER. Openssl and other implementations
            // handle this automatically.
            size_t length = bytes_to_process - bytes_encrypted;
            sa_status status = symmetric_context_decrypt(symmetric_context, out_bytes + bytes_encrypted,
                    &length, in_bytes + bytes_encrypted, bytes_to_process - bytes_encrypted);
            if (status != SA_STATUS_OK) {
                ERROR("symmetric_context_decrypt failed");
                return status;
            }

            uint64_t new_iv = be64toh(*counter_buffer);
            new_iv += number_of_full_blocks + (leading_partial_block_size > 0 ? 1 : 0);
            (*counter_buffer) = htobe64(new_iv);
            *enc_byte_count += length;
            bytes_encrypted = bytes_to_process; // length?
        }
    }

    return SA_STATUS_OK;
}

size_t cenc_get_required_length(
        sa_subsample_length* subsample_lengths,
        size_t subsample_count) {

    size_t required_length = 0;
    for (size_t i = 0; i < subsample_count; i++) {
        size_t subsample_len;
        if (add_overflow(subsample_lengths[i].bytes_of_clear_data, subsample_lengths[i].bytes_of_protected_data,
                    &subsample_len)) {
            return CENC_OVERFLOW;
        }

        size_t new_required_length;
        if (add_overflow(required_length, subsample_len, &new_required_length)) {
            return CENC_OVERFLOW;
        }

        required_length = new_required_length;
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
        if (required_length == CENC_OVERFLOW) {
            ERROR("cenc_get_required_length integer overflow");
            status = SA_STATUS_INVALID_PARAMETER;
            break;
        }

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
        symmetric_context_t* symmetric_context = cipher_get_symmetric_context(cipher);
        if (symmetric_context == NULL) {
            ERROR("cipher_get_symmetric_context failed");
            status = SA_STATUS_NULL_PARAMETER;
            break;
        }

        uint8_t iv[AES_BLOCK_SIZE];
        memcpy(iv, sample->iv, sample->iv_length);
        status = symmetric_context_set_iv(symmetric_context, iv, AES_BLOCK_SIZE);
        if (status != SA_STATUS_OK) {
            ERROR("symmetric_context_set_iv failed");
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
                    status = decrypt(out_bytes + offset, in_bytes + offset, block, &enc_byte_count, iv,
                            cipher_algorithm, symmetric_context);
                    if (status != SA_STATUS_OK) {
                        ERROR("decrypt failed");
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
                        status = symmetric_context_set_iv(symmetric_context, iv, AES_BLOCK_SIZE);
                        if (status != SA_STATUS_OK) {
                            ERROR("symmetric_context_set_iv failed");
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
                            status = decrypt(out_bytes + offset, in_bytes + offset, block, &enc_byte_count, iv,
                                    cipher_algorithm, symmetric_context);
                            if (status != SA_STATUS_OK) {
                                ERROR("decrypt failed");
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
            if (sample->in->buffer_type == SA_BUFFER_TYPE_CLEAR) {
		sample->in->context.clear.offset += offset;
	    } 
#ifndef DISABLE_SVP
	    else if( sample->in->buffer_type == SA_BUFFER_TYPE_SVP) {
		sample->in->context.svp.offset += offset;
	    }
#endif // DISABLE_SVP

            if (sample->out->buffer_type == SA_BUFFER_TYPE_CLEAR) {
                sample->out->context.clear.offset += offset;
	    }
#ifndef DISABLE_SVP
	    else if (sample->out->buffer_type == SA_BUFFER_TYPE_SVP) {
                sample->out->context.svp.offset += offset;
	    }
#endif // DISABLE_SVP
        }
    } while (false);
#ifndef DISABLE_SVP
    if (in_svp != NULL)
        svp_store_release_exclusive(client_get_svp_store(client), sample->in->context.svp.buffer, in_svp, caller_uuid);

    if (out_svp != NULL)
        svp_store_release_exclusive(client_get_svp_store(client), sample->out->context.svp.buffer, out_svp,
                caller_uuid);
#endif // DISABLE_SVP
    if (cipher != NULL)
        cipher_store_release_exclusive(cipher_store, sample->context, cipher, caller_uuid);

    return status;
}
