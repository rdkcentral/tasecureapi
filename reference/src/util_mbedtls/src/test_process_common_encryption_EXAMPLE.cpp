/*
 * Copyright 2020-2025 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_process_common_encryption.h"
#include "common.h"
#include "log.h"
#include "sa.h"
#include "sa_cenc.h"
#include <arpa/inet.h>
#include <memory.h>

#ifdef __APPLE__
#define htobe64(x) htonll(x)
#define be64toh(x) ntohll(x)
#elif defined(__linux__)
#include <endian.h>
#ifndef htobe64
#define htobe64(x) htobe64(x)
#endif
#ifndef be64toh
#define be64toh(x) be64toh(x)
#endif
#endif

#define MIN(A, B) ((A) <= (B) ? (A) : (B))

// Create and initialize a fresh mbedTLS cipher context
mbedtls_cipher_context_t* ProcessCommonEncryptionBase::mbedtls_init(
        const void* iv,
        const uint8_t* key,
        sa_cipher_algorithm cipher_algorithm) {

    if (cipher_algorithm != SA_CIPHER_ALGORITHM_AES_CTR) {
        ERROR("Only AES-CTR supported in this example");
        return nullptr;
    }

    // Allocate new context
    auto* context = new mbedtls_cipher_context_t;
    mbedtls_cipher_init(context);

    // Select cipher type based on key size (assumed 128-bit for this example)
    const mbedtls_cipher_info_t* cipher_info = 
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
    
    if (cipher_info == nullptr) {
        ERROR("mbedtls_cipher_info_from_type failed");
        delete context;
        return nullptr;
    }

    // Setup cipher
    if (mbedtls_cipher_setup(context, cipher_info) != 0) {
        ERROR("mbedtls_cipher_setup failed");
        mbedtls_cipher_free(context);
        delete context;
        return nullptr;
    }

    // Set key (ENCRYPT mode for encryption)
    if (mbedtls_cipher_setkey(context, key, 128, MBEDTLS_ENCRYPT) != 0) {
        ERROR("mbedtls_cipher_setkey failed");
        mbedtls_cipher_free(context);
        delete context;
        return nullptr;
    }

    // Set IV
    if (mbedtls_cipher_set_iv(context, static_cast<const uint8_t*>(iv), AES_BLOCK_SIZE) != 0) {
        ERROR("mbedtls_cipher_set_iv failed");
        mbedtls_cipher_free(context);
        delete context;
        return nullptr;
    }

    return context;
}

// Encrypt with CTR rollover handling (similar to cenc.c decrypt logic)
bool ProcessCommonEncryptionBase::encrypt(
        uint8_t* out_bytes,
        uint8_t* in_bytes,
        size_t bytes_to_process,
        size_t* enc_byte_count,
        uint8_t* iv,
        mbedtls_cipher_context_t* context) {

    // Counter rollover logic for AES-CTR
    size_t leading_partial_block_size =
            *enc_byte_count % AES_BLOCK_SIZE == 0 ? 0 : AES_BLOCK_SIZE - *enc_byte_count % AES_BLOCK_SIZE;
    size_t number_of_full_blocks = (bytes_to_process - leading_partial_block_size) / AES_BLOCK_SIZE;
    uint64_t* counter_buffer = (uint64_t*) (iv + 8);
    size_t num_blocks_before_rollover = UINT64_MAX - be64toh(*counter_buffer) + 1;
    bool counter_rollover =
            num_blocks_before_rollover <= (number_of_full_blocks + (leading_partial_block_size > 0 ? 1 : 0));

    for (size_t bytes_encrypted = 0; bytes_to_process > bytes_encrypted;) {
        if (counter_rollover) {
            // Handle rollover case
            if (leading_partial_block_size > 0) {
                size_t length = leading_partial_block_size;
                if (mbedtls_cipher_update(context, in_bytes + bytes_encrypted, leading_partial_block_size,
                        out_bytes + bytes_encrypted, &length) != 0) {
                    ERROR("mbedtls_cipher_update failed");
                    return false;
                }
                (*counter_buffer) = htobe64(be64toh(*counter_buffer) + 1);
                if (mbedtls_cipher_set_iv(context, iv, AES_BLOCK_SIZE) != 0) {
                    ERROR("mbedtls_cipher_set_iv failed");
                    return false;
                }
                *enc_byte_count += length;
                bytes_encrypted += length;
                leading_partial_block_size = 0;
            }

            size_t full_blocks_to_encrypt = MIN(num_blocks_before_rollover, number_of_full_blocks);
            if (full_blocks_to_encrypt > 0) {
                size_t length = full_blocks_to_encrypt * AES_BLOCK_SIZE;
                if (mbedtls_cipher_update(context, in_bytes + bytes_encrypted, 
                        full_blocks_to_encrypt * AES_BLOCK_SIZE,
                        out_bytes + bytes_encrypted, &length) != 0) {
                    ERROR("mbedtls_cipher_update failed");
                    return false;
                }
                (*counter_buffer) = htobe64(be64toh(*counter_buffer) + full_blocks_to_encrypt);
                if (mbedtls_cipher_set_iv(context, iv, AES_BLOCK_SIZE) != 0) {
                    ERROR("mbedtls_cipher_set_iv failed");
                    return false;
                }
                *enc_byte_count += length;
                bytes_encrypted += length;
                number_of_full_blocks -= full_blocks_to_encrypt;
                num_blocks_before_rollover = UINT64_MAX;
            }
            counter_rollover = false;
        } else {
            // No rollover - encrypt normally
            size_t length = bytes_to_process - bytes_encrypted;
            if (mbedtls_cipher_update(context, in_bytes + bytes_encrypted, 
                    bytes_to_process - bytes_encrypted,
                    out_bytes + bytes_encrypted, &length) != 0) {
                ERROR("mbedtls_cipher_update failed");
                return false;
            }
            *enc_byte_count += length;
            bytes_encrypted += length;
        }
    }

    return true;
}

// Main function: Process samples with FRESH CONTEXT PER SAMPLE
bool ProcessCommonEncryptionBase::encrypt_samples(
        uint8_t* in_bytes,
        std::vector<sa_sample>& samples,
        std::vector<uint8_t>& clear_key,
        sa_cipher_algorithm cipher_algorithm) {

    size_t offset = 0;
    
    // KEY DIFFERENCE: Loop creates FRESH context for EACH sample
    for (const sa_sample& sample : samples) {
        uint8_t iv[AES_BLOCK_SIZE];
        memcpy(iv, sample.iv, sample.iv_length);

        // ✨ CREATE FRESH CONTEXT FOR THIS SAMPLE ✨
        mbedtls_cipher_context_t* context = mbedtls_init(
            static_cast<const uint8_t*>(sample.iv), 
            clear_key.data(),
            cipher_algorithm);
            
        if (context == nullptr) {
            ERROR("mbedtls_init failed");
            return false;
        }

        // Process all subsamples for THIS sample using THIS context
        size_t enc_byte_count = 0;
        for (size_t i = 0; i < sample.subsample_count; i++) {
            // Skip clear data
            offset += sample.subsample_lengths[i].bytes_of_clear_data;

            // Encrypt protected data
            if (sample.subsample_lengths[i].bytes_of_protected_data > 0) {
                std::vector<uint8_t> out_bytes(sample.subsample_lengths[i].bytes_of_protected_data);
                
                if (!encrypt(out_bytes.data(), in_bytes + offset, 
                        sample.subsample_lengths[i].bytes_of_protected_data, 
                        &enc_byte_count, iv, context)) {
                    ERROR("encrypt failed");
                    mbedtls_cipher_free(context);
                    delete context;
                    return false;
                }

                memcpy(in_bytes + offset, out_bytes.data(), 
                       sample.subsample_lengths[i].bytes_of_protected_data);
                offset += sample.subsample_lengths[i].bytes_of_protected_data;
            }
        }

        // ✨ FREE THIS SAMPLE'S CONTEXT ✨
        mbedtls_cipher_free(context);
        delete context;
    }

    return true;
}

bool ProcessCommonEncryptionBase::build_samples(
        size_t sample_size,
        size_t crypt_byte_block,
        size_t skip_byte_block,
        size_t subsample_count,
        size_t bytes_of_clear_data,
        std::vector<uint8_t>& iv,
        sa_cipher_algorithm cipher_algorithm,
        std::vector<uint8_t>& clear_key,
        const std::shared_ptr<sa_crypto_cipher_context>& cipher,
        sample_data& sample_data,
        std::vector<sa_sample>& samples) {

    // Build sample structure (same as OpenSSL version)
    size_t const sample_count = samples.size();
    size_t const subsample_size = sample_size / subsample_count;
    sample_data.clear = random(subsample_size * subsample_count * sample_count);
    sample_data.subsample_lengths.resize(subsample_count * sample_count);

    for (size_t i = 0; i < sample_count; i++) {
        auto* sample = &samples[i];
        sample->iv = iv.data();
        sample->iv_length = iv.size();
        sample->crypt_byte_block = crypt_byte_block;
        sample->skip_byte_block = skip_byte_block;
        sample->subsample_count = subsample_count;

        sample->subsample_lengths = &sample_data.subsample_lengths[i * subsample_count];
        for (size_t j = 0; j < subsample_count; j++) {
            sample->subsample_lengths[j].bytes_of_clear_data =
                    bytes_of_clear_data == UINT32_MAX ? subsample_size : bytes_of_clear_data;
            sample->subsample_lengths[j].bytes_of_protected_data =
                    subsample_size - sample->subsample_lengths[j].bytes_of_clear_data;
        }

        sample->context = *cipher;
        sample->out = sample_data.out.get();
    }

    // Encrypt the data using mbedTLS with FRESH CONTEXTS
    return encrypt_samples(const_cast<uint8_t*>(sample_data.clear.data()), samples, clear_key, cipher_algorithm);
}
