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

#ifndef TEST_PROCESS_COMMON_ENCRYPTION_H
#define TEST_PROCESS_COMMON_ENCRYPTION_H

#include "sa_cenc.h"
#include <memory>
#include <openssl/evp.h>
#include <string>
#include <vector>

typedef struct {
    std::vector<uint8_t> clear;
    std::shared_ptr<sa_buffer> in;
    std::shared_ptr<sa_buffer> out;
    std::vector<sa_subsample_length> subsample_lengths;
} sample_data;

class ProcessCommonEncryptionBase {
protected:
    bool build_samples(
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
            std::vector<sa_sample>& samples);

#ifdef ENABLE_SVP
    virtual sa_status svp_buffer_write(
            sa_svp_buffer out,
            const void* in,
            size_t in_length) = 0;

#endif
    ~ProcessCommonEncryptionBase() = default;

private:
    static EVP_CIPHER_CTX* openssl_init(
            const void* iv,
            const uint8_t* key,
            sa_cipher_algorithm cipher_algorithm);

    static bool encrypt(
            uint8_t* out_bytes,
            uint8_t* in_bytes,
            size_t bytes_to_process,
            size_t* enc_byte_count,
            uint8_t* iv,
            EVP_CIPHER_CTX* context);

    static bool encrypt_samples(
            uint8_t* in_bytes,
            std::vector<sa_sample>& samples,
            std::vector<uint8_t>& clear_key,
            sa_cipher_algorithm cipher_algorithm);
};

// Shared data for the AES-CTR tests
namespace ctr_partial_block_test {
    constexpr size_t GUARD_SIZE = 64;
    constexpr uint8_t GUARD_VALUE = 0xa5;

    struct sample_case {
        std::vector<sa_subsample_length> subsample_lengths;
        std::vector<uint8_t> clear;     // Expected decrypted sample.
        std::vector<uint8_t> in_bytes;  // Encrypted sample followed by guard bytes.
        std::vector<uint8_t> out_bytes; // Guard bytes only. Same size as in_bytes.
        size_t total_length = 0;
    };

    const std::vector<std::vector<sa_subsample_length>>& subsample_cases();

    const std::vector<uint64_t>& counters();

    /**
     * Sets the counter (last 8 bytes) of a 16 byte AES-CTR IV.
     */
    void set_counter(
            std::vector<uint8_t>& iv,
            uint64_t counter);

    /**
     * Builds a random sample, encrypts its protected bytes with AES-CTR using the key and IV, and fills the input and
     * output vectors with guard bytes after the sample.
     */
    bool build_sample(
            sample_case& sample_case,
            const std::vector<sa_subsample_length>& subsample_lengths,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& iv);

    /**
     * Checks the decrypted data and that the guard bytes after the sample are unchanged.
     *
     * @param[in] result the output buffer, which is at least sample_case.out_bytes.size() bytes.
     * @param[out] error a description of the first failure.
     * @return true if the output is correct.
     */
    bool verify_output(
            const sample_case& sample_case,
            const uint8_t* result,
            std::string& error);
} // namespace ctr_partial_block_test

#endif // TEST_PROCESS_COMMON_ENCRYPTION_H
