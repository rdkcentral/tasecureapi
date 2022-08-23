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

#ifndef SA_PROCESS_COMMON_ENCRYPTION_COMMON_H
#define SA_PROCESS_COMMON_ENCRYPTION_COMMON_H

#include "sa.h"
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"
#include <memory>
#include <vector>

typedef struct {
    std::vector<uint8_t> clear;
    std::shared_ptr<sa_buffer> in;
    std::shared_ptr<sa_buffer> out;
    std::vector<sa_subsample_length> subsample_lengths;
} sample_data;

class SaProcessCommonEncryptionBase : public SaCipherCryptoBase {
protected:
    static bool build_samples(
            size_t sample_size,
            size_t crypt_byte_block,
            size_t skip_byte_block,
            size_t subsample_count,
            size_t bytes_of_clear_data,
            cipher_parameters& parameters,
            sa_buffer_type out_buffer_type,
            sa_buffer_type in_buffer_type,
            const std::shared_ptr<sa_crypto_cipher_context>& cipher,
            sample_data& sample_data,
            std::vector<sa_sample>& samples);

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

// clang-format off
using SaProcessCommonEncryptionType = std::tuple<std::tuple<size_t, size_t>, size_t, size_t, size_t,
        sa_cipher_algorithm, std::tuple<sa_buffer_type, sa_buffer_type>>;
// clang-format on

class SaProcessCommonEncryptionTest : public ::testing::TestWithParam<SaProcessCommonEncryptionType>,
                                      public SaProcessCommonEncryptionBase {
protected:
    void SetUp() override;
};

class SaProcessCommonEncryptionNegativeTest : public ::testing::Test, public SaProcessCommonEncryptionBase {};

class SaProcessCommonEncryptionAlternativeTest : public ::testing::Test, public SaProcessCommonEncryptionBase {};

#endif // SA_PROCESS_COMMON_ENCRYPTION_COMMON_H
