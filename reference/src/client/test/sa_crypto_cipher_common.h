/**
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

#ifndef SA_CRYPTO_CIPHER_COMMON_H
#define SA_CRYPTO_CIPHER_COMMON_H

#include "sa_types.h"
#include "gtest/gtest.h"
#include <memory>
#include <openssl/ec.h>
#include <vector>

typedef struct { // NOLINT
    sa_cipher_algorithm cipher_algorithm;
    std::shared_ptr<sa_key> key;
    std::vector<uint8_t> clear_key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> aad;
    std::vector<uint8_t> tag;
    std::shared_ptr<void> parameters;
    std::shared_ptr<void> end_parameters;
    sa_elliptic_curve curve;
    sa_digest_algorithm oaep_digest_algorithm;
    sa_digest_algorithm oaep_mgf1_digest_algorithm;
    size_t oaep_label_length;
    bool svp_required;
} cipher_parameters;

class SaCipherCryptoBase {
protected:
    static bool import_key(
            cipher_parameters& parameters,
            sa_key_type key_type,
            size_t key_size);

    static void get_cipher_parameters(cipher_parameters& parameters);

    static std::shared_ptr<sa_crypto_cipher_context> initialize_cipher(
            sa_cipher_mode cipher_mode,
            sa_key_type key_type,
            size_t key_size,
            cipher_parameters& parameters);

    static bool verify_encrypt(
            sa_buffer* encrypted,
            std::vector<uint8_t>& clear,
            cipher_parameters& parameters,
            bool padded);

    static bool verify_decrypt(
            sa_buffer* decrypted,
            std::vector<uint8_t>& clear);

    static std::vector<uint8_t> encrypt_openssl(
            std::vector<uint8_t>& clear,
            cipher_parameters& parameters);

    static std::vector<uint8_t> decrypt_openssl(
            std::vector<uint8_t>& encrypted_data,
            cipher_parameters& parameters);

    static size_t get_required_length(
            sa_cipher_algorithm cipher_algorithm,
            size_t key_length,
            size_t bytes_to_process,
            bool apply_pad);

    static bool ec_is_valid_x_coordinate(
            std::shared_ptr<EC_GROUP>& ec_group,
            const std::vector<uint8_t>& coordinate);
};

// clang-format off
using SaCryptoCipherDecryptTestType = std::tuple<sa_cipher_algorithm, sa_key_type, size_t, sa_buffer_type,
    sa_digest_algorithm, sa_digest_algorithm, size_t>;

class SaCryptoCipherDecryptTest : public ::testing::TestWithParam<SaCryptoCipherDecryptTestType>,
                                  public SaCipherCryptoBase {
protected:
    void SetUp() override;
};

using SaCryptoCipherTestType = std::tuple<sa_cipher_algorithm, sa_key_type, size_t, sa_buffer_type>;

class SaCryptoCipherEncryptTest : public ::testing::TestWithParam<SaCryptoCipherTestType>, public SaCipherCryptoBase {
protected:
    void SetUp() override;
};

class SaCryptoCipherProcessLastTest : public ::testing::TestWithParam<SaCryptoCipherTestType>,
                                      public SaCipherCryptoBase {
protected:
    void SetUp() override;
};

using SaCryptoCipherWithSvpTestType = std::tuple<sa_buffer_type, sa_cipher_mode>;

class SaCryptoCipherWithSvpTest : public ::testing::TestWithParam<SaCryptoCipherWithSvpTestType>,
                                  public SaCipherCryptoBase {
protected:
    void SetUp() override;
};

using SaCryptoCipherWithoutSvpTestType = std::tuple<sa_cipher_mode>;

class SaCryptoCipherWithoutSvpTest : public ::testing::TestWithParam<SaCryptoCipherWithoutSvpTestType>,
                                     public SaCipherCryptoBase {};

class SaCryptoCipherSvpOnlyTest : public ::testing::Test, public SaCipherCryptoBase {
protected:
    void SetUp() override;
};

using SaCryptoCipherElGamalTestType = std::tuple<sa_elliptic_curve>;

class SaCryptoCipherElGamalTest : public ::testing::TestWithParam<SaCryptoCipherElGamalTestType>,
                                  public SaCipherCryptoBase {};

class SaCryptoCipherElGamalFailTest : public ::testing::TestWithParam<SaCryptoCipherElGamalTestType>,
                                      public SaCipherCryptoBase {};

class SaCryptoCipherMultipleThread : public ::testing::Test, public SaCipherCryptoBase {
public:
    static sa_status process_multiple_threads(size_t id);
};

// clang-format on
#endif // SA_CRYPTO_CIPHER_COMMON_H
