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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_F(SaCryptoCipherWithoutSvpTest, failLastChacha20Poly1305EncryptShortTag) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        parameters.iv = random(CHACHA20_NONCE_LENGTH);
        parameters.aad = random(36);
        parameters.clear_key = random(SYM_256_KEY_SIZE);
        parameters.tag = std::vector<uint8_t>(CHACHA20_TAG_LENGTH - 1);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        parameters.key = create_sa_key_symmetric(&rights, parameters.clear_key);
        ASSERT_NE(parameters.key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_cipher_parameters_chacha20_poly1305 chacha20_poly1305_parameters = {parameters.iv.data(),
                parameters.iv.size(), parameters.aad.data(), parameters.aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_ENCRYPT,
                *parameters.key, &chacha20_poly1305_parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(8);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        // get out_length
        status = sa_crypto_cipher_process_last(nullptr, *cipher, in_buffer.get(), &bytes_to_process, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);

        sa_cipher_end_parameters_chacha20_poly1305 end_parameters = {parameters.tag.data(), parameters.tag.size()};
        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processLastChacha20Poly1305DecryptShortTag) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        parameters.iv = random(CHACHA20_NONCE_LENGTH);
        parameters.aad = random(36);
        parameters.tag = std::vector<uint8_t>(CHACHA20_TAG_LENGTH - 1);
        parameters.clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        parameters.key = create_sa_key_symmetric(&rights, parameters.clear_key);
        ASSERT_NE(parameters.key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_cipher_parameters_chacha20_poly1305 chacha20_poly1305_parameters = {parameters.iv.data(),
                parameters.iv.size(), parameters.aad.data(), parameters.aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
                *parameters.key, &chacha20_poly1305_parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(8);

        // encrypt using OpenSSL
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_chacha20_poly1305_openssl(encrypted, clear, parameters.iv, parameters.aad, parameters.tag,
                parameters.clear_key));
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        // get out_length
        size_t bytes_to_process = encrypted.size();
        status = sa_crypto_cipher_process_last(nullptr, *cipher, in_buffer.get(), &bytes_to_process, nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        // decrypt using SecApi
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        bytes_to_process = encrypted.size();
        sa_cipher_end_parameters_chacha20_poly1305 end_parameters = {parameters.tag.data(), parameters.tag.size()};
        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastChacha20Poly1305FailsInvalidOutLength) {
        sa_cipher_mode cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto nonce = random(CHACHA20_NONCE_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_chacha20_poly1305 parameters = {nonce.data(), nonce.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> tag(CHACHA20_TAG_LENGTH);
        sa_cipher_end_parameters_chacha20_poly1305 end_parameters = {tag.data(), tag.size()};

        auto clear = random(AES_BLOCK_SIZE);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size() - 1);
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastChacha20Poly1305FailsInvalidInLength) {
        sa_cipher_mode cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto nonce = random(CHACHA20_NONCE_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_chacha20_poly1305 parameters = {nonce.data(), nonce.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> tag(CHACHA20_TAG_LENGTH);
        sa_cipher_end_parameters_chacha20_poly1305 end_parameters = {tag.data(), tag.size()};

        auto clear = random(AES_BLOCK_SIZE);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = 2 * clear.size();

        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastChacha20Poly1305FailsNullParameters) {
        sa_cipher_mode cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto nonce = random(CHACHA20_NONCE_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_chacha20_poly1305 parameters = {nonce.data(), nonce.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastChacha20Poly1305FailsNullTag) {
        sa_cipher_mode cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto nonce = random(CHACHA20_NONCE_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_chacha20_poly1305 parameters = {nonce.data(), nonce.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_cipher_end_parameters_chacha20_poly1305 end_parameters = {nullptr, 0};

        auto clear = random(AES_BLOCK_SIZE);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastChacha20Poly1305FailsInvalidTagLength) {
        sa_cipher_mode cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto nonce = random(CHACHA20_NONCE_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_chacha20_poly1305 parameters = {nonce.data(), nonce.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20_POLY1305, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> tag(CHACHA20_TAG_LENGTH + 1);
        sa_cipher_end_parameters_chacha20_poly1305 end_parameters = {tag.data(), tag.size()};

        auto clear = random(AES_BLOCK_SIZE);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
