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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaCryptoCipherEncryptTest, processNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        parameters.svp_required = false;
        sa_key_type const key_type = std::get<1>(GetParam());
        size_t const key_size = std::get<2>(GetParam());
        sa_buffer_type const buffer_type = std::get<3>(GetParam());

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);

        // get out_length
        size_t bytes_to_process = clear.size();
        sa_status status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        size_t const required_length = get_required_length(parameters.cipher_algorithm, key_size, clear.size(), true);
        ASSERT_EQ(bytes_to_process, required_length);

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);

        bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // For GCM/ChaCha20-Poly1305, call process_last to generate the authentication tag
        if (parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM ||
                parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_CHACHA20_POLY1305) {
            size_t bytes_to_process_last = 0;
            if (parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_GCM) {
                sa_cipher_end_parameters_aes_gcm end_parameters = {parameters.tag.data(), parameters.tag.size()};
                status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(),
                        &bytes_to_process_last, &end_parameters);
            } else {
                sa_cipher_end_parameters_chacha20_poly1305 end_parameters = {parameters.tag.data(),
                        parameters.tag.size()};
                status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(),
                        &bytes_to_process_last, &end_parameters);
            }
            ASSERT_EQ(status, SA_STATUS_OK);
        }

        // Verify the encryption.
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, false));
    }

    TEST_P(SaCryptoCipherDecryptTest, processNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        sa_key_type const key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        sa_buffer_type const buffer_type = std::get<3>(GetParam());
        parameters.oaep_digest_algorithm = std::get<4>(GetParam());
        parameters.oaep_mgf1_digest_algorithm = std::get<5>(GetParam());
        parameters.oaep_label_length = std::get<6>(GetParam());
        parameters.svp_required = false;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        std::vector<uint8_t> clear;
        if (key_type == SA_KEY_TYPE_EC) {
            key_size = ec_get_key_size(parameters.curve);
            clear = random(key_size);
            if (parameters.curve == SA_ELLIPTIC_CURVE_NIST_P521)
                clear[0] &= 0x1;
        } else {
            clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        }

        // encrypt using OpenSSL
        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(buffer_type, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        // Exclude the padding block since we are not calling sa_crypto_cipher_process_last.
        bool const pkcs7 = parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                           parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
        size_t const checked_length = pkcs7 ? encrypted.size() - AES_BLOCK_SIZE : encrypted.size();
        size_t bytes_to_process = checked_length;
        sa_status status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        size_t const required_length = get_required_length(parameters.cipher_algorithm, key_size, clear.size(), false);
        ASSERT_EQ(bytes_to_process, required_length);

        // decrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);

        bytes_to_process = checked_length;
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        if (pkcs7) {
            ASSERT_EQ(bytes_to_process + AES_BLOCK_SIZE, clear.size());
            clear.resize(bytes_to_process);
        } else {
            ASSERT_EQ(bytes_to_process, clear.size());
        }

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_P(SaCryptoCipherWithSvpTest, processFailsInvalidOutLength) {
        sa_buffer_type const buffer_type = std::get<0>(GetParam());
        sa_cipher_mode const cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, cipher_mode, *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);

        size_t bytes_to_process = clear.size();
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process - 1);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithSvpTest, processFailsOutOffsetOverflow) {
        sa_buffer_type const buffer_type = std::get<0>(GetParam());
        sa_cipher_mode const cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, cipher_mode, *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);

        size_t bytes_to_process = clear.size();
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        if (buffer_type == SA_BUFFER_TYPE_CLEAR)
            out_buffer->context.clear.offset = SIZE_MAX - 4;

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithSvpTest, processFailsInOffsetOverflow) {
        sa_buffer_type const buffer_type = std::get<0>(GetParam());
        sa_cipher_mode const cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, cipher_mode, *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);

        size_t bytes_to_process = clear.size();
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        if (buffer_type == SA_BUFFER_TYPE_CLEAR)
            in_buffer->context.clear.offset = SIZE_MAX - 4;

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processFailsInvalidContext) {
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();
        sa_status const status = sa_crypto_cipher_process(out_buffer.get(), INVALID_HANDLE, in_buffer.get(),
                &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processFailsNullIn) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, nullptr, &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
