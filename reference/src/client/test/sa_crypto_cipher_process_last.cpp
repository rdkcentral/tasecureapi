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
    TEST_P(SaCryptoCipherProcessLastTest, processNominalEncrypt) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        sa_buffer_type buffer_type = std::get<3>(GetParam());

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);

        // get out_length
        size_t bytes_to_process = clear.size();
        sa_status status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        size_t required_length = get_required_length(parameters.cipher_algorithm, key_size, clear.size(), true,
                parameters.oaep_digest_algorithm, parameters.oaep_mgf1_digest_algorithm);
        ASSERT_EQ(bytes_to_process, required_length);

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        bool pkcs7 = parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                     parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
        size_t last_block_size = pkcs7 ? AES_BLOCK_SIZE : 0;
        bytes_to_process = 0;
        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                parameters.end_parameters.get());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, last_block_size);

        // Verify the encryption.
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, false));
    }

    TEST_P(SaCryptoCipherProcessLastTest, processNominalDecrypt) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        sa_buffer_type buffer_type = std::get<3>(GetParam());

        auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        auto clear = random(AES_BLOCK_SIZE * 2);

        // encrypt using OpenSSL
        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(buffer_type, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        size_t bytes_to_process = encrypted.size();
        sa_status status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        size_t required_length = get_required_length(parameters.cipher_algorithm, key_size, clear.size(), true,
                parameters.oaep_digest_algorithm, parameters.oaep_mgf1_digest_algorithm);
        ASSERT_EQ(bytes_to_process, required_length);

        // decrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        size_t last_block_size = bytes_to_process - clear.size();
        bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        bytes_to_process = last_block_size;
        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                parameters.end_parameters.get());
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, 0);

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_P(SaCryptoCipherWithSvpTest, processLastFailsBadOutLength) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        sa_cipher_mode cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, cipher_mode, *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = clear.size();
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process - 1);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process, nullptr);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processLastFailsBadContext) {
        auto clear = random(AES_BLOCK_SIZE * 2);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();
        sa_status status = sa_crypto_cipher_process_last(out_buffer.get(), INVALID_HANDLE, in_buffer.get(),
                &bytes_to_process, nullptr);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processLastFailsNullIn) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_ECB, SA_CIPHER_MODE_ENCRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, nullptr, &bytes_to_process, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
