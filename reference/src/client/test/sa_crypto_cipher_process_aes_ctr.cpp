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
    TEST_P(SaCryptoCipherWithSvpTest, processAesCtrEncryptResumePartialBlock) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
        sa_key_type key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t key_size = SYM_128_KEY_SIZE;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        auto clear = random(34);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size() / 2;
        sa_status status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size() / 2);

        bytes_to_process = clear.size() / 2;
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size() / 2);

        // Verify the encryption.
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, true));
    }

    TEST_P(SaCryptoCipherWithSvpTest, processAesCtrDecryptResumePartialBlock) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_CTR;
        sa_key_type key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t key_size = SYM_128_KEY_SIZE;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        // encrypt using OpenSSL

        auto clear = random(34);

        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(buffer_type, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        auto out_buffer = buffer_alloc(buffer_type, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size() / 2;
        sa_status status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size() / 2);

        bytes_to_process = clear.size() / 2;
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size() / 2);

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_P(SaCryptoCipherWithSvpTest, processAesCtrFailsBadOutLength) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        sa_cipher_mode cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(AES_BLOCK_SIZE);
        sa_cipher_parameters_aes_ctr parameters = {iv.data(), iv.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_CTR, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size() - 1);
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaCryptoCipherSvpOnlyTest, initAesCtrFailsDecryptBadRightsSvpOptionalNotSet) {
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(AES_BLOCK_SIZE);
        sa_cipher_parameters_aes_ctr parameters = {iv.data(), iv.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_CTR, SA_CIPHER_MODE_DECRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size() - 1);
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
} // namespace
