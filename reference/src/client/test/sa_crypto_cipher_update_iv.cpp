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

#include "client_test_helpers.h"
#include "sa.h"
#include "sa_crypto_cipher_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    bool supports_update_iv(sa_cipher_algorithm cipher_algorithm) {
        return cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC ||
               cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
               cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CTR;
    }

    TEST_P(SaCryptoCipherEncryptTest, updateIvNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        parameters.svp_required = false;
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        sa_buffer_type buffer_type = std::get<3>(GetParam());

        if (!supports_update_iv(parameters.cipher_algorithm))
            return;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        parameters.iv = random(AES_BLOCK_SIZE);
        sa_status status = sa_crypto_cipher_update_iv(*cipher, parameters.iv.data(), parameters.iv.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);

        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);

        // get out_length
        size_t bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        size_t required_length = get_required_length(parameters.cipher_algorithm, key_size, clear.size(), true);
        ASSERT_EQ(bytes_to_process, required_length);

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the encryption.
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, false));
    }

    TEST_P(SaCryptoCipherDecryptTest, updateIvNominal) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = std::get<0>(GetParam());
        sa_key_type key_type = std::get<1>(GetParam());
        size_t key_size = std::get<2>(GetParam());
        sa_buffer_type buffer_type = std::get<3>(GetParam());
        parameters.oaep_digest_algorithm = std::get<4>(GetParam());
        parameters.oaep_mgf1_digest_algorithm = std::get<5>(GetParam());
        parameters.oaep_label_length = std::get<6>(GetParam());
        parameters.svp_required = false;

        if (!supports_update_iv(parameters.cipher_algorithm))
            return;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        parameters.iv = random(AES_BLOCK_SIZE);
        sa_status status = sa_crypto_cipher_update_iv(*cipher, parameters.iv.data(), parameters.iv.size());
        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);

        // encrypt using OpenSSL
        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(buffer_type, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        // Exclude the padding block since we are not calling sa_crypto_cipher_process_last.
        bool pkcs7 = parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_CBC_PKCS7 ||
                     parameters.cipher_algorithm == SA_CIPHER_ALGORITHM_AES_ECB_PKCS7;
        size_t checked_length = pkcs7 ? encrypted.size() - AES_BLOCK_SIZE : encrypted.size();
        size_t bytes_to_process = checked_length;
        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        size_t required_length = get_required_length(parameters.cipher_algorithm, key_size, clear.size(), false);
        ASSERT_EQ(bytes_to_process, required_length);

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        bytes_to_process = checked_length;
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, updateIvFailsInvalidContext) {
        auto iv = random(AES_BLOCK_SIZE);
        sa_status status = sa_crypto_cipher_update_iv(INVALID_HANDLE, iv.data(), iv.size());
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_P(SaCryptoCipherWithSvpTest, updateIvFailsInvalidContext) {
        sa_cipher_mode cipher_mode = std::get<1>(GetParam());
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_ECB;
        parameters.svp_required = false;

        auto cipher = initialize_cipher(cipher_mode, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        sa_status status = sa_crypto_cipher_update_iv(*cipher, nullptr, 0);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }
} // namespace
