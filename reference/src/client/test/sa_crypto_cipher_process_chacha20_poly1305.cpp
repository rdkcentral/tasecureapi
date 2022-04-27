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
    TEST_P(SaCryptoCipherWithSvpTest, processChacha20Poly1305NominalEncryptAes256NullAadZeroLength) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;

        ASSERT_TRUE(import_key(parameters, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE));

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        parameters.iv = random(CHACHA20_NONCE_LENGTH);
        parameters.aad = {};
        parameters.tag = std::vector<uint8_t>(AES_BLOCK_SIZE);
        auto* cipher_parameters_chacha20_poly1305 = new sa_cipher_parameters_chacha20_poly1305;
        cipher_parameters_chacha20_poly1305->nonce = parameters.iv.data();
        cipher_parameters_chacha20_poly1305->nonce_length = parameters.iv.size();
        cipher_parameters_chacha20_poly1305->aad = nullptr;
        cipher_parameters_chacha20_poly1305->aad_length = 0;
        parameters.parameters =
                std::shared_ptr<sa_cipher_parameters_chacha20_poly1305>(cipher_parameters_chacha20_poly1305);

        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_ENCRYPT,
                *parameters.key, parameters.parameters.get());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(AES_BLOCK_SIZE * 2);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the encryption.
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, false));
    }

    TEST_P(SaCryptoCipherWithSvpTest, processChacha20Poly1305NominalDecryptAes256NullAadZeroLength) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;

        ASSERT_TRUE(import_key(parameters, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE));

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        parameters.iv = random(CHACHA20_NONCE_LENGTH);
        parameters.aad = {};
        parameters.tag = std::vector<uint8_t>(AES_BLOCK_SIZE);
        auto* cipher_parameters_chacha20_poly1305 = new sa_cipher_parameters_chacha20_poly1305;
        cipher_parameters_chacha20_poly1305->nonce = parameters.iv.data();
        cipher_parameters_chacha20_poly1305->nonce_length = parameters.iv.size();
        cipher_parameters_chacha20_poly1305->aad = nullptr;
        cipher_parameters_chacha20_poly1305->aad_length = 0;
        parameters.parameters =
                std::shared_ptr<sa_cipher_parameters_chacha20_poly1305>(cipher_parameters_chacha20_poly1305);

        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
                *parameters.key, parameters.parameters.get());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        // encrypt using OpenSSL
        auto clear = random(AES_BLOCK_SIZE * 2);
        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(buffer_type, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        // get out_length
        size_t bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, encrypted.size());

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(buffer_type, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_P(SaCryptoCipherWithSvpTest, processChacha20Poly1305EncryptResumePartialBlock) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        sa_key_type key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t key_size = SYM_256_KEY_SIZE;

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
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, false));
    }

    TEST_P(SaCryptoCipherWithSvpTest, processChacha20Poly1305DecryptResumePartialBlock) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_CHACHA20_POLY1305;
        sa_key_type key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t key_size = SYM_256_KEY_SIZE;

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

    TEST_P(SaCryptoCipherWithSvpTest, processChacha20Poly1305FailsBadOutLength) {
        sa_buffer_type buffer_type = std::get<0>(GetParam());
        sa_cipher_mode cipher_mode = std::get<1>(GetParam());
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);

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

        auto clear = random(33);
        auto in_buffer = buffer_alloc(buffer_type, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(buffer_type, clear.size() - 1);
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaCryptoCipherSvpOnlyTest, initChacha20Poly1305FailsDecryptBadRightsSvpOptionalNotSet) {
        auto clear_key = random(SYM_256_KEY_SIZE);

        sa_rights rights;
        rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto nonce = random(CHACHA20_NONCE_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_chacha20_poly1305 parameters = {nonce.data(), nonce.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_CHACHA20_POLY1305,
                SA_CIPHER_MODE_DECRYPT, *key, &parameters);
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
