/*
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
    TEST_F(SaCryptoCipherWithoutSvpTest, processLastAesGcmEncryptShortTag) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        parameters.iv = random(GCM_IV_LENGTH);
        parameters.aad = random(36);
        parameters.clear_key = random(SYM_128_KEY_SIZE);
        parameters.tag = std::vector<uint8_t>(MAX_GCM_TAG_LENGTH - 4);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        parameters.key = create_sa_key_symmetric(&rights, parameters.clear_key);
        ASSERT_NE(parameters.key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_cipher_parameters_aes_gcm gcm_parameters = {parameters.iv.data(), parameters.iv.size(),
                parameters.aad.data(), parameters.aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_ENCRYPT,
                *parameters.key, &gcm_parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(8);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);

        // encrypt using SecApi - process the data first
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Finalize GCM encryption to generate authentication tag (no more data to process)
        size_t bytes_to_process_last = 0;
        sa_cipher_end_parameters_aes_gcm end_parameters = {parameters.tag.data(), parameters.tag.size()};
        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process_last,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Extract encrypted data for verification
        std::vector<uint8_t> encrypted_data = {static_cast<uint8_t*>(out_buffer->context.clear.buffer),
                static_cast<uint8_t*>(out_buffer->context.clear.buffer) + clear.size()};

        // Verify by decrypting with SecAPI (same library ensures consistency)
        auto decrypt_cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(decrypt_cipher, nullptr);

        sa_cipher_parameters_aes_gcm decrypt_gcm_parameters = {parameters.iv.data(), parameters.iv.size(),
                parameters.aad.data(), parameters.aad.size()};
        status = sa_crypto_cipher_init(decrypt_cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
                *parameters.key, &decrypt_gcm_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto encrypted_in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted_data);
        ASSERT_NE(encrypted_in_buffer, nullptr);

        auto decrypted_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted_data.size());
        ASSERT_NE(decrypted_buffer, nullptr);

        // Decrypt the data first
        size_t decrypt_bytes = encrypted_data.size();
        status = sa_crypto_cipher_process(decrypted_buffer.get(), *decrypt_cipher, encrypted_in_buffer.get(),
                &decrypt_bytes);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(decrypt_bytes, encrypted_data.size());

        // Finalize and verify the tag (no more data to process)
        size_t decrypt_bytes_last = 0;
        sa_cipher_end_parameters_aes_gcm decrypt_end_parameters = {parameters.tag.data(), parameters.tag.size()};
        status = sa_crypto_cipher_process_last(decrypted_buffer.get(), *decrypt_cipher, encrypted_in_buffer.get(),
                &decrypt_bytes_last, &decrypt_end_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Verify decrypted data matches original
        ASSERT_TRUE(verify_decrypt(decrypted_buffer.get(), clear));
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processLastAesDecryptGcmShortTag) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        parameters.iv = random(GCM_IV_LENGTH);
        parameters.aad = random(36);
        parameters.tag = std::vector<uint8_t>(MAX_GCM_TAG_LENGTH - 4);
        parameters.clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        parameters.key = create_sa_key_symmetric(&rights, parameters.clear_key);
        ASSERT_NE(parameters.key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_cipher_parameters_aes_gcm gcm_parameters = {parameters.iv.data(), parameters.iv.size(),
                parameters.aad.data(), parameters.aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
                *parameters.key, &gcm_parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(8);

        // encrypt using OpenSSL
        auto encrypted = std::vector<uint8_t>(clear.size());
        ASSERT_TRUE(encrypt_aes_gcm_openssl(encrypted, clear, parameters.iv, parameters.aad, parameters.tag,
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
        sa_cipher_end_parameters_aes_gcm end_parameters = {parameters.tag.data(), parameters.tag.size()};
        status = sa_crypto_cipher_process_last(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process,
                &end_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastAesGcmFailsInvalidOutLength) {
        sa_cipher_mode const cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(GCM_IV_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_aes_gcm parameters = {iv.data(), iv.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_GCM, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> tag(AES_BLOCK_SIZE);
        sa_cipher_end_parameters_aes_gcm end_parameters = {tag.data(), tag.size()};

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

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastAesGcmFailsInvalidInLength) {
        sa_cipher_mode const cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(GCM_IV_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_aes_gcm parameters = {iv.data(), iv.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_GCM, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> tag(AES_BLOCK_SIZE);
        sa_cipher_end_parameters_aes_gcm end_parameters = {tag.data(), tag.size()};

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

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastAesGcmFailsNullParameters) {
        sa_cipher_mode const cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(GCM_IV_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_aes_gcm parameters = {iv.data(), iv.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_GCM, cipher_mode, *key,
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

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastAesGcmFailsNullTag) {
        sa_cipher_mode const cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(GCM_IV_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_aes_gcm parameters = {iv.data(), iv.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_GCM, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        sa_cipher_end_parameters_aes_gcm end_parameters = {nullptr, 0};

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

    TEST_P(SaCryptoCipherWithoutSvpTest, processLastAesGcmFailsInvalidTagLength) {
        sa_cipher_mode const cipher_mode = std::get<0>(GetParam());
        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(GCM_IV_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_aes_gcm parameters = {iv.data(), iv.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_GCM, cipher_mode, *key,
                &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> tag(AES_BLOCK_SIZE + 1);
        sa_cipher_end_parameters_aes_gcm end_parameters = {tag.data(), tag.size()};

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
