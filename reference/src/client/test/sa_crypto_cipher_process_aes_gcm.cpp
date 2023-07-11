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
    TEST_F(SaCryptoCipherWithoutSvpTest, processAesGcmNominalEncryptAes128NullAadZeroLength) {
        cipher_parameters parameters = {
                .cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM,
                .key = nullptr,
                .clear_key = {},
                .iv = {},
                .aad = {},
                .tag = {},
                .parameters = nullptr,
                .end_parameters = nullptr,
                .curve = SA_ELLIPTIC_CURVE_NIST_P256,
                .oaep_digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .oaep_mgf1_digest_algorithm = SA_DIGEST_ALGORITHM_SHA1,
                .oaep_label_length = 0,
                .svp_required = false};

        ASSERT_TRUE(import_key(parameters, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE));
        if (*parameters.key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        parameters.iv = random(GCM_IV_LENGTH);
        parameters.aad = {};
        parameters.tag = std::vector<uint8_t>(AES_BLOCK_SIZE);
        auto* cipher_parameters_aes_gcm = new sa_cipher_parameters_aes_gcm;
        cipher_parameters_aes_gcm->iv = parameters.iv.data();
        cipher_parameters_aes_gcm->iv_length = parameters.iv.size();
        cipher_parameters_aes_gcm->aad = nullptr;
        cipher_parameters_aes_gcm->aad_length = 0;
        parameters.parameters = std::shared_ptr<sa_cipher_parameters_aes_gcm>(cipher_parameters_aes_gcm);

        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_ENCRYPT,
                *parameters.key, parameters.parameters.get());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the encryption.
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, false));
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processAesGcmNominalDecryptAes128NullAadZeroLength) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        parameters.svp_required = false;

        ASSERT_TRUE(import_key(parameters, SA_KEY_TYPE_SYMMETRIC, SYM_128_KEY_SIZE));
        if (*parameters.key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        parameters.iv = random(GCM_IV_LENGTH);
        parameters.aad = {};
        parameters.tag = std::vector<uint8_t>(AES_BLOCK_SIZE);
        auto* cipher_parameters_aes_gcm = new sa_cipher_parameters_aes_gcm;
        cipher_parameters_aes_gcm->iv = parameters.iv.data();
        cipher_parameters_aes_gcm->iv_length = parameters.iv.size();
        cipher_parameters_aes_gcm->aad = nullptr;
        cipher_parameters_aes_gcm->aad_length = 0;
        parameters.parameters = std::shared_ptr<sa_cipher_parameters_aes_gcm>(cipher_parameters_aes_gcm);

        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
                *parameters.key, parameters.parameters.get());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        // encrypt using OpenSSL
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        // get out_length
        size_t bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, encrypted.size());

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processAesGcmNominalEncryptAes256NullAadZeroLength) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        parameters.svp_required = false;

        ASSERT_TRUE(import_key(parameters, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE));
        if (*parameters.key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        parameters.iv = random(GCM_IV_LENGTH);
        parameters.aad = {};
        parameters.tag = std::vector<uint8_t>(AES_BLOCK_SIZE);
        auto* cipher_parameters_aes_gcm = new sa_cipher_parameters_aes_gcm;
        cipher_parameters_aes_gcm->iv = parameters.iv.data();
        cipher_parameters_aes_gcm->iv_length = parameters.iv.size();
        cipher_parameters_aes_gcm->aad = nullptr;
        cipher_parameters_aes_gcm->aad_length = 0;
        parameters.parameters = std::shared_ptr<sa_cipher_parameters_aes_gcm>(cipher_parameters_aes_gcm);

        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_ENCRYPT,
                *parameters.key, parameters.parameters.get());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the encryption.
        ASSERT_TRUE(verify_encrypt(out_buffer.get(), clear, parameters, false));
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processAesGcmNominalDecryptAes256NullAadZeroLength) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        parameters.svp_required = false;

        ASSERT_TRUE(import_key(parameters, SA_KEY_TYPE_SYMMETRIC, SYM_256_KEY_SIZE));
        if (*parameters.key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        parameters.iv = random(GCM_IV_LENGTH);
        parameters.aad = {};
        parameters.tag = std::vector<uint8_t>(AES_BLOCK_SIZE);
        auto* cipher_parameters_aes_gcm = new sa_cipher_parameters_aes_gcm;
        cipher_parameters_aes_gcm->iv = parameters.iv.data();
        cipher_parameters_aes_gcm->iv_length = parameters.iv.size();
        cipher_parameters_aes_gcm->aad = nullptr;
        cipher_parameters_aes_gcm->aad_length = 0;
        parameters.parameters = std::shared_ptr<sa_cipher_parameters_aes_gcm>(cipher_parameters_aes_gcm);

        sa_status status = sa_crypto_cipher_init(cipher.get(), parameters.cipher_algorithm, SA_CIPHER_MODE_DECRYPT,
                *parameters.key, parameters.parameters.get());
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        // encrypt using OpenSSL
        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        // get out_length
        size_t bytes_to_process = clear.size();
        status = sa_crypto_cipher_process(nullptr, *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, encrypted.size());

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, bytes_to_process);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(bytes_to_process, clear.size());

        // Verify the decryption.
        ASSERT_TRUE(verify_decrypt(out_buffer.get(), clear));
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processAesGcmEncryptResumePartialBlock) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        parameters.svp_required = false;
        sa_key_type const key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t const key_size = SYM_128_KEY_SIZE;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_ENCRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        auto clear = random(34);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);

        // encrypt using SecApi
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
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

    TEST_F(SaCryptoCipherWithoutSvpTest, processAesGcmDecryptResumePartialBlock) {
        cipher_parameters parameters;
        parameters.cipher_algorithm = SA_CIPHER_ALGORITHM_AES_GCM;
        parameters.svp_required = false;
        sa_key_type const key_type = SA_KEY_TYPE_SYMMETRIC;
        size_t const key_size = SYM_128_KEY_SIZE;

        auto cipher = initialize_cipher(SA_CIPHER_MODE_DECRYPT, key_type, key_size, parameters);
        ASSERT_NE(cipher, nullptr);
        if (*cipher == UNSUPPORTED_CIPHER)
            GTEST_SKIP() << "Cipher algorithm not supported";

        // encrypt using OpenSSL
        auto clear = random(34);

        auto encrypted = encrypt_openssl(clear, parameters);
        ASSERT_FALSE(encrypted.empty());

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, encrypted);
        ASSERT_NE(in_buffer, nullptr);

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
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

    TEST_P(SaCryptoCipherWithoutSvpTest, processAesGcmFailsInvalidOutLength) {
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

        auto clear = random(33);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size() - 1);
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initAesGcmFailsSvpIn) {
        if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(GCM_IV_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_aes_gcm parameters = {iv.data(), iv.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_GCM, SA_CIPHER_MODE_DECRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, initAesGcmFailsSvpOut) {
        if (sa_svp_supported() == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "SVP not supported. Skipping all SVP tests";

        auto clear_key = random(SYM_128_KEY_SIZE);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_SVP_OPTIONAL);

        auto key = create_sa_key_symmetric(&rights, clear_key);
        ASSERT_NE(key, nullptr);

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        auto iv = random(GCM_IV_LENGTH);
        auto aad = random(36);
        sa_cipher_parameters_aes_gcm parameters = {iv.data(), iv.size(), aad.data(), aad.size()};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_AES_GCM, SA_CIPHER_MODE_DECRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto clear = random(static_cast<size_t>(AES_BLOCK_SIZE) * 2);
        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, clear);
        ASSERT_NE(in_buffer, nullptr);
        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, clear.size());
        ASSERT_NE(out_buffer, nullptr);
        size_t bytes_to_process = clear.size();

        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
} // namespace
