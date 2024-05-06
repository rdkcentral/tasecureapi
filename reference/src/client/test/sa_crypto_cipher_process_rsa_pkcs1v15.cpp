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
#include <openssl/evp.h>

using namespace client_test_helpers;

namespace {
    TEST_F(SaCryptoCipherWithoutSvpTest, processRsaPkcs1v15FailsInvalidInLength) {
        auto clear_key = sample_rsa_2048_pkcs8();

        auto rsa = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa, nullptr);

        auto clear = random(65);
        auto in = std::vector<uint8_t>(EVP_PKEY_bits(rsa.get()) / 8);
        size_t const in_length = in.size();
        ASSERT_TRUE(encrypt_rsa_pkcs1v15_openssl(in, clear, rsa));
        in.resize(in_length - 1);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_RSA_PKCS1V15, SA_CIPHER_MODE_DECRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(cipher, nullptr);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, in);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = in.size();

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, EVP_PKEY_bits(rsa.get()) / 8);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processRsaPkcs1v15InvalidOutLength) {
        auto clear_key = sample_rsa_2048_pkcs8();

        auto rsa = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa, nullptr);

        auto clear = random(65);
        auto in = std::vector<uint8_t>(EVP_PKEY_bits(rsa.get()) / 8);
        size_t const in_length = in.size();
        ASSERT_TRUE(encrypt_rsa_pkcs1v15_openssl(in, clear, rsa));
        in.resize(in_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_RSA_PKCS1V15, SA_CIPHER_MODE_DECRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(cipher, nullptr);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, in);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = in.size();

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, EVP_PKEY_bits(rsa.get()) / 8 - 12);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST_F(SaCryptoCipherWithoutSvpTest, processRsaPkcs1v15InvalidInPadding) {
        auto clear_key = sample_rsa_2048_pkcs8();

        auto rsa = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa, nullptr);

        auto in = std::vector<uint8_t>(EVP_PKEY_bits(rsa.get()) / 8);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_RSA_PKCS1V15, SA_CIPHER_MODE_DECRYPT,
                *key, nullptr);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(cipher, nullptr);

        // Initializing PKCS#1 v1.5 input buffer with garbage padding.
        std::fill(in.begin(), in.begin() + 4, 0xff);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, in);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = in.size();

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, EVP_PKEY_bits(rsa.get()) / 8);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_VERIFICATION_FAILED);
    }

    TEST_F(SaCryptoCipherSvpOnlyTest, processRsaPkcs1v15FailsInvalidBufferType) {
        auto clear_key = sample_rsa_2048_pkcs8();

        auto rsa = rsa_import_pkcs8(clear_key);
        ASSERT_NE(rsa, nullptr);

        auto clear = random(65);
        auto in = std::vector<uint8_t>(EVP_PKEY_bits(rsa.get()) / 8);
        size_t const in_length = in.size();
        ASSERT_TRUE(encrypt_rsa_oaep_openssl(in, clear, rsa, SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA1, {}));
        in.resize(in_length);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto key = create_sa_key_rsa(&rights, clear_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        auto cipher = create_uninitialized_sa_crypto_cipher_context();
        ASSERT_NE(cipher, nullptr);

        sa_cipher_parameters_rsa_oaep parameters = {SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA256, nullptr, 0};
        sa_status status = sa_crypto_cipher_init(cipher.get(), SA_CIPHER_ALGORITHM_RSA_OAEP, SA_CIPHER_MODE_DECRYPT,
                *key, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Cipher algorithm not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_NE(cipher, nullptr);

        auto in_buffer = buffer_alloc(SA_BUFFER_TYPE_CLEAR, in);
        ASSERT_NE(in_buffer, nullptr);
        size_t bytes_to_process = in.size();

        auto out_buffer = buffer_alloc(SA_BUFFER_TYPE_SVP, EVP_PKEY_bits(rsa.get()) / 8);
        ASSERT_NE(out_buffer, nullptr);
        status = sa_crypto_cipher_process(out_buffer.get(), *cipher, in_buffer.get(), &bytes_to_process);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }
} // namespace
