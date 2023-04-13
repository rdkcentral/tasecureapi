/**
 * Copyright 2022-2023 Comcast Cable Communications Management, LLC
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

#include "sa_engine_common.h"
#if OPENSSL_VERSION_NUMBER < 0x30000000
#include "client_test_helpers.h"
#include "digest_util.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>

using namespace client_test_helpers;

TEST_P(SaEnginePkeyEncryptTest, encryptTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    auto padding = std::get<2>(GetParam());
    auto oaep_digest_algorithm = std::get<3>(GetParam());
    auto oaep_mgf1_digest_algorithm = std::get<4>(GetParam());
    auto oaep_label = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);

    auto data = random(32);
    auto label = random(oaep_label);
    std::vector<uint8_t> encrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> encrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(encrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_encrypt_init(encrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(encrypt_pkey_ctx.get(), padding), 1);
    if (padding == RSA_PKCS1_OAEP_PADDING) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_oaep_md(encrypt_pkey_ctx.get(), digest_mechanism(oaep_digest_algorithm)), 1);
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(encrypt_pkey_ctx.get(), digest_mechanism(oaep_mgf1_digest_algorithm)),
                1);
        if (oaep_label > 0) {
            void* new_label = malloc(label.size());
            if (new_label == nullptr) {
                GTEST_FATAL_FAILURE_("malloc failed");
            }

            memcpy(new_label, label.data(), label.size());
            if (EVP_PKEY_CTX_set0_rsa_oaep_label(encrypt_pkey_ctx.get(), new_label,
                        static_cast<int>(label.size())) != 1) {
                free(new_label);
                GTEST_FATAL_FAILURE_("EVP_PKEY_CTX_set0_rsa_oaep_label failed");
            }
        }
    }

    size_t encrypted_data_length = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), nullptr, &encrypted_data_length, data.data(), data.size()), 1);
    encrypted_data.resize(encrypted_data_length);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());
    if (result == OPENSSL_NOT_SUPPORTED)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(decrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(decrypt_pkey_ctx.get(), padding), 1);
    if (padding == RSA_PKCS1_OAEP_PADDING) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_oaep_md(decrypt_pkey_ctx.get(), digest_mechanism(oaep_digest_algorithm)), 1);
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(decrypt_pkey_ctx.get(), digest_mechanism(oaep_mgf1_digest_algorithm)),
                1);
        if (oaep_label > 0) {
            void* new_label = malloc(label.size());
            if (new_label == nullptr) {
                GTEST_FATAL_FAILURE_("malloc failed");
            }

            memcpy(new_label, label.data(), label.size());
            if (EVP_PKEY_CTX_set0_rsa_oaep_label(decrypt_pkey_ctx.get(), new_label,
                        static_cast<int>(label.size())) != 1) {
                free(new_label);
                GTEST_FATAL_FAILURE_("EVP_PKEY_CTX_set0_rsa_oaep_label failed");
            }
        }
    }

    size_t decrypted_data_length = 0;
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), nullptr, &decrypted_data_length, encrypted_data.data(),
            encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), decrypted_data.data(), &decrypted_data_length,
            encrypted_data.data(), encrypted_data.size());
    if (result == OPENSSL_NOT_SUPPORTED)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    ASSERT_EQ(decrypted_data, data);
}

TEST_F(SaEnginePkeyEncryptTest, defaultPaddingTest) {
    sa_key_type key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;
    int padding = RSA_PKCS1_PADDING;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);

    auto data = random(32);
    std::vector<uint8_t> encrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> encrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(encrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_encrypt_init(encrypt_pkey_ctx.get()), 1);
    size_t encrypted_data_length = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), nullptr, &encrypted_data_length, data.data(), data.size()), 1);
    encrypted_data.resize(encrypted_data_length);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());
    if (result == OPENSSL_NOT_SUPPORTED)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(decrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(decrypt_pkey_ctx.get(), padding), 1);
    size_t decrypted_data_length = 0;
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), nullptr, &decrypted_data_length, encrypted_data.data(),
            encrypted_data.size());
    if (result == OPENSSL_NOT_SUPPORTED)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), decrypted_data.data(), &decrypted_data_length,
            encrypted_data.data(), encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    ASSERT_EQ(decrypted_data, data);
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyPkcs1EncryptTests,
        SaEnginePkeyEncryptTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_PADDING),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsa1024OaepEncryptTests,
        SaEnginePkeyEncryptTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_OAEP_PADDING),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsa2048OaepEncryptTests,
        SaEnginePkeyEncryptTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_2048_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_OAEP_PADDING),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsa3072OaepEncryptTests,
        SaEnginePkeyEncryptTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_3072_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_OAEP_PADDING),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsa4096OaepEncryptTests,
        SaEnginePkeyEncryptTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_4096_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_OAEP_PADDING),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16)));
// clang-format on
#endif
