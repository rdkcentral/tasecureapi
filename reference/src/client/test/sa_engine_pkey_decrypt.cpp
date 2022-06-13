/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
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
#include "sa_engine_common.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

using namespace client_test_helpers;

TEST_P(SaEnginePkeyEncryptTest, encryptTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    auto padding = std::get<2>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

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
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(encrypt_pkey_ctx.get(), padding), 1);
    size_t encrypted_data_length = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), nullptr, &encrypted_data_length, data.data(), data.size()), 1);
    encrypted_data.resize(encrypted_data_length);
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());
    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(decrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(decrypt_pkey_ctx.get(), padding), 1);
    size_t decrypted_data_length = 0;
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), nullptr, &decrypted_data_length, encrypted_data.data(),
            encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), decrypted_data.data(), &decrypted_data_length,
            encrypted_data.data(), encrypted_data.size());
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
        GTEST_SKIP() << "key type not supported";

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
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());
    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_decrypt_init(decrypt_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(decrypt_pkey_ctx.get(), padding), 1);
    size_t decrypted_data_length = 0;
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), nullptr, &decrypted_data_length, encrypted_data.data(),
            encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    result = EVP_PKEY_decrypt(decrypt_pkey_ctx.get(), decrypted_data.data(), &decrypted_data_length,
            encrypted_data.data(), encrypted_data.size());
    ASSERT_EQ(result, 1);
    decrypted_data.resize(decrypted_data_length);
    ASSERT_EQ(decrypted_data, data);
}

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyEncryptTests,
        SaEnginePkeyEncryptTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH, RSA_4096_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING)));
