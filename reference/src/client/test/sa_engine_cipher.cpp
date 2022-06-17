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

using namespace client_test_helpers;

TEST_P(SaEngineCipherTest, encryptTest) {
    int nid = std::get<0>(GetParam());
    int padded = std::get<1>(GetParam());
    int key_length = std::get<2>(GetParam());
    int iv_length = std::get<3>(GetParam());

    const EVP_CIPHER* cipher = EVP_get_cipherbynid(nid);

    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    bool include_aad = nid == NID_aes_128_gcm || nid == NID_aes_256_gcm || nid == NID_chacha20_poly1305;
#else
    bool include_aad = nid == NID_aes_128_gcm || nid == NID_aes_256_gcm;
#endif
    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);
    auto data = random(16);
    auto iv = random(iv_length);
    auto aad = include_aad ? random(256) : std::vector<uint8_t>(0);
    std::vector<uint8_t> encrypted(128);

    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    ASSERT_EQ(1, EVP_EncryptInit_ex(cipher_ctx.get(), cipher, engine.get(),
                         reinterpret_cast<const unsigned char*>(key.get()), iv.data()));
    ASSERT_EQ(EVP_CIPHER_CTX_set_padding(cipher_ctx.get(), padded), 1);

    int length;
    int total_length = 0;
    if (!aad.empty()) {
        ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), nullptr, &length, aad.data(), aad.size()));
    }

    ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), encrypted.data(), &length, data.data(), data.size()));
    total_length += length;
    ASSERT_NE(0, EVP_EncryptFinal(cipher_ctx.get(), encrypted.data() + total_length, &length));
    total_length += length;
    encrypted.resize(total_length);

    std::vector<uint8_t> tag = {};
    if (include_aad) {
        tag.resize(16);
        ASSERT_EQ(1, EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()));
    }

    ASSERT_TRUE(verifyEncrypt(encrypted, data, clear_key, iv, aad, tag, cipher, padded));
}

TEST_P(SaEngineCipherTest, decryptTest) {
    int nid = std::get<0>(GetParam());
    int padded = std::get<1>(GetParam());
    int key_length = std::get<2>(GetParam());
    int iv_length = std::get<3>(GetParam());

    const EVP_CIPHER* cipher = EVP_get_cipherbynid(nid);

    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);

#if OPENSSL_VERSION_NUMBER >= 0x10100000
    bool include_aad = nid == NID_aes_128_gcm || nid == NID_aes_256_gcm || nid == NID_chacha20_poly1305;
#else
    bool include_aad = nid == NID_aes_128_gcm || nid == NID_aes_256_gcm;
#endif
    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);
    auto data = random(16);
    auto iv = random(iv_length);
    auto aad = include_aad ? random(256) : std::vector<uint8_t>(0);
    std::vector<uint8_t> tag(include_aad ? 16 : 0);
    std::vector<uint8_t> encrypted(128);
    std::vector<uint8_t> decrypted(128);

    ASSERT_TRUE(doEncrypt(encrypted, data, clear_key, iv, aad, tag, cipher, padded));
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    ASSERT_EQ(1, EVP_DecryptInit_ex(cipher_ctx.get(), cipher, engine.get(),
                         reinterpret_cast<const unsigned char*>(key.get()), iv.data()));
    ASSERT_NE(0, EVP_CIPHER_CTX_set_padding(cipher_ctx.get(), padded));

    int length;
    int total_length = 0;
    if (!aad.empty()) {
        ASSERT_EQ(1, EVP_DecryptUpdate(cipher_ctx.get(), nullptr, &length, aad.data(), aad.size()));
    }

    ASSERT_EQ(1, EVP_DecryptUpdate(cipher_ctx.get(), decrypted.data(), &length, encrypted.data(), encrypted.size()));
    total_length += length;
    if (include_aad) {
        ASSERT_EQ(1, EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()));
    }

    ASSERT_EQ(1, EVP_DecryptFinal(cipher_ctx.get(), decrypted.data() + total_length, &length));
    total_length += length;
    decrypted.resize(total_length);
    ASSERT_EQ(decrypted, data);
}

TEST_F(SaEngineCipherTest, initSeparateParams) {
    int nid = NID_aes_128_cbc;
    int padded = 1;
    int key_length = 16;
    int iv_length = 16;

    const EVP_CIPHER* cipher = EVP_get_cipherbynid(nid);

    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);

    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);
    auto data = random(16);
    auto iv = random(iv_length);
    auto aad = std::vector<uint8_t>(0);
    std::vector<uint8_t> encrypted(128);

    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    ASSERT_EQ(1, EVP_EncryptInit_ex(cipher_ctx.get(), cipher, engine.get(), nullptr, nullptr));
    ASSERT_EQ(1, EVP_EncryptInit_ex(cipher_ctx.get(), nullptr, engine.get(),
                         reinterpret_cast<const unsigned char*>(key.get()), nullptr));
    ASSERT_EQ(1, EVP_EncryptInit_ex(cipher_ctx.get(), nullptr, engine.get(), nullptr, iv.data()));
    ASSERT_EQ(EVP_CIPHER_CTX_set_padding(cipher_ctx.get(), padded), 1);

    int length;
    int total_length = 0;
    if (!aad.empty()) {
        ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), nullptr, &length, aad.data(), aad.size()));
    }

    ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), encrypted.data(), &length, data.data(), data.size()));
    total_length += length;
    ASSERT_NE(0, EVP_EncryptFinal(cipher_ctx.get(), encrypted.data() + total_length, &length));
    total_length += length;
    encrypted.resize(total_length);

    std::vector<uint8_t> tag = {};
    ASSERT_TRUE(verifyEncrypt(encrypted, data, clear_key, iv, aad, tag, cipher, padded));
}

INSTANTIATE_TEST_SUITE_P(
        SaEngineCipherTestTests,
        SaEngineCipherTest,
        ::testing::Values(
#if OPENSSL_VERSION_NUMBER >= 0x10100000
                std::make_tuple(NID_chacha20, true, 32, 16),
                std::make_tuple(NID_chacha20_poly1305, true, 32, 12),
#endif
                std::make_tuple(NID_aes_128_ecb, true, 16, 0),
                std::make_tuple(NID_aes_128_ecb, false, 16, 0),
                std::make_tuple(NID_aes_256_ecb, true, 32, 0),
                std::make_tuple(NID_aes_256_ecb, false, 32, 0),
                std::make_tuple(NID_aes_128_cbc, true, 16, 16),
                std::make_tuple(NID_aes_128_cbc, false, 16, 16),
                std::make_tuple(NID_aes_256_cbc, true, 32, 16),
                std::make_tuple(NID_aes_256_cbc, false, 32, 16),
                std::make_tuple(NID_aes_128_ctr, false, 16, 16),
                std::make_tuple(NID_aes_256_ctr, false, 32, 16),
                std::make_tuple(NID_aes_128_gcm, false, 16, 12),
                std::make_tuple(NID_aes_256_gcm, false, 32, 12)));
