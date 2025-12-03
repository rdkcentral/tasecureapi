/*
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

#include "sa_provider_common.h"
#if OPENSSL_VERSION_NUMBER >= 0x30000000
#include "client_test_helpers.h"
#include "sa.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>

using namespace client_test_helpers;

namespace {
    sa_status check_algorithm_supported(
            const char* algorithm_name,
            ossl_unused std::shared_ptr<sa_key>& key) {

        auto status = SA_STATUS_OK;

        // Check for algorithm support.
        if (strcmp(algorithm_name, SN_chacha20) == 0) {
            auto cipher_context = create_uninitialized_sa_crypto_cipher_context();
            auto nonce = random(CHACHA20_NONCE_LENGTH);
            auto counter = random(CHACHA20_COUNTER_LENGTH);
            sa_cipher_parameters_chacha20 parameters = {counter.data(), counter.size(), nonce.data(),
                    nonce.size()};
            status = sa_crypto_cipher_init(cipher_context.get(), SA_CIPHER_ALGORITHM_CHACHA20,
                    SA_CIPHER_MODE_ENCRYPT, *key, &parameters);
        } else if (strcmp(algorithm_name, SN_chacha20_poly1305) == 0) {
            auto cipher_context = create_uninitialized_sa_crypto_cipher_context();
            auto nonce = random(CHACHA20_NONCE_LENGTH);
            auto aad = random(CHACHA20_COUNTER_LENGTH);
            sa_cipher_parameters_chacha20_poly1305 parameters = {nonce.data(), nonce.size(), aad.data(), aad.size()};
            status = sa_crypto_cipher_init(cipher_context.get(), SA_CIPHER_ALGORITHM_CHACHA20_POLY1305,
                    SA_CIPHER_MODE_ENCRYPT, *key, &parameters);
        }

        return status;
    }
} // namespace

TEST_P(SaProviderCipherTest, encryptTest) {
    const char* algorithm_name = std::get<0>(GetParam());
    int const padded = std::get<1>(GetParam());
    int const key_length = std::get<2>(GetParam());
    int const iv_length = std::get<3>(GetParam());

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    bool const include_aad = strcmp(algorithm_name, SN_aes_128_gcm) == 0 ||
                             strcmp(algorithm_name, SN_aes_256_gcm) == 0 ||
                             strcmp(algorithm_name, SN_chacha20_poly1305) == 0;
    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);
    if (check_algorithm_supported(algorithm_name, key) == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "algorithm not supported";

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_uint64(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    auto data = random((padded == 1) ? 50 : 48);
    auto iv = random(iv_length);
    auto aad = include_aad ? random(256) : std::vector<uint8_t>(0);
    std::vector<uint8_t> encrypted(128);

    std::shared_ptr<EVP_CIPHER> const cipher = {EVP_CIPHER_fetch(lib_ctx, algorithm_name, nullptr), EVP_CIPHER_free};
    ASSERT_NE(cipher, nullptr);
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    ASSERT_EQ(1, EVP_EncryptInit_ex2(cipher_ctx.get(), cipher.get(), nullptr, iv.data(), params));
    ASSERT_EQ(EVP_CIPHER_CTX_set_padding(cipher_ctx.get(), padded), 1);

    int length;
    int total_length = 0;
    if (!aad.empty()) {
        ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), nullptr, &length, aad.data(), aad.size()));
    }

    ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), encrypted.data(), &length, data.data(), 12));
    total_length += length;
    ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), encrypted.data() + total_length, &length, data.data() + 12, 28));
    total_length += length;
    ASSERT_EQ(1, EVP_EncryptUpdate(cipher_ctx.get(), encrypted.data() + total_length, &length, data.data() + 40,
                         data.size() - 40));
    total_length += length;
    ASSERT_NE(0, EVP_EncryptFinal(cipher_ctx.get(), encrypted.data() + total_length, &length));
    total_length += length;
    encrypted.resize(total_length);

    std::vector<uint8_t> tag = {};
    if (include_aad) {
        tag.resize(16);
        ASSERT_EQ(1, EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data()));
    }

    ASSERT_TRUE(verifyEncrypt(encrypted, data, clear_key, iv, aad, tag, algorithm_name, padded));

    cipher_ctx.reset();
    sa_header header;
    ASSERT_EQ(sa_key_header(&header, *key), SA_STATUS_OK);
}

TEST_P(SaProviderCipherTest, decryptTest) {
    const char* algorithm_name = std::get<0>(GetParam());
    int const padded = std::get<1>(GetParam());
    int const key_length = std::get<2>(GetParam());
    int const iv_length = std::get<3>(GetParam());

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    bool const include_aad = strcmp(algorithm_name, SN_aes_128_gcm) == 0 ||
                             strcmp(algorithm_name, SN_aes_256_gcm) == 0 ||
                             strcmp(algorithm_name, SN_chacha20_poly1305) == 0;
    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);
    if (check_algorithm_supported(algorithm_name, key) == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "algorithm not supported";

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_uint64(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    auto data = random((padded == 1) ? 50 : 48);
    auto iv = random(iv_length);
    auto aad = include_aad ? random(256) : std::vector<uint8_t>(0);
    std::vector<uint8_t> tag(include_aad ? 16 : 0);
    std::vector<uint8_t> encrypted(128);
    std::vector<uint8_t> decrypted(128);

    ASSERT_TRUE(doEncrypt(encrypted, data, clear_key, iv, aad, tag, algorithm_name, padded));

    std::shared_ptr<EVP_CIPHER> const cipher = {EVP_CIPHER_fetch(lib_ctx, algorithm_name, nullptr), EVP_CIPHER_free};
    ASSERT_NE(cipher, nullptr);
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    ASSERT_EQ(1, EVP_DecryptInit_ex2(cipher_ctx.get(), cipher.get(), nullptr, iv.data(), params));
    ASSERT_NE(0, EVP_CIPHER_CTX_set_padding(cipher_ctx.get(), padded));

    int length;
    int total_length = 0;
    if (!aad.empty()) {
        ASSERT_EQ(1, EVP_DecryptUpdate(cipher_ctx.get(), nullptr, &length, aad.data(), aad.size()));
    }

    ASSERT_EQ(1, EVP_DecryptUpdate(cipher_ctx.get(), decrypted.data(), &length, encrypted.data(), 12));
    total_length += length;
    ASSERT_EQ(1, EVP_DecryptUpdate(cipher_ctx.get(), decrypted.data() + total_length, &length, encrypted.data() + 12,
                         28));
    total_length += length;
    ASSERT_EQ(1, EVP_DecryptUpdate(cipher_ctx.get(), decrypted.data() + total_length, &length, encrypted.data() + 40,
                         encrypted.size() - 40));
    total_length += length;
    if (include_aad) {
        ASSERT_EQ(1, EVP_CIPHER_CTX_ctrl(cipher_ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()));
    }

    ASSERT_EQ(1, EVP_DecryptFinal(cipher_ctx.get(), decrypted.data() + total_length, &length));
    total_length += length;
    decrypted.resize(total_length);
    ASSERT_EQ(decrypted, data);

    cipher_ctx.reset();
    sa_header header;
    ASSERT_EQ(sa_key_header(&header, *key), SA_STATUS_OK);
}

TEST_P(SaProviderCipherTest, initSeparateParams) {
    const char* algorithm_name = std::get<0>(GetParam());
    int const padded = std::get<1>(GetParam());
    int const key_length = std::get<2>(GetParam());
    int const iv_length = std::get<3>(GetParam());

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    bool const include_aad = strcmp(algorithm_name, SN_aes_128_gcm) == 0 ||
                             strcmp(algorithm_name, SN_aes_256_gcm) == 0 ||
                             strcmp(algorithm_name, SN_chacha20_poly1305) == 0;
    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);
    if (check_algorithm_supported(algorithm_name, key) == SA_STATUS_OPERATION_NOT_SUPPORTED)
        GTEST_SKIP() << "algorithm not supported";

    auto data = random((padded == 1) ? 23 : 16);
    auto iv = random(iv_length);
    auto aad = include_aad ? random(256) : std::vector<uint8_t>(0);
    std::vector<uint8_t> encrypted(128);
    std::shared_ptr<EVP_CIPHER> const cipher = {EVP_CIPHER_fetch(lib_ctx, algorithm_name, nullptr), EVP_CIPHER_free};
    ASSERT_NE(cipher, nullptr);
    std::shared_ptr<EVP_CIPHER_CTX> cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    ASSERT_EQ(1, EVP_EncryptInit_ex2(cipher_ctx.get(), cipher.get(), nullptr, nullptr, nullptr));
    ASSERT_EQ(1, EVP_EncryptInit_ex2(cipher_ctx.get(), nullptr, clear_key.data(), nullptr, nullptr));
    ASSERT_EQ(1, EVP_EncryptInit_ex2(cipher_ctx.get(), nullptr, nullptr, iv.data(), nullptr));
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

    ASSERT_TRUE(verifyEncrypt(encrypted, data, clear_key, iv, aad, tag, algorithm_name, padded));

    sa_key key1;
    OSSL_PARAM params2[] = {
            OSSL_PARAM_construct_uint64(OSSL_PARAM_SA_KEY, &key1),
            OSSL_PARAM_construct_end()};
    ASSERT_EQ(EVP_CIPHER_CTX_get_params(cipher_ctx.get(), params2), 1);
    cipher_ctx.reset();
    sa_header header;
    ASSERT_EQ(sa_key_header(&header, key1), SA_STATUS_INVALID_PARAMETER);
}

INSTANTIATE_TEST_SUITE_P(
        SaProviderCipherTestTests,
        SaProviderCipherTest,
        ::testing::Values(
                std::make_tuple(SN_chacha20, true, 32, 16),
                std::make_tuple(SN_chacha20_poly1305, false, 32, 12),  // AEAD: no padding
                std::make_tuple(SN_aes_128_ecb, true, 16, 0),
                std::make_tuple(SN_aes_128_ecb, false, 16, 0),
                std::make_tuple(SN_aes_256_ecb, true, 32, 0),
                std::make_tuple(SN_aes_256_ecb, false, 32, 0),
                std::make_tuple(SN_aes_128_cbc, true, 16, 16),
                std::make_tuple(SN_aes_128_cbc, false, 16, 16),
                std::make_tuple(SN_aes_256_cbc, true, 32, 16),
                std::make_tuple(SN_aes_256_cbc, false, 32, 16),
                std::make_tuple(SN_aes_128_ctr, true, 16, 16),
                std::make_tuple(SN_aes_256_ctr, true, 32, 16),
                std::make_tuple(SN_aes_128_gcm, false, 16, 12),
                std::make_tuple(SN_aes_256_gcm, false, 32, 12)));
#endif
