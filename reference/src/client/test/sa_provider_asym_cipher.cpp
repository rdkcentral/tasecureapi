/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
#include "digest_util.h"
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

using namespace client_test_helpers;

TEST_P(SaProviderAsymCipherTest, encryptTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    auto padding = std::get<2>(GetParam());
    auto oaep_digest_algorithm = std::get<3>(GetParam());
    auto oaep_mgf1_digest_algorithm = std::get<4>(GetParam());
    auto oaep_label = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    if (key_type == SA_KEY_TYPE_RSA) {
        clear_key = get_rsa_private_key(key_length);
    } else if (key_type == SA_KEY_TYPE_EC) {
        curve = static_cast<sa_elliptic_curve>(key_length);
        clear_key = ec_generate_key_bytes(curve);
    }

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    const uint8_t* p_clear_key = clear_key.data();
    EVP_PKEY* temp = d2i_AutoPrivateKey_ex(nullptr, &p_clear_key, static_cast<long>(clear_key.size()), // NOLINT
            lib_ctx, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);

    auto data = random(32);
    auto label = random(oaep_label);
    std::vector<uint8_t> encrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> encrypt_pkey_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(encrypt_pkey_ctx, nullptr);

    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &padding);
    if (padding == RSA_PKCS1_OAEP_PADDING) {
        params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                const_cast<char*>(digest_string(oaep_digest_algorithm)), 0);
        params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                const_cast<char*>(digest_string(oaep_mgf1_digest_algorithm)), 0);
    }

    if (oaep_label > 0) {
        params[p++] = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, label.data(), label.size());
    }

    params[p] = OSSL_PARAM_construct_end();

    ASSERT_EQ(EVP_PKEY_encrypt_init_ex(encrypt_pkey_ctx.get(), params), 1);

    size_t encrypted_data_length = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), nullptr, &encrypted_data_length, data.data(), data.size()), 1);
    encrypted_data.resize(encrypted_data_length);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());

    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);

    ASSERT_EQ(EVP_PKEY_decrypt_init_ex(decrypt_pkey_ctx.get(), params), 1);
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

TEST_F(SaProviderAsymCipherTest, defaultPaddingTest) {
    size_t key_length = RSA_2048_BYTE_LENGTH;
    int padding = RSA_PKCS1_PADDING;

    std::vector<uint8_t> clear_key;
    clear_key = get_rsa_private_key(key_length);

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    const uint8_t* p_clear_key = clear_key.data();
    EVP_PKEY* temp = d2i_AutoPrivateKey_ex(nullptr, &p_clear_key, static_cast<long>(clear_key.size()), // NOLINT
            lib_ctx, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    ASSERT_NE(evp_pkey, nullptr);

    auto data = random(32);
    std::vector<uint8_t> encrypted_data;
    std::shared_ptr<EVP_PKEY_CTX> encrypt_pkey_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(encrypt_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_encrypt_init(encrypt_pkey_ctx.get()), 1);
    size_t encrypted_data_length = 0;
    ASSERT_EQ(EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), nullptr, &encrypted_data_length, data.data(), data.size()), 1);
    encrypted_data.resize(encrypted_data_length);
    int result = EVP_PKEY_encrypt(encrypt_pkey_ctx.get(), encrypted_data.data(), &encrypted_data_length, data.data(),
            data.size());

    ASSERT_EQ(result, 1);

    std::vector<uint8_t> decrypted_data;
    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &padding),
            OSSL_PARAM_construct_end()};

    std::shared_ptr<EVP_PKEY_CTX> decrypt_pkey_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(decrypt_pkey_ctx, nullptr);

    ASSERT_EQ(EVP_PKEY_decrypt_init_ex(decrypt_pkey_ctx.get(), params), 1);
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

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProviderAsymCipherPkcs1EncryptTests,
        SaProviderAsymCipherTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_PADDING),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1),
                ::testing::Values(0)));

INSTANTIATE_TEST_SUITE_P(
        SaProviderAsymCipherRsa1024OaepEncryptTests,
        SaProviderAsymCipherTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH),
                ::testing::Values(RSA_PKCS1_OAEP_PADDING),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaProviderAsymCipherRsa2048OaepEncryptTests,
        SaProviderAsymCipherTest,
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
        SaProviderAsymCipherRsa3072OaepEncryptTests,
        SaProviderAsymCipherTest,
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
        SaProviderAsymCipherRsa4096OaepEncryptTests,
        SaProviderAsymCipherTest,
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
