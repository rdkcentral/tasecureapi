/*
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
#include <gtest/gtest.h>
#include <openssl/evp.h>

#define DEFAULT_DIGEST "SHA256"

using namespace client_test_helpers;

TEST_P(SaProviderSignTest, digestSignWithUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    const auto* const md_name = std::get<2>(GetParam());
    const auto* const mgf1_md_name = std::get<3>(GetParam());
    auto padding = std::get<4>(GetParam());
    auto salt = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    size_t signature_length = 0;
    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    int result = EVP_DigestSignInit_ex(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, md_name, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_sign_ctx, mgf1_md_name, nullptr), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestSignUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), nullptr, &signature_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), signature.data(), &signature_length), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, md_name, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_verify_ctx, mgf1_md_name, nullptr), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_P(SaProviderSignTest, signTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    const auto* const md_name = std::get<2>(GetParam());
    const auto* const mgf1_md_name = std::get<3>(GetParam());
    auto padding = std::get<4>(GetParam());
    auto salt = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    std::shared_ptr<EVP_MD> const evp_md(EVP_MD_fetch(lib_ctx, md_name, nullptr), EVP_MD_free);
    ASSERT_NE(evp_md, nullptr);
    ASSERT_EQ(EVP_DigestInit_ex2(evp_md_sign_ctx.get(), evp_md.get(), nullptr), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_sign_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_sign_ctx.get(), mgf1_md_name, nullptr), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx.get(), salt), 1);
        }
    }

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    EVP_PKEY_CTX* temp_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_verify_ctx(temp_ctx, EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_verify_ctx.get(), mgf1_md_name, nullptr), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), salt), 1);
        }
    }

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, md_name, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_ver2_ctx, mgf1_md_name, nullptr), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_P(SaProviderSignWithGenerateTest, signTestWithGenerateKey) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    const auto* const md_name = std::get<2>(GetParam());

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    sa_elliptic_curve curve;
    auto evp_pkey = generate_sa_key(lib_ctx, key_type, key_length, curve);
    if (evp_pkey == nullptr)
        GTEST_SKIP() << "Operation not supported";

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    std::shared_ptr<EVP_MD> const evp_md(EVP_MD_fetch(lib_ctx, md_name, nullptr), EVP_MD_free);
    ASSERT_NE(evp_md, nullptr);
    ASSERT_EQ(EVP_DigestInit_ex2(evp_md_sign_ctx.get(), evp_md.get(), nullptr), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_sign_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    EVP_PKEY_CTX* temp_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_verify_ctx(temp_ctx, EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, md_name, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_P(SaProviderSignDefaultDigestSignTest, defaultDigestTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    size_t signature_length = 0;
    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    int result = EVP_DigestSignInit_ex(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, nullptr, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, RSA_PKCS1_PADDING), 1);
    }

    ASSERT_EQ(EVP_DigestSignUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), nullptr, &signature_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), signature.data(), &signature_length), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, DEFAULT_DIGEST, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, RSA_PKCS1_PADDING), 1);
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_P(SaProviderSignDefaultDigestSignTest, defaultDigestTest2) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    std::shared_ptr<EVP_MD> const evp_md(EVP_MD_fetch(lib_ctx, DEFAULT_DIGEST, nullptr), EVP_MD_free);
    ASSERT_NE(evp_md, nullptr);
    ASSERT_EQ(EVP_DigestInit_ex2(evp_md_sign_ctx.get(), evp_md.get(), nullptr), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_sign_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), RSA_PKCS1_PADDING), 1);
    }

    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    EVP_PKEY_CTX* temp_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_verify_ctx(temp_ctx, EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), RSA_PKCS1_PADDING), 1);
    }

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, DEFAULT_DIGEST, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, RSA_PKCS1_PADDING), 1);
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_F(SaProviderSignTest, defaultPaddingTest) {
    sa_key_type const key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    std::shared_ptr<EVP_MD> const evp_md(EVP_MD_fetch(lib_ctx, DEFAULT_DIGEST, nullptr), EVP_MD_free);
    ASSERT_NE(evp_md, nullptr);
    ASSERT_EQ(EVP_DigestInit_ex2(evp_md_sign_ctx.get(), evp_md.get(), nullptr), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_sign_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    int const padding = RSA_PKCS1_PADDING;
    EVP_PKEY_CTX* temp_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_verify_ctx(temp_ctx, EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, DEFAULT_DIGEST, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_F(SaProviderSignTest, defaultSaltTest) {
    sa_key_type const key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    std::shared_ptr<EVP_MD> const evp_md(EVP_MD_fetch(lib_ctx, DEFAULT_DIGEST, nullptr), EVP_MD_free);
    ASSERT_NE(evp_md, nullptr);
    ASSERT_EQ(EVP_DigestInit_ex2(evp_md_sign_ctx.get(), evp_md.get(), nullptr), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_sign_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_sign_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), RSA_PKCS1_PSS_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    EVP_PKEY_CTX* temp_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_verify_ctx(temp_ctx, EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), RSA_PKCS1_PSS_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_verify_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), RSA_PSS_SALTLEN_AUTO), 1);

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, DEFAULT_DIGEST, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, RSA_PKCS1_PSS_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ver2_ctx, evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, RSA_PSS_SALTLEN_AUTO), 1);

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_F(SaProviderSignTest, defaultMgf1DigestTest) {
    sa_key_type const key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    std::shared_ptr<EVP_MD> const evp_md(EVP_MD_fetch(lib_ctx, DEFAULT_DIGEST, nullptr), EVP_MD_free);
    ASSERT_NE(evp_md, nullptr);
    ASSERT_EQ(EVP_DigestInit_ex2(evp_md_sign_ctx.get(), evp_md.get(), nullptr), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_sign_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), RSA_PKCS1_PSS_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx.get(), RSA_PSS_SALTLEN_AUTO), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    EVP_PKEY_CTX* temp_ctx = EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_verify_ctx(temp_ctx, EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), RSA_PKCS1_PSS_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_verify_ctx.get(), DEFAULT_DIGEST, nullptr), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), RSA_PSS_SALTLEN_AUTO), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, DEFAULT_DIGEST, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, RSA_PKCS1_PSS_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_verify_ctx.get(), DEFAULT_DIGEST, nullptr), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, RSA_PSS_SALTLEN_AUTO), 1);
    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_P(SaProviderSignTest, digestSignNoUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    const auto* const md_name = std::get<2>(GetParam());
    const auto* const mgf1_md_name = std::get<3>(GetParam());
    auto padding = std::get<4>(GetParam());
    auto salt = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    size_t signature_length = 0;
    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    int result = EVP_DigestSignInit_ex(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, md_name, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_sign_ctx, mgf1_md_name, nullptr), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = nullptr;
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, md_name, lib_ctx, nullptr,
            evp_pkey.get(), nullptr);
    ASSERT_EQ(result, 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md_name(evp_pkey_verify_ctx, mgf1_md_name, nullptr), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}

TEST_P(SaProviderSignEdTest, digestSignTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);

    OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get()),
            OSSL_PARAM_construct_end()};

    const char* key_name = get_key_name(key_type, curve);
    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_name(lib_ctx, key_name, nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    EVP_PKEY* temp = nullptr;
    ASSERT_EQ(EVP_PKEY_fromdata_init(evp_pkey_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_fromdata(evp_pkey_ctx.get(), &temp, EVP_PKEY_KEYPAIR, params), 1);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    int result = EVP_DigestSignInit_ex(evp_md_sign_ctx.get(), nullptr, nullptr, lib_ctx, nullptr, evp_pkey.get(),
            nullptr);
    ASSERT_EQ(result, 1);
    size_t signature_length = 0;
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), nullptr, nullptr, lib_ctx, nullptr, evp_pkey.get(),
            nullptr);
    ASSERT_EQ(result, 1);
    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}

TEST_P(SaProviderSignEdTest, digestSignTestWithGenerateKey) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    auto data = random(256);
    std::vector<uint8_t> signature;
    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    sa_elliptic_curve curve;
    auto evp_pkey = generate_sa_key(lib_ctx, key_type, key_length, curve);
    if (evp_pkey == nullptr)
        GTEST_SKIP() << "Operation not supported";

    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    int result = EVP_DigestSignInit_ex(evp_md_sign_ctx.get(), nullptr, nullptr, lib_ctx, nullptr, evp_pkey.get(),
            nullptr);
    ASSERT_EQ(result, 1);
    size_t signature_length = 0;
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> const evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    result = EVP_DigestVerifyInit_ex(evp_md_verify_ctx.get(), nullptr, nullptr, lib_ctx, nullptr, evp_pkey.get(),
            nullptr);
    ASSERT_EQ(result, 1);
    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}

INSTANTIATE_TEST_SUITE_P(
        SaProviderSignEdTests,
        SaProviderSignEdTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_ED448)));

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProviderSignWithGenerateRsaPkcs1Tests,
        SaProviderSignWithGenerateTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values("SHA1", "SHA256", "SHA384","SHA512")));

INSTANTIATE_TEST_SUITE_P(
        SaProviderSignRsaPkcs1Tests,
        SaProviderSignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values("SHA1", "SHA256", "SHA384","SHA512"),
                ::testing::Values("SHA1"),
                ::testing::Values(RSA_PKCS1_PADDING),
                ::testing::Values(0)));

INSTANTIATE_TEST_SUITE_P(
        SaProviderSignRsaPssTests,
        SaProviderSignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values("SHA1", "SHA256", "SHA384","SHA512"),
                ::testing::Values("SHA1", "SHA256", "SHA384","SHA512"),
                ::testing::Values(RSA_PKCS1_PSS_PADDING),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaProviderSignEcTests,
        SaProviderSignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224, SA_ELLIPTIC_CURVE_NIST_P256,
                    SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521),
                ::testing::Values("SHA1", "SHA256", "SHA384","SHA512"),
                ::testing::Values("SHA1"),
                ::testing::Values(0),
                ::testing::Values(0)));

INSTANTIATE_TEST_SUITE_P(
        SaProviderSignDefaultDigestSignTests,
        SaProviderSignDefaultDigestSignTest,
        ::testing::Values(std::make_tuple(SA_KEY_TYPE_RSA, RSA_2048_BYTE_LENGTH),
                          std::make_tuple(SA_KEY_TYPE_EC, SA_ELLIPTIC_CURVE_NIST_P256)));
// clang-format on

#endif
