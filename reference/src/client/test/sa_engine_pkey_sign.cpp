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

TEST_P(SaEnginePkeySignTest, digestSignWithUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    int nid = std::get<2>(GetParam());
    int mgf1_nid = std::get<3>(GetParam());
    auto padding = std::get<4>(GetParam());
    auto salt = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);

    size_t signature_length = 0;
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_sign_ctx, EVP_get_digestbynid(mgf1_nid)), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestSignUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), nullptr, &signature_length), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), signature.data(), &signature_length), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_verify_ctx, EVP_get_digestbynid(mgf1_nid)), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST_P(SaEnginePkeySignTest, signTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    int nid = std::get<2>(GetParam());
    int mgf1_nid = std::get<3>(GetParam());
    auto padding = std::get<4>(GetParam());
    auto salt = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestInit(evp_md_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_sign_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_sign_ctx.get(), EVP_get_digestbynid(mgf1_nid)), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx.get(), salt), 1);
        }
    }

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_verify_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()),
            EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_verify_ctx.get(), EVP_get_digestbynid(mgf1_nid)), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), salt), 1);
        }
    }

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ver2_ctx, EVP_get_digestbynid(mgf1_nid)), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST(SaEnginePkeySignTest, defaultPaddingTest) {
    sa_key_type key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_sha256();
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestInit(evp_md_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_sign_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    int padding = RSA_PKCS1_PADDING;
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_verify_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()),
            EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST(SaEnginePkeySignTest, defaultSaltTest) {
    sa_key_type key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;
    int padding = RSA_PKCS1_PSS_PADDING;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_sha256();
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestInit(evp_md_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_sign_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), padding), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_verify_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()),
            EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), RSA_PSS_SALTLEN_AUTO), 1);

    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ver2_ctx, evp_md), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, RSA_PSS_SALTLEN_AUTO), 1);

    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

TEST(SaEnginePkeySignTest, defaultMgf1DigestTest) {
    sa_key_type key_type = SA_KEY_TYPE_RSA;
    size_t key_length = RSA_2048_BYTE_LENGTH;
    int padding = RSA_PKCS1_PSS_PADDING;

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    const EVP_MD* evp_md = EVP_sha256();
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestInit(evp_md_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_DigestUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    unsigned int digest_length;
    uint8_t digest[EVP_MAX_MD_SIZE];
    ASSERT_EQ(EVP_DigestFinal(evp_md_sign_ctx.get(), digest, &digest_length), 1);

    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_sign_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()), EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey, nullptr);

    size_t signature_length = 0;
    ASSERT_EQ(EVP_PKEY_sign_init(evp_pkey_sign_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_sign_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx.get(), padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx.get(), RSA_PSS_SALTLEN_AUTO), 1);
    ASSERT_EQ(EVP_PKEY_sign(evp_pkey_sign_ctx.get(), nullptr, &signature_length, digest, digest_length), 1);
    signature.resize(signature_length);
    int result = EVP_PKEY_sign(evp_pkey_sign_ctx.get(), signature.data(), &signature_length, digest, digest_length);
    if (result == -2)
        GTEST_SKIP() << "Operation not supported";

    ASSERT_EQ(result, 1);
    signature.resize(signature_length);

    // Verify with EVP_PKEY_verify
    std::shared_ptr<EVP_PKEY_CTX> evp_pkey_verify_ctx(EVP_PKEY_CTX_new(evp_pkey.get(), engine.get()),
            EVP_PKEY_CTX_free);
    ASSERT_EQ(EVP_PKEY_verify_init(evp_pkey_verify_ctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(evp_pkey_verify_ctx.get(), evp_md), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx.get(), padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_verify_ctx.get(), EVP_sha1()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx.get(), RSA_PSS_SALTLEN_AUTO), 1);
    ASSERT_EQ(EVP_PKEY_verify(evp_pkey_verify_ctx.get(), signature.data(), signature.size(), digest, digest_length), 1);

    // Verify again with DigestVerify
    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_ver2_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_ver2_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_ver2_ctx, padding), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_ver2_ctx, EVP_sha1()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_ver2_ctx, RSA_PSS_SALTLEN_AUTO), 1);
    ASSERT_EQ(EVP_DigestVerifyUpdate(evp_md_verify_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestVerifyFinal(evp_md_verify_ctx.get(), signature.data(), signature.size()), 1);
}

#if OPENSSL_VERSION_NUMBER >= 0x10100000
TEST_P(SaEnginePkeySignTest, digestSignNoUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    int nid = std::get<2>(GetParam());
    int mgf1_nid = std::get<3>(GetParam());
    auto padding = std::get<4>(GetParam());
    auto salt = std::get<5>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);
    const EVP_MD* evp_md = EVP_get_digestbynid(nid);

    size_t signature_length = 0;
    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_sign_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_sign_ctx, EVP_get_digestbynid(mgf1_nid)), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_sign_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_verify_ctx = nullptr;
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), &evp_pkey_verify_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    if (key_type == SA_KEY_TYPE_RSA) {
        ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(evp_pkey_verify_ctx, padding), 1);
        if (padding == RSA_PKCS1_PSS_PADDING) {
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_mgf1_md(evp_pkey_verify_ctx, EVP_get_digestbynid(mgf1_nid)), 1);
            ASSERT_EQ(EVP_PKEY_CTX_set_rsa_pss_saltlen(evp_pkey_verify_ctx, salt), 1);
        }
    }

    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}

TEST_P(SaEnginePkeySignEdTest, digestSignTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type not supported";

    auto data = random(256);
    std::vector<uint8_t> signature;
    std::shared_ptr<ENGINE> engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> evp_pkey(temp, EVP_PKEY_free);

    std::shared_ptr<EVP_MD_CTX> evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), nullptr, nullptr, engine.get(), evp_pkey.get()), 1);
    size_t signature_length = 0;
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), signature.data(), &signature_length, data.data(), data.size()), 1);
    signature.resize(signature_length);

    std::shared_ptr<EVP_MD_CTX> evp_md_verify_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_verify_ctx, nullptr);
    ASSERT_EQ(EVP_DigestVerifyInit(evp_md_verify_ctx.get(), nullptr, nullptr, engine.get(), evp_pkey.get()), 1);
    ASSERT_EQ(EVP_DigestVerify(evp_md_verify_ctx.get(), signature.data(), signature.size(), data.data(), data.size()),
            1);
}

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyEdTests,
        SaEnginePkeySignEdTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_ED25519, SA_ELLIPTIC_CURVE_ED448)));
#endif

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsaPkcs1Tests,
        SaEnginePkeySignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(NID_sha1),
                ::testing::Values(RSA_PKCS1_PADDING),
                ::testing::Values(0)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyRsaPssTests,
        SaEnginePkeySignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_RSA),
                ::testing::Values(RSA_1024_BYTE_LENGTH, RSA_2048_BYTE_LENGTH, RSA_3072_BYTE_LENGTH,
                    RSA_4096_BYTE_LENGTH),
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(RSA_PKCS1_PSS_PADDING),
                ::testing::Values(0, 16)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyEcTests,
        SaEnginePkeySignTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224, SA_ELLIPTIC_CURVE_NIST_P256,
                    SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521),
                ::testing::Values(NID_sha1, NID_sha256, NID_sha384, NID_sha512),
                ::testing::Values(NID_sha1),
                ::testing::Values(0),
                ::testing::Values(0)));
// clang-format on
