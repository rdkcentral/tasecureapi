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
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sa_engine_common.h"
// These tests fail on OpenSSL 1.1.1f, so disable them.
#if OPENSSL_VERSION_NUMBER > 0x1010106f && OPENSSL_VERSION_NUMBER < 0x30000000
#include "client_test_helpers.h"
#include "digest_util.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>

using namespace client_test_helpers;

TEST_P(SaEnginePkeyMacTest, digestSignWithUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    auto digest_algorithm = std::get<2>(GetParam());
    auto mac_algorithm = std::get<3>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> mac;
    std::shared_ptr<ENGINE> const engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);
    const EVP_MD* evp_md;
    if (mac_algorithm == SA_MAC_ALGORITHM_HMAC)
        evp_md = digest_mechanism(digest_algorithm);
    else
        evp_md = nullptr;

    size_t mac_length = 0;
    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_DigestSignUpdate(evp_md_sign_ctx.get(), data.data(), data.size()), 1);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), nullptr, &mac_length), 1);
    mac.resize(mac_length);
    ASSERT_EQ(EVP_DigestSignFinal(evp_md_sign_ctx.get(), mac.data(), &mac_length), 1);
    mac.resize(mac_length);

    std::vector<uint8_t> mac2;
    if (mac_algorithm == SA_MAC_ALGORITHM_HMAC)
        ASSERT_TRUE(hmac_openssl(mac2, clear_key, data, digest_algorithm));
    else
        ASSERT_TRUE(cmac_openssl(mac2, clear_key, data));

    ASSERT_EQ(mac, mac2);
}

TEST_P(SaEnginePkeyMacTest, digestSignNoUpdateFinalTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());
    auto digest_algorithm = std::get<2>(GetParam());
    auto mac_algorithm = std::get<3>(GetParam());

    std::vector<uint8_t> clear_key;
    sa_elliptic_curve curve;
    auto key = create_sa_key(key_type, key_length, clear_key, curve);
    ASSERT_NE(key, nullptr);
    if (*key == UNSUPPORTED_KEY)
        GTEST_SKIP() << "key type, key size, or curve not supported";

    auto data = random(256);
    std::vector<uint8_t> mac;
    std::shared_ptr<ENGINE> const engine(sa_get_engine(), sa_engine_free);
    ASSERT_NE(engine, nullptr);
    EVP_PKEY* temp = ENGINE_load_private_key(engine.get(), reinterpret_cast<char*>(key.get()), nullptr, nullptr);
    ASSERT_NE(temp, nullptr);
    std::shared_ptr<EVP_PKEY> const evp_pkey(temp, EVP_PKEY_free);
    const EVP_MD* evp_md;
    if (mac_algorithm == SA_MAC_ALGORITHM_HMAC)
        evp_md = digest_mechanism(digest_algorithm);
    else
        evp_md = nullptr;

    size_t mac_length = 0;
    std::shared_ptr<EVP_MD_CTX> const evp_md_sign_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    ASSERT_NE(evp_md_sign_ctx, nullptr);
    EVP_PKEY_CTX* evp_pkey_sign_ctx = nullptr;
    ASSERT_EQ(EVP_DigestSignInit(evp_md_sign_ctx.get(), &evp_pkey_sign_ctx, evp_md, engine.get(), evp_pkey.get()),
            1);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), nullptr, &mac_length, data.data(), data.size()), 1);
    mac.resize(mac_length);
    ASSERT_EQ(EVP_DigestSign(evp_md_sign_ctx.get(), mac.data(), &mac_length, data.data(), data.size()), 1);
    mac.resize(mac_length);

    std::vector<uint8_t> mac2;
    if (mac_algorithm == SA_MAC_ALGORITHM_HMAC)
        ASSERT_TRUE(hmac_openssl(mac2, clear_key, data, digest_algorithm));
    else
        ASSERT_TRUE(cmac_openssl(mac2, clear_key, data));
    ASSERT_EQ(mac, mac2);
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyCmacTests,
        SaEnginePkeyMacTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(0),
                ::testing::Values(SA_MAC_ALGORITHM_CMAC)));

INSTANTIATE_TEST_SUITE_P(
        SaEnginePkeyHmacTests,
        SaEnginePkeyMacTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_SYMMETRIC),
                ::testing::Values(SYM_128_KEY_SIZE, SYM_160_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(SA_DIGEST_ALGORITHM_SHA1, SA_DIGEST_ALGORITHM_SHA256, SA_DIGEST_ALGORITHM_SHA384,
                    SA_DIGEST_ALGORITHM_SHA512),
                ::testing::Values(SA_MAC_ALGORITHM_HMAC)));
// clang-format on
#endif
