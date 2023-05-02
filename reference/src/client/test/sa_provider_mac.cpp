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
 *
 * distributed under the License is distributed on an "AS IS" BASIS,
 *
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

TEST_P(SaProviderMacTest, mac) {
    auto key_length = std::get<0>(GetParam());
    const auto* digest_name = std::get<1>(GetParam());
    const auto* mac_algorithm = std::get<2>(GetParam());

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    std::shared_ptr<EVP_MAC> const evp_mac(EVP_MAC_fetch(lib_ctx, mac_algorithm, nullptr), EVP_MAC_free);
    ASSERT_NE(evp_mac, nullptr);
    std::shared_ptr<EVP_MAC_CTX> const evp_mac_ctx(EVP_MAC_CTX_new(evp_mac.get()), EVP_MAC_CTX_free);

    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);
    OSSL_PARAM params[3];
    size_t param = 0;
    params[param++] = OSSL_PARAM_construct_ulong(OSSL_PARAM_SA_KEY, key.get());
    if (strcmp(mac_algorithm, "HMAC") == 0)
        params[param++] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>(digest_name),
                strlen(digest_name));

    params[param] = OSSL_PARAM_construct_end();

    auto data = random(256);
    ASSERT_EQ(EVP_MAC_init(evp_mac_ctx.get(), nullptr, 0, params), 1);
    ASSERT_EQ(EVP_MAC_update(evp_mac_ctx.get(), data.data(), data.size()), 1);
    size_t mac_length;
    ASSERT_EQ(EVP_MAC_final(evp_mac_ctx.get(), nullptr, &mac_length, 0), 1);
    std::vector<uint8_t> mac(mac_length);
    ASSERT_EQ(EVP_MAC_final(evp_mac_ctx.get(), mac.data(), &mac_length, mac.size()), 1);
    mac.resize(mac_length);

    std::vector<uint8_t> mac2;
    if (strcmp(mac_algorithm, "HMAC") == 0)
        ASSERT_TRUE(hmac_openssl(mac2, clear_key, data, digest_algorithm_from_name(digest_name)));
    else
        ASSERT_TRUE(cmac_openssl(mac2, clear_key, data));

    ASSERT_EQ(mac, mac2);
}

TEST_P(SaProviderMacTest, macWithKeyImport) {
    auto key_length = std::get<0>(GetParam());
    const auto* digest_name = std::get<1>(GetParam());
    const auto* mac_algorithm = std::get<2>(GetParam());

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    std::shared_ptr<EVP_MAC> const evp_mac(EVP_MAC_fetch(lib_ctx, mac_algorithm, nullptr), EVP_MAC_free);
    ASSERT_NE(evp_mac, nullptr);
    std::shared_ptr<EVP_MAC_CTX> const evp_mac_ctx(EVP_MAC_CTX_new(evp_mac.get()), EVP_MAC_CTX_free);

    auto clear_key = random(key_length);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    OSSL_PARAM params[3];
    size_t param = 0;
    if (strcmp(mac_algorithm, "HMAC") == 0)
        params[param++] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>(digest_name),
                strlen(digest_name));

    params[param] = OSSL_PARAM_construct_end();

    auto data = random(256);
    ASSERT_EQ(EVP_MAC_init(evp_mac_ctx.get(), clear_key.data(), clear_key.size(), params), 1);
    ASSERT_EQ(EVP_MAC_update(evp_mac_ctx.get(), data.data(), data.size()), 1);
    size_t mac_length;
    ASSERT_EQ(EVP_MAC_final(evp_mac_ctx.get(), nullptr, &mac_length, 0), 1);
    std::vector<uint8_t> mac(mac_length);
    ASSERT_EQ(EVP_MAC_final(evp_mac_ctx.get(), mac.data(), &mac_length, mac.size()), 1);
    mac.resize(mac_length);

    std::vector<uint8_t> mac2;
    if (strcmp(mac_algorithm, "HMAC") == 0)
        ASSERT_TRUE(hmac_openssl(mac2, clear_key, data, digest_algorithm_from_name(digest_name)));
    else
        ASSERT_TRUE(cmac_openssl(mac2, clear_key, data));

    ASSERT_EQ(mac, mac2);
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProviderCmacTests,
        SaProviderMacTest,
        ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values(""),
                ::testing::Values("CMAC")));

INSTANTIATE_TEST_SUITE_P(
        SaProviderHmacTests,
        SaProviderMacTest,
        ::testing::Combine(
                ::testing::Values(SYM_128_KEY_SIZE, SYM_160_KEY_SIZE, SYM_256_KEY_SIZE),
                ::testing::Values("SHA1", "SHA256", "SHA384", "SHA512"),
                ::testing::Values("HMAC")));
// clang-format on
#endif
