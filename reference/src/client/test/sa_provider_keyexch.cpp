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

using namespace client_test_helpers;

TEST_P(SaProviderKeyExchangeTest, deriveTest) {
    auto key_type = std::get<0>(GetParam());
    auto key_length = std::get<1>(GetParam());

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    sa_elliptic_curve curve;
    auto evp_pkey = generate_sa_key(lib_ctx, key_type, key_length, curve);
    if (evp_pkey == nullptr)
        GTEST_SKIP() << "Operation not supported";

    std::vector<uint8_t> clear_derived_key(SYM_128_KEY_SIZE);
    std::vector<uint8_t> clear_shared_secret;
    std::shared_ptr<EVP_PKEY> other_private_key;
    std::vector<uint8_t> other_public_key_bytes;
    if (key_type == SA_KEY_TYPE_DH) {
        std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> dh_parameters = get_dh_parameters(key_length);
        auto p = std::get<0>(dh_parameters);
        auto g = std::get<1>(dh_parameters);
        ASSERT_TRUE(dh_generate_key(other_private_key, other_public_key_bytes, p, g));
        ASSERT_TRUE(dh_compute_secret(clear_shared_secret, other_private_key, evp_pkey));
    } else if (key_type == SA_KEY_TYPE_EC) {
        ASSERT_EQ(ec_generate_key(curve, other_private_key, other_public_key_bytes), SA_STATUS_OK);
        ASSERT_TRUE(ecdh_compute_secret(clear_shared_secret, other_private_key, evp_pkey));
    }

    auto info = random(AES_BLOCK_SIZE);
    ASSERT_TRUE(concat_kdf(clear_derived_key, clear_shared_secret, info, SA_DIGEST_ALGORITHM_SHA256));

    std::shared_ptr<EVP_PKEY_CTX> const evp_pkey_ctx(EVP_PKEY_CTX_new_from_pkey(lib_ctx, evp_pkey.get(), nullptr),
            EVP_PKEY_CTX_free);
    ASSERT_NE(evp_pkey_ctx, nullptr);
    ASSERT_EQ(EVP_PKEY_derive_init(evp_pkey_ctx.get()), 1);
    if (key_type == SA_KEY_TYPE_DH) {
        ASSERT_EQ(EVP_PKEY_CTX_set_dh_pad(evp_pkey_ctx.get(), 1), 1);
    }

    EVP_PKEY* temp = sa_import_public_key(other_public_key_bytes.data(), other_public_key_bytes.size());
    auto other_public_key = std::shared_ptr<EVP_PKEY>(temp, EVP_PKEY_free);
    ASSERT_EQ(EVP_PKEY_derive_set_peer(evp_pkey_ctx.get(), other_public_key.get()), 1);
    size_t shared_secret_size = 0;
    ASSERT_EQ(EVP_PKEY_derive(evp_pkey_ctx.get(), nullptr, &shared_secret_size), 1);
    std::vector<uint8_t> shared_secret(shared_secret_size);
    size_t written = shared_secret_size;
    ASSERT_EQ(EVP_PKEY_derive(evp_pkey_ctx.get(), shared_secret.data(), &written), 1);

    auto shared_secret_key = create_uninitialized_sa_key();
    *shared_secret_key = *reinterpret_cast<sa_key*>(shared_secret.data());
    sa_kdf_parameters_concat kdf_parameters_concat = {
            .key_length = SYM_128_KEY_SIZE,
            .digest_algorithm = SA_DIGEST_ALGORITHM_SHA256,
            .parent = *shared_secret_key,
            .info = info.data(),
            .info_length = info.size()};
    auto derived_key = create_uninitialized_sa_key();
    ASSERT_NE(derived_key, nullptr);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    sa_status const status = sa_key_derive(derived_key.get(), &rights, SA_KDF_ALGORITHM_CONCAT, &kdf_parameters_concat);
    ASSERT_EQ(status, SA_STATUS_OK);
    ASSERT_TRUE(key_check_sym(*derived_key, clear_derived_key));
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProviderKeyExchangeDhTests,
        SaProviderKeyExchangeTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_DH),
                ::testing::Values(DH_768_BYTE_LENGTH, DH_1024_BYTE_LENGTH, DH_1536_BYTE_LENGTH, DH_2048_BYTE_LENGTH,
DH_3072_BYTE_LENGTH, DH_4096_BYTE_LENGTH)));

INSTANTIATE_TEST_SUITE_P(
        SaProviderKeyExchangeEcTests,
        SaProviderKeyExchangeTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_NIST_P192, SA_ELLIPTIC_CURVE_NIST_P224, SA_ELLIPTIC_CURVE_NIST_P256,
                    SA_ELLIPTIC_CURVE_NIST_P384, SA_ELLIPTIC_CURVE_NIST_P521)));

INSTANTIATE_TEST_SUITE_P(
        SaProviderKeyExchangeXTests,
        SaProviderKeyExchangeTest,
        ::testing::Combine(
                ::testing::Values(SA_KEY_TYPE_EC),
                ::testing::Values(SA_ELLIPTIC_CURVE_X25519, SA_ELLIPTIC_CURVE_X448)));
#endif
