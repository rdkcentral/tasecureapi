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
#include <openssl/kdf.h>

#ifdef __APPLE__
#define htobe32(x) htonl(x)
#endif

using namespace client_test_helpers;

TEST_P(SaProviderKdfTest, deriveTest) {
    const auto* const kdf_algorithm = std::get<0>(GetParam());
    const auto* const digest_name = std::get<1>(GetParam());

    OSSL_LIB_CTX* lib_ctx = sa_get_provider();
    ASSERT_NE(lib_ctx, nullptr);
    auto clear_key = random(SYM_128_KEY_SIZE);
    sa_rights rights;
    sa_rights_set_allow_all(&rights);
    auto key = create_sa_key_symmetric(&rights, clear_key);

    std::shared_ptr<EVP_KDF> evp_kdf(EVP_KDF_fetch(lib_ctx, kdf_algorithm, nullptr), EVP_KDF_free);
    ASSERT_NE(evp_kdf, nullptr);
    std::shared_ptr<EVP_KDF_CTX> evp_kdf_ctx(EVP_KDF_CTX_new(evp_kdf.get()), EVP_KDF_CTX_free);
    ASSERT_NE(evp_kdf_ctx, nullptr);

    std::vector<uint8_t> clear_derived_key(SYM_128_KEY_SIZE);
    auto derived_key = create_uninitialized_sa_key();
    auto salt = random(AES_BLOCK_SIZE);
    auto info = random(AES_BLOCK_SIZE);
    if (strcmp(kdf_algorithm, "HKDF") == 0) {
        ASSERT_TRUE(hkdf(clear_derived_key, clear_key, salt, info, digest_algorithm_from_name(digest_name)));
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key.get(), sizeof(sa_key)),
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest_name),
                        strlen(digest_name)),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
                OSSL_PARAM_END};
        int result = EVP_KDF_derive(evp_kdf_ctx.get(), reinterpret_cast<unsigned char*>(derived_key.get()),
                SYM_128_KEY_SIZE, params);
        ASSERT_EQ(result, 1);
    } else if (strcmp(kdf_algorithm, "CONCAT") == 0) {
        ASSERT_TRUE(concat_kdf(clear_derived_key, clear_key, info, digest_algorithm_from_name(digest_name)));
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key.get(), sizeof(sa_key)),
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest_name),
                        strlen(digest_name)),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
                OSSL_PARAM_END};
        int result = EVP_KDF_derive(evp_kdf_ctx.get(), reinterpret_cast<unsigned char*>(derived_key.get()),
                SYM_128_KEY_SIZE, params);
        ASSERT_EQ(result, 1);
    } else if (strcmp(kdf_algorithm, "ANSI_X963") == 0) {
        ASSERT_TRUE(ansi_x963_kdf(clear_derived_key, clear_key, info, digest_algorithm_from_name(digest_name)));
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key.get(), sizeof(sa_key)),
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest_name),
                        strlen(digest_name)),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
                OSSL_PARAM_END};
        int result = EVP_KDF_derive(evp_kdf_ctx.get(), reinterpret_cast<unsigned char*>(derived_key.get()),
                SYM_128_KEY_SIZE, params);
        ASSERT_EQ(result, 1);
    } else if (strcmp(kdf_algorithm, "CMAC") == 0) {
        std::vector<uint8_t> other_data(37);
        std::copy(salt.begin(), salt.end(), other_data.begin());
        size_t position = salt.size();
        other_data[position++] = 0;
        std::copy(info.begin(), info.end(), other_data.begin() + static_cast<int64_t>(position));
        position += info.size();
        uint32_t length = htobe32(SYM_128_KEY_SIZE);
        auto* p_length = reinterpret_cast<uint8_t*>(&length);
        std::copy(p_length, p_length + 4, other_data.begin() + static_cast<int64_t>(position));
        ASSERT_TRUE(cmac_kdf(clear_derived_key, clear_key, other_data, 1));
        int one = 1;
        OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key.get(), sizeof(sa_key)),
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest_name),
                        strlen(digest_name)),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
                OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
                OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, &one),
                OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L, &one),
                OSSL_PARAM_END};
        int result = EVP_KDF_derive(evp_kdf_ctx.get(), reinterpret_cast<unsigned char*>(derived_key.get()),
                SYM_128_KEY_SIZE, params);
        ASSERT_EQ(result, 1);
    }

    ASSERT_TRUE(key_check_sym(*derived_key, clear_derived_key));
}

// clang-format off
INSTANTIATE_TEST_SUITE_P(
        SaProviderKdfHashTests,
        SaProviderKdfTest,
        ::testing::Combine(
                ::testing::Values("HKDF", "CONCAT", "ANSI_X963"),
                ::testing::Values("SHA1", "SHA256", "SHA384", "SHA512")));
INSTANTIATE_TEST_SUITE_P(
        SaProviderKdfCmacTests,
        SaProviderKdfTest,
        ::testing::Combine(
                ::testing::Values("CMAC"),
                ::testing::Values("")));
// clang-format on
#endif
