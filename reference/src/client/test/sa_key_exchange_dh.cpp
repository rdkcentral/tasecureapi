/**
 * Copyright 2020-2022 Comcast Cable Communications Management, LLC
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
#include "sa_key_exchange_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyExchangeDhTest, nominal) {
        const std::vector<uint8_t>& dhp = std::get<0>(GetParam());
        const std::vector<uint8_t>& dhg = std::get<1>(GetParam());

        auto dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_dh parameters = {
                .p = dhp.data(),
                .p_length = dhp.size(),
                .g = dhg.data(),
                .g_length = dhg.size()};
        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t dh_public_key_length;
        status = sa_key_get_public(nullptr, &dh_public_key_length, *dh_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> dh_public_key(dh_public_key_length);
        status = sa_key_get_public(dh_public_key.data(), &dh_public_key_length, *dh_key);
        ASSERT_EQ(status, SA_STATUS_OK);
        EVP_PKEY* temp = dh_import_public(dh_public_key.data(), dh_public_key.size(), dhp.data(), dhp.size(),
                dhg.data(), dhg.size());
        ASSERT_NE(temp, nullptr);
        auto public_evp_pkey = std::shared_ptr<EVP_PKEY>(temp, EVP_PKEY_free);

        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(dh_generate(other_dh, other_public_key, dhp, dhg));
        auto shared_secret = create_uninitialized_sa_key();
        ASSERT_NE(shared_secret, nullptr);
        status = sa_key_exchange(shared_secret.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *dh_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto info = random(AES_BLOCK_SIZE);
        sa_kdf_parameters_concat kdf_parameters_concat = {
                .key_length = SYM_128_KEY_SIZE,
                .digest_algorithm = SA_DIGEST_ALGORITHM_SHA256,
                .parent = *shared_secret,
                .info = info.data(),
                .info_length = info.size()};

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_derive(key.get(), &rights, SA_KDF_ALGORITHM_CONCAT, &kdf_parameters_concat);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> clear_key(SYM_128_KEY_SIZE);
        std::vector<uint8_t> clear_shared_secret;
        ASSERT_TRUE(dh_compute_secret(clear_shared_secret, other_dh, public_evp_pkey, dhp, dhg));
        ASSERT_TRUE(concat_kdf(clear_key, clear_shared_secret, info, SA_DIGEST_ALGORITHM_SHA256));
        ASSERT_TRUE(key_check_sym(*key, clear_key));
    }

    TEST_F(SaKeyExchangeDhTest, failsNullKey) {
        auto dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp3072 = sample_dh_p_3072();
        std::vector<uint8_t> dhg3072 = sample_dh_g_3072();

        sa_generate_parameters_dh parameters = {
                .p = dhp3072.data(),
                .p_length = dhp3072.size(),
                .g = dhg3072.data(),
                .g_length = dhg3072.size()};
        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(dh_generate(other_dh, other_public_key, dhp3072, dhg3072));
        status = sa_key_exchange(nullptr, &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *dh_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeDhTest, failsNullRights) {
        auto dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp3072 = sample_dh_p_3072();
        std::vector<uint8_t> dhg3072 = sample_dh_g_3072();

        sa_generate_parameters_dh parameters = {
                .p = dhp3072.data(),
                .p_length = dhp3072.size(),
                .g = dhg3072.data(),
                .g_length = dhg3072.size()};
        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(dh_generate(other_dh, other_public_key, dhp3072, dhg3072));
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), nullptr, SA_KEY_EXCHANGE_ALGORITHM_DH, *dh_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeDhTest, failsNullOtherPublic) {
        auto dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp3072 = sample_dh_p_3072();
        std::vector<uint8_t> dhg3072 = sample_dh_g_3072();

        sa_generate_parameters_dh parameters = {
                .p = dhp3072.data(),
                .p_length = dhp3072.size(),
                .g = dhg3072.data(),
                .g_length = dhg3072.size()};
        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *dh_key, nullptr, 0, nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeDhTest, failsKeyDisallowsExchange) {
        auto dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

        std::vector<uint8_t> dhp3072 = sample_dh_p_3072();
        std::vector<uint8_t> dhg3072 = sample_dh_g_3072();
        sa_generate_parameters_dh parameters = {
                .p = dhp3072.data(),
                .p_length = dhp3072.size(),
                .g = dhg3072.data(),
                .g_length = dhg3072.size()};
        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(dh_generate(other_dh, other_public_key, dhp3072, dhg3072));
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *dh_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyExchangeDhTest, failsKeySupportsDh) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::vector<uint8_t> rsa_2048 = sample_rsa_2048_pkcs8();
        auto rsa_key = create_sa_key_rsa(&rights, rsa_2048);
        ASSERT_NE(rsa_key, nullptr);
        if (*rsa_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(dh_generate(other_dh, other_public_key, sample_dh_p_3072(), sample_dh_g_3072()));
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        sa_status status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *rsa_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }

    TEST_F(SaKeyExchangeDhTest, failsOtherPublicSizeMismatch) {
        auto dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        std::vector<uint8_t> dhp2048 = sample_dh_p_2048();
        std::vector<uint8_t> dhg2048 = sample_dh_g_2048();
        sa_generate_parameters_dh parameters = {
                .p = dhp2048.data(),
                .p_length = dhp2048.size(),
                .g = dhg2048.data(),
                .g_length = dhg2048.size()};
        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(dh_generate(other_dh, other_public_key, sample_dh_p_3072(), sample_dh_g_3072()));
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_DH, *dh_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
