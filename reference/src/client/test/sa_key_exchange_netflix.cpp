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
    TEST_P(SaKeyExchangeNetflixTest, nominal) {
        const std::vector<uint8_t>& dhp = std::get<0>(GetParam());
        const std::vector<uint8_t>& dhg = std::get<1>(GetParam());

        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key, dhp, dhg));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Calculate the test side of the netflix key exchange.
        std::vector<uint8_t> clear_key(SYM_128_KEY_SIZE);
        std::vector<uint8_t> clear_shared_secret;
        ASSERT_TRUE(dh_compute_secret(clear_shared_secret, other_dh, dh_public_key, dhp, dhg));
        std::vector<uint8_t> clear_kenc;
        std::vector<uint8_t> clear_khmac;
        std::vector<uint8_t> clear_kwrap;
        ASSERT_TRUE(netflix_compute_secret(clear_kenc, clear_khmac, clear_kwrap, clear_kd, clear_shared_secret));

        // Verify both keys.
        ASSERT_TRUE(key_check_sym(*kenc, clear_kenc));
        ASSERT_TRUE(key_check_sym(*khmac, clear_khmac));
        ASSERT_TRUE(key_check_sym(*kwrap, clear_kwrap));
    }

    TEST_F(SaKeyExchangeNetflixTest, failsNullKey) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        sa_status status = sa_key_exchange(nullptr, &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsNullRights) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), nullptr, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsNullOtherPublic) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, nullptr, 0, &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsNullParameters) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsOutKeNull) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = nullptr,
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsNullRightsKe) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = nullptr,
                .out_kh = khmac.get(),
                .rights_kh = nullptr};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsOutKhNull) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = nullptr,
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsNullRightsKh) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = nullptr,
                .out_kh = khmac.get(),
                .rights_kh = nullptr};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsUnknownKw) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = INVALID_HANDLE,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsKwDisallowsDerive) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Generate a kd that disallows derive.
        sa_rights kw_rights;
        rights_set_allow_all(&kw_rights);
        SA_USAGE_BIT_CLEAR(kw_rights.usage_flags, SA_USAGE_FLAG_DERIVE);
        sa_generate_parameters_symmetric symmetric_parameters = {
                .key_length = SYM_128_KEY_SIZE};
        kd = create_uninitialized_sa_key();
        ASSERT_NE(kd, nullptr);

        sa_status status = sa_key_generate(kd.get(), &kw_rights, SA_KEY_TYPE_SYMMETRIC, &symmetric_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsKwNotSymmetric) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Generate a kd that is not symmetric.
        sa_generate_parameters_ec ec_parameters = {curve};
        kd = create_uninitialized_sa_key();
        ASSERT_NE(kd, nullptr);

        sa_status status = sa_key_generate(kd.get(), &rights, SA_KEY_TYPE_EC, &ec_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsUnknownKey) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                INVALID_HANDLE, other_public_key.data(), other_public_key.size(),
                &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsKeyDisallowsExchange) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Generate a dh key that disallows exchange.
        sa_rights key_rights;
        rights_set_allow_all(&key_rights);
        SA_USAGE_BIT_CLEAR(key_rights.usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);
        auto dhp = sample_dh_p_3072();
        auto dhg = sample_dh_g_3072();
        sa_generate_parameters_dh dh_parameters = {
                .p = dhp.data(),
                .p_length = dhp.size(),
                .g = dhg.data(),
                .g_length = dhg.size()};
        dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_status status = sa_key_generate(dh_key.get(), &key_rights, SA_KEY_TYPE_DH, &dh_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsKeyNotDh) {
        auto curve = SA_ELLIPTIC_CURVE_NIST_P256;
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_3072(), sample_dh_g_3072()));

        // Generate a dh that is not a DH key.
        sa_generate_parameters_ec ec_parameters = {curve};
        dh_key = create_uninitialized_sa_key();
        ASSERT_NE(dh_key, nullptr);

        sa_status status = sa_key_generate(dh_key.get(), &rights, SA_KEY_TYPE_EC, &ec_parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }

    TEST_F(SaKeyExchangeNetflixTest, failsOtherPublicMismatch) {
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::shared_ptr<sa_key> kd;
        std::vector<uint8_t> clear_kd;
        std::shared_ptr<sa_key> dh_key;
        std::shared_ptr<EVP_PKEY> dh_public_key;
        std::shared_ptr<EVP_PKEY> other_dh;
        std::vector<uint8_t> other_public_key;
        ASSERT_TRUE(setup_key_exchange(kd, clear_kd, dh_key, dh_public_key, other_dh, other_public_key,
                sample_dh_p_2048(), sample_dh_g_2048()));

        // Generate the other DH key.
        ASSERT_TRUE(dh_generate(other_dh, other_public_key, sample_dh_p_3072(), sample_dh_g_3072()));

        // Do the netflix key exchange.
        auto kenc = create_uninitialized_sa_key();
        ASSERT_NE(kenc, nullptr);
        auto khmac = create_uninitialized_sa_key();
        ASSERT_NE(khmac, nullptr);

        sa_key_exchange_parameters_netflix_authenticated_dh netflix_parameters = {
                .in_kw = *kd,
                .out_ke = kenc.get(),
                .rights_ke = &rights,
                .out_kh = khmac.get(),
                .rights_kh = &rights};

        auto kwrap = create_uninitialized_sa_key();
        sa_status status = sa_key_exchange(kwrap.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_NETFLIX_AUTHENTICATED_DH,
                *dh_key, other_public_key.data(), other_public_key.size(), &netflix_parameters);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
