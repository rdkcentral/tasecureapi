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
    TEST_P(SaKeyExchangeEcdhTest, nominal) {
        auto curve = std::get<0>(GetParam());
        auto key_size = ec_get_key_size(curve);
        auto ec_key = create_uninitialized_sa_key();
        ASSERT_NE(ec_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {curve};
        sa_status status = sa_key_generate(ec_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        size_t ec_public_key_length;
        status = sa_key_get_public(nullptr, &ec_public_key_length, *ec_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> ec_public_key(ec_public_key_length);
        status = sa_key_get_public(ec_public_key.data(), &ec_public_key_length, *ec_key);
        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_ec;
        std::vector<uint8_t> other_public_key;
        status = ec_generate_key(curve, other_ec, other_public_key);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto shared_secret = create_uninitialized_sa_key();
        ASSERT_NE(shared_secret, nullptr);
        status = sa_key_exchange(shared_secret.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *ec_key,
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
        std::vector<uint8_t> clear_shared_secret(key_size);
        ASSERT_TRUE(ecdh_compute_secret(curve, clear_shared_secret, other_ec, ec_public_key));
        ASSERT_TRUE(concat_kdf(clear_key, clear_shared_secret, info, SA_DIGEST_ALGORITHM_SHA256));
        ASSERT_TRUE(key_check_sym(*key, clear_key));
    }

    TEST_P(SaKeyExchangeEcdhTest, failsNullKey) {
        auto curve = std::get<0>(GetParam());
        auto ec_key = create_uninitialized_sa_key();
        ASSERT_NE(ec_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {curve};
        sa_status status = sa_key_generate(ec_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_ec;
        std::vector<uint8_t> other_public_key;
        status = ec_generate_key(curve, other_ec, other_public_key);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        status = sa_key_exchange(nullptr, &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *ec_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaKeyExchangeEcdhTest, failsNullRights) {
        auto curve = std::get<0>(GetParam());
        auto ec_key = create_uninitialized_sa_key();
        ASSERT_NE(ec_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {curve};
        sa_status status = sa_key_generate(ec_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_ec;
        std::vector<uint8_t> other_public_key;
        status = ec_generate_key(curve, other_ec, other_public_key);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), nullptr, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *ec_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaKeyExchangeEcdhTest, failsNullOtherPublic) {
        auto curve = std::get<0>(GetParam());
        auto ec_key = create_uninitialized_sa_key();
        ASSERT_NE(ec_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {curve};
        sa_status status = sa_key_generate(ec_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *ec_key, nullptr, 0,
                nullptr);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST_P(SaKeyExchangeEcdhTest, failsKeyDisallowsExchange) {
        auto curve = std::get<0>(GetParam());
        auto ec_key = create_uninitialized_sa_key();
        ASSERT_NE(ec_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);
        SA_USAGE_BIT_CLEAR(rights.usage_flags, SA_USAGE_FLAG_KEY_EXCHANGE);

        sa_generate_parameters_ec parameters = {curve};
        sa_status status = sa_key_generate(ec_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::shared_ptr<EVP_PKEY> other_ec;
        std::vector<uint8_t> other_public_key;
        status = ec_generate_key(curve, other_ec, other_public_key);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *ec_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_OPERATION_NOT_ALLOWED);
    }

    TEST_P(SaKeyExchangeEcdhTest, failsKeySupportsEcdh) {
        auto curve = std::get<0>(GetParam());
        sa_rights rights;
        rights_set_allow_all(&rights);

        std::vector<uint8_t> rsa_2048 = sample_rsa_2048_pkcs8();
        auto rsa_key = create_sa_key_rsa(&rights, rsa_2048);
        ASSERT_NE(rsa_key, nullptr);
        if (*rsa_key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type not supported";

        std::shared_ptr<EVP_PKEY> other_ec;
        std::vector<uint8_t> other_public_key;
        sa_status status = ec_generate_key(curve, other_ec, other_public_key);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);
        status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *rsa_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_BAD_KEY_TYPE);
    }

    TEST_P(SaKeyExchangeEcdhTest, failsOtherPublicSizeMismatch) {
        auto curve = std::get<0>(GetParam());
        auto key_size = ec_get_key_size(curve);
        auto ec_key = create_uninitialized_sa_key();
        ASSERT_NE(ec_key, nullptr);

        sa_rights rights;
        rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {curve};
        sa_status status = sa_key_generate(ec_key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        if (status == SA_STATUS_OPERATION_NOT_SUPPORTED)
            GTEST_SKIP() << "Curve not supported";

        ASSERT_EQ(status, SA_STATUS_OK);

        std::vector<uint8_t> other_public_key = random(key_size * 2 + 1);
        auto key = create_uninitialized_sa_key();
        status = sa_key_exchange(key.get(), &rights, SA_KEY_EXCHANGE_ALGORITHM_ECDH, *ec_key,
                other_public_key.data(), other_public_key.size(), nullptr);
        ASSERT_EQ(status, SA_STATUS_BAD_PARAMETER);
    }
} // namespace
