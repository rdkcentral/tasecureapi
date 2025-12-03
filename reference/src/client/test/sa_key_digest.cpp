/*
 * Copyright 2020-2023 Comcast Cable Communications Management, LLC
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
#include "digest_util.h"
#include "sa.h"
#include "sa_key_common.h"
#include "gtest/gtest.h"

using namespace client_test_helpers;

namespace {
    TEST_P(SaKeyDigestTest, nominal) {
        sa_key_type const key_type = std::get<0>(GetParam());
        size_t key_length = std::get<1>(GetParam());
        sa_digest_algorithm const digest_algorithm = std::get<2>(GetParam());
        size_t const length = digest_length(digest_algorithm);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_status status;
        std::vector<uint8_t> clear_key;
        sa_elliptic_curve curve;
        auto key = create_sa_key(key_type, key_length, clear_key, curve);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        size_t out_length = 0;
        status = sa_key_digest(nullptr, &out_length, *key, digest_algorithm);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_length, length);

        auto digest = std::vector<uint8_t>(out_length);
        status = sa_key_digest(digest.data(), &out_length, *key, digest_algorithm);
        ASSERT_EQ(status, SA_STATUS_OK);
        ASSERT_EQ(out_length, length);

        std::vector<uint8_t> result;
        ASSERT_TRUE(test_helpers_openssl::digest(result, digest_algorithm, clear_key, {}, {}));
        ASSERT_EQ(result, digest);
    }

    TEST(SaKeyDigestTest, failOutLengthNull) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        auto clear_key = random(SYM_128_KEY_SIZE);
        auto key = create_sa_key_symmetric(&rights, clear_key);

        sa_status const status = sa_key_digest(nullptr, nullptr, *key, SA_DIGEST_ALGORITHM_SHA256);
        ASSERT_EQ(status, SA_STATUS_NULL_PARAMETER);
    }

    TEST(SaKeyDigestTest, failDh) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);
        std::vector<uint8_t> dhp2048 = sample_dh_p_2048();
        std::vector<uint8_t> dhg2048 = sample_dh_g_2048();

        sa_generate_parameters_dh parameters = {dhp2048.data(), dhp2048.size(), dhg2048.data(), dhg2048.size()};
        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_DH, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length = 0;
        status = sa_key_digest(nullptr, &out_length, *key, SA_DIGEST_ALGORITHM_SHA256);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST(SaKeyDigestTest, failEc) {
        auto key = create_uninitialized_sa_key();
        ASSERT_NE(key, nullptr);

        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        sa_generate_parameters_ec parameters = {SA_ELLIPTIC_CURVE_NIST_P256};
        sa_status status = sa_key_generate(key.get(), &rights, SA_KEY_TYPE_EC, &parameters);
        ASSERT_EQ(status, SA_STATUS_OK);

        size_t out_length = 0;
        status = sa_key_digest(nullptr, &out_length, *key, SA_DIGEST_ALGORITHM_SHA256);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }

    TEST(SaKeyDigestTest, failRsa) {
        sa_rights rights;
        sa_rights_set_allow_all(&rights);

        auto rsa_key = sample_rsa_2048_pkcs8();
        auto key = create_sa_key_rsa(&rights, rsa_key);
        ASSERT_NE(key, nullptr);
        if (*key == UNSUPPORTED_KEY)
            GTEST_SKIP() << "key type, key size, or curve not supported";

        size_t out_length = 0;
        sa_status const status = sa_key_digest(nullptr, &out_length, *key, SA_DIGEST_ALGORITHM_SHA256);
        ASSERT_EQ(status, SA_STATUS_INVALID_PARAMETER);
    }
} // namespace
